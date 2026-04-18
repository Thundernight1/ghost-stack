// Package main — ipam.go implements minimalist IP Address Management (IPAM)
// for GHOST-STACK CORE.
//
// Gap 3: Static IP pool allocation.
//
// Pool: 10.200.0.0/16 subdivided into /24 subnets per department.
// Each department gets a /24 subnet with static allocation:
//   - .1 = gateway (host-side veth)
//   - .2 = container primary IP
//   - .3-.254 = available for intra-department services
//
// Allocations are persisted in the StateManager SQLite database
// to survive restarts. On startup, the IPAM reconstructs its bitmap
// from the database.
package main

import (
	"database/sql"
	"fmt"
	"net"
	"sync"
)

// IPAM constants.
const (
	// IPAMBaseNetwork is the base network for all department subnets.
	// Each department gets a /24 from this /16 pool.
	IPAMBaseNetwork = "10.200.0.0/16"

	// IPAMSubnetPrefix is the prefix length for each department subnet.
	IPAMSubnetPrefix = 24

	// IPAMMaxSubnets is the maximum number of /24 subnets available.
	// 10.200.0.0/16 → 256 subnets (10.200.0.0/24 through 10.200.255.0/24).
	// Subnet 0 is reserved for infrastructure (DNS, orchestrator).
	IPAMMaxSubnets = 256
)

// SubnetAllocation represents an allocated department subnet.
type SubnetAllocation struct {
	DeptID      int    `json:"dept_id"`
	SubnetIndex int    `json:"subnet_index"` // 0-255
	SubnetCIDR  string `json:"subnet_cidr"`  // e.g., "10.200.1.0/24"
	GatewayIP   string `json:"gateway_ip"`   // e.g., "10.200.1.1"
	ContainerIP string `json:"container_ip"` // e.g., "10.200.1.2"
}

// IPAM manages IP address allocation for department containers.
type IPAM struct {
	mu        sync.Mutex
	allocated map[int]int // DeptID → subnet index
	bitmap    [IPAMMaxSubnets]bool // True = allocated
	db        *sql.DB
}

// NewIPAM creates a new IPAM instance and loads existing allocations
// from the state database.
func NewIPAM(db *sql.DB) (*IPAM, error) {
	ipam := &IPAM{
		allocated: make(map[int]int),
		db:        db,
	}

	// Reserve subnet 0 for infrastructure.
	ipam.bitmap[0] = true

	// Load existing allocations from database.
	if err := ipam.loadFromDB(); err != nil {
		// Not fatal — fresh start.
		fmt.Printf("[IPAM] No existing allocations found (fresh start)\n")
	}

	return ipam, nil
}

// loadFromDB reconstructs the allocation bitmap from the state database.
func (ipam *IPAM) loadFromDB() error {
	if ipam.db == nil {
		return nil
	}

	rows, err := ipam.db.Query(`
		SELECT dept_id, container_ip, subnet_cidr FROM departments
		WHERE status != 'deleted'
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var deptID int
		var containerIP, subnetCIDR string
		if err := rows.Scan(&deptID, &containerIP, &subnetCIDR); err != nil {
			continue
		}

		// Extract subnet index from container IP (10.200.X.2 → X).
		ip := net.ParseIP(containerIP)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil || ip4[0] != 10 || ip4[1] != 200 {
			continue
		}

		subnetIdx := int(ip4[2])
		if subnetIdx >= 0 && subnetIdx < IPAMMaxSubnets {
			ipam.bitmap[subnetIdx] = true
			ipam.allocated[deptID] = subnetIdx
		}
	}

	return nil
}

// Allocate assigns the next available /24 subnet to a department.
// Returns the full allocation details including gateway and container IPs.
func (ipam *IPAM) Allocate(deptID int) (*SubnetAllocation, error) {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	// Check if already allocated.
	if idx, exists := ipam.allocated[deptID]; exists {
		return ipam.buildAllocation(deptID, idx), nil
	}

	// Find the next free subnet.
	freeIdx := -1
	for i := 1; i < IPAMMaxSubnets; i++ { // Start at 1 (0 is reserved).
		if !ipam.bitmap[i] {
			freeIdx = i
			break
		}
	}

	if freeIdx == -1 {
		return nil, fmt.Errorf("ipam: IP pool exhausted — all %d subnets allocated", IPAMMaxSubnets-1)
	}

	// Mark as allocated.
	ipam.bitmap[freeIdx] = true
	ipam.allocated[deptID] = freeIdx

	alloc := ipam.buildAllocation(deptID, freeIdx)

	// Persist to database.
	if ipam.db != nil {
		ipam.db.Exec(`
			INSERT INTO ip_allocations (ip_address, dept_id) VALUES (?, ?)
			ON CONFLICT(ip_address) DO UPDATE SET dept_id = excluded.dept_id
		`, alloc.ContainerIP, deptID)
	}

	return alloc, nil
}

// Release frees a department's subnet allocation back to the pool.
func (ipam *IPAM) Release(deptID int) error {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	idx, exists := ipam.allocated[deptID]
	if !exists {
		return fmt.Errorf("ipam: department %d has no allocation", deptID)
	}

	ipam.bitmap[idx] = false
	delete(ipam.allocated, deptID)

	// Remove from database.
	if ipam.db != nil {
		ipam.db.Exec(`DELETE FROM ip_allocations WHERE dept_id = ?`, deptID)
	}

	return nil
}

// GetAllocation returns the current subnet allocation for a department.
func (ipam *IPAM) GetAllocation(deptID int) (*SubnetAllocation, error) {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	idx, exists := ipam.allocated[deptID]
	if !exists {
		return nil, fmt.Errorf("ipam: department %d not allocated", deptID)
	}

	return ipam.buildAllocation(deptID, idx), nil
}

// buildAllocation constructs a SubnetAllocation from a subnet index.
func (ipam *IPAM) buildAllocation(deptID, subnetIndex int) *SubnetAllocation {
	return &SubnetAllocation{
		DeptID:      deptID,
		SubnetIndex: subnetIndex,
		SubnetCIDR:  fmt.Sprintf("10.200.%d.0/24", subnetIndex),
		GatewayIP:   fmt.Sprintf("10.200.%d.1", subnetIndex),
		ContainerIP: fmt.Sprintf("10.200.%d.2", subnetIndex),
	}
}

// ListAllocations returns all current subnet allocations.
func (ipam *IPAM) ListAllocations() []*SubnetAllocation {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	var result []*SubnetAllocation
	for deptID, idx := range ipam.allocated {
		result = append(result, ipam.buildAllocation(deptID, idx))
	}
	return result
}

// AvailableSubnets returns the number of unallocated /24 subnets.
func (ipam *IPAM) AvailableSubnets() int {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	count := 0
	for i := 1; i < IPAMMaxSubnets; i++ {
		if !ipam.bitmap[i] {
			count++
		}
	}
	return count
}

// ValidateNoConflict checks that a proposed IP doesn't conflict
// with any existing allocation.
func (ipam *IPAM) ValidateNoConflict(containerIP string) error {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	ip := net.ParseIP(containerIP)
	if ip == nil {
		return fmt.Errorf("ipam: invalid IP: %s", containerIP)
	}

	ip4 := ip.To4()
	if ip4 == nil || ip4[0] != 10 || ip4[1] != 200 {
		return fmt.Errorf("ipam: IP not in GHOST-STACK range: %s", containerIP)
	}

	subnetIdx := int(ip4[2])
	if subnetIdx >= 0 && subnetIdx < IPAMMaxSubnets && ipam.bitmap[subnetIdx] {
		return fmt.Errorf("ipam: subnet 10.200.%d.0/24 already allocated", subnetIdx)
	}

	return nil
}
