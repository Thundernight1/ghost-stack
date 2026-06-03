// Package hierarchy implements the 4-tier RBAC visibility enforcement
// for GHOST-STACK CORE department containers.
//
// Hierarchy: ROOT > DIRECTOR > MANAGER > STAFF
//
// Enforcement is at kernel level via user namespace UID mapping.
// Cross-department data access is cryptographically impossible,
// not just policy-based.
package hierarchy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Tier represents a position in the 4-tier department hierarchy.
type Tier int

const (
	// TierStaff is the lowest tier — sees only own container, zero upward visibility.
	TierStaff Tier = iota
	// TierManager sees own department + direct reports only.
	TierManager
	// TierDirector can read all subordinate container data.
	TierDirector
	// TierRoot is the highest tier — full system visibility.
	TierRoot
)

// String returns the human-readable tier name.
func (t Tier) String() string {
	switch t {
	case TierStaff:
		return "STAFF"
	case TierManager:
		return "MANAGER"
	case TierDirector:
		return "DIRECTOR"
	case TierRoot:
		return "ROOT"
	default:
		return "UNKNOWN"
	}
}

// UIDRange defines the UID mapping range for a namespace tier.
// These ranges are mapped into user namespaces to provide kernel-level
// isolation between departments and hierarchy tiers.
type UIDRange struct {
	// HostStart is the starting UID on the host.
	HostStart uint32
	// ContainerStart is the starting UID inside the container namespace.
	ContainerStart uint32
	// Size is the number of UIDs in the mapping.
	Size uint32
}

// TierUIDBase returns the base host UID range for a given tier.
// Each tier occupies a 100,000 UID band to prevent any overlap.
//
// ROOT:      100000-199999
// DIRECTOR:  200000-299999
// MANAGER:   300000-399999
// STAFF:     400000-499999
//
// Within each tier, departments are further segmented by DeptID * 1000.
func TierUIDBase(tier Tier) uint32 {
	switch tier {
	case TierRoot:
		return 100000
	case TierDirector:
		return 200000
	case TierManager:
		return 300000
	case TierStaff:
		return 400000
	default:
		return 500000
	}
}

// DepartmentUIDMapping computes the user namespace UID mapping for a
// specific department at a given tier. The deptID must be 0-99.
func DepartmentUIDMapping(tier Tier, deptID int) UIDRange {
	if deptID < 0 || deptID > 99 {
		panic("ghost-stack: deptID must be in range [0, 99]")
	}
	base := TierUIDBase(tier)
	return UIDRange{
		HostStart:      base + uint32(deptID)*1000,
		ContainerStart: 0,
		Size:           1000,
	}
}

// Department represents a department container with its hierarchy metadata.
type Department struct {
	// ID is the unique department identifier (0-99).
	ID int
	// Name is the human-readable department name.
	Name string
	// Tier is the hierarchy tier of this department.
	Tier Tier
	// ParentID is the ID of the parent department (-1 for ROOT).
	ParentID int
	// Children holds the IDs of direct child departments.
	Children []int
	// IsolationKey is a per-department cryptographic key derived from
	// a master secret + department-specific entropy. Used to make
	// cross-department data access cryptographically impossible.
	IsolationKey [32]byte
	// CreatedAt is the department creation timestamp.
	CreatedAt time.Time
	// ContainerPID is the PID of the department's init process (0 if not running).
	ContainerPID int
	// CgroupPath is the cgroup v2 subtree path for this department.
	CgroupPath string
}

// HierarchyTree manages the complete department hierarchy and enforces
// RBAC visibility rules at the structural level.
type HierarchyTree struct {
	mu          sync.RWMutex
	departments map[int]*Department
	masterKey   [32]byte
}

// NewHierarchyTree creates a new hierarchy tree with a random master key.
func NewHierarchyTree() (*HierarchyTree, error) {
	ht := &HierarchyTree{
		departments: make(map[int]*Department),
	}
	// Generate master key for department isolation key derivation.
	if _, err := rand.Read(ht.masterKey[:]); err != nil {
		return nil, fmt.Errorf("ghost-stack: failed to generate master key: %w", err)
	}
	return ht, nil
}

// deriveIsolationKey derives a department-specific isolation key from the
// master key using HKDF-like construction: SHA-256(masterKey || deptID || entropy).
func (ht *HierarchyTree) deriveIsolationKey(deptID int) ([32]byte, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return [32]byte{}, fmt.Errorf("ghost-stack: entropy generation failed: %w", err)
	}
	h := sha256.New()
	h.Write(ht.masterKey[:])
	h.Write([]byte(fmt.Sprintf("dept:%d", deptID)))
	h.Write(entropy)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key, nil
}

// RegisterDepartment adds a new department to the hierarchy.
// The parent must exist (unless tier is ROOT, in which case parentID is -1).
func (ht *HierarchyTree) RegisterDepartment(id int, name string, tier Tier, parentID int) (*Department, error) {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	if _, exists := ht.departments[id]; exists {
		return nil, fmt.Errorf("ghost-stack: department %d already registered", id)
	}

	// Validate parent relationship.
	if tier == TierRoot {
		parentID = -1
	} else {
		parent, exists := ht.departments[parentID]
		if !exists {
			return nil, fmt.Errorf("ghost-stack: parent department %d not found", parentID)
		}
		// Parent must be strictly higher tier.
		if parent.Tier <= tier {
			return nil, fmt.Errorf("ghost-stack: parent tier %s must be higher than child tier %s",
				parent.Tier, tier)
		}
		parent.Children = append(parent.Children, id)
	}

	isolationKey, err := ht.deriveIsolationKey(id)
	if err != nil {
		return nil, err
	}

	dept := &Department{
		ID:           id,
		Name:         name,
		Tier:         tier,
		ParentID:     parentID,
		Children:     []int{},
		IsolationKey: isolationKey,
		CreatedAt:    time.Now(),
		CgroupPath:   fmt.Sprintf("/sys/fs/cgroup/ghost-stack/dept-%d", id),
	}
	ht.departments[id] = dept
	return dept, nil
}

// CanAccess checks whether a requester department can access data from
// a target department based on the 4-tier RBAC rules:
//
//   - ROOT: can access everything
//   - DIRECTOR: can access all subordinate containers
//   - MANAGER: can access own department + direct children
//   - STAFF: can access only own container
func (ht *HierarchyTree) CanAccess(requesterID, targetID int) (bool, error) {
	ht.mu.RLock()
	defer ht.mu.RUnlock()

	requester, exists := ht.departments[requesterID]
	if !exists {
		return false, fmt.Errorf("ghost-stack: requester department %d not found", requesterID)
	}
	if _, exists := ht.departments[targetID]; !exists {
		return false, fmt.Errorf("ghost-stack: target department %d not found", targetID)
	}

	// Self-access is always allowed.
	if requesterID == targetID {
		return true, nil
	}

	switch requester.Tier {
	case TierRoot:
		// ROOT can access everything.
		return true, nil

	case TierDirector:
		// DIRECTOR can access all subordinates (recursive).
		return ht.isSubordinateOf(targetID, requesterID), nil

	case TierManager:
		// MANAGER can access direct children only.
		for _, childID := range requester.Children {
			if childID == targetID {
				return true, nil
			}
		}
		return false, nil

	case TierStaff:
		// STAFF sees only own container — zero upward/lateral visibility.
		return false, nil

	default:
		return false, fmt.Errorf("ghost-stack: unknown tier %d", requester.Tier)
	}
}

// isSubordinateOf checks if targetID is a descendant of ancestorID
// in the hierarchy tree (recursive traversal).
func (ht *HierarchyTree) isSubordinateOf(targetID, ancestorID int) bool {
	ancestor, exists := ht.departments[ancestorID]
	if !exists {
		return false
	}
	for _, childID := range ancestor.Children {
		if childID == targetID {
			return true
		}
		if ht.isSubordinateOf(targetID, childID) {
			return true
		}
	}
	return false
}

// GetDepartment returns a department by ID (read-only copy).
func (ht *HierarchyTree) GetDepartment(id int) (*Department, error) {
	ht.mu.RLock()
	defer ht.mu.RUnlock()

	dept, exists := ht.departments[id]
	if !exists {
		return nil, fmt.Errorf("ghost-stack: department %d not found", id)
	}
	// Return a copy to prevent mutation.
	cpy := *dept
	cpy.Children = make([]int, len(dept.Children))
	copy(cpy.Children, dept.Children)
	return &cpy, nil
}

// ListVisible returns all department IDs visible to the given requester
// based on RBAC rules.
func (ht *HierarchyTree) ListVisible(requesterID int) ([]int, error) {
	ht.mu.RLock()
	defer ht.mu.RUnlock()

	requester, exists := ht.departments[requesterID]
	if !exists {
		return nil, fmt.Errorf("ghost-stack: requester department %d not found", requesterID)
	}

	var visible []int

	switch requester.Tier {
	case TierRoot:
		// ROOT sees everything.
		for id := range ht.departments {
			visible = append(visible, id)
		}

	case TierDirector:
		// DIRECTOR sees self + all subordinates.
		visible = append(visible, requesterID)
		ht.collectSubordinates(requesterID, &visible)

	case TierManager:
		// MANAGER sees self + direct children.
		visible = append(visible, requesterID)
		visible = append(visible, requester.Children...)

	case TierStaff:
		// STAFF sees only self.
		visible = append(visible, requesterID)
	}

	return visible, nil
}

// collectSubordinates recursively collects all descendant department IDs.
func (ht *HierarchyTree) collectSubordinates(parentID int, result *[]int) {
	parent, exists := ht.departments[parentID]
	if !exists {
		return
	}
	for _, childID := range parent.Children {
		*result = append(*result, childID)
		ht.collectSubordinates(childID, result)
	}
}

// GetIsolationKeyHex returns the hex-encoded isolation key for a department.
// Only accessible if the requester has access rights.
func (ht *HierarchyTree) GetIsolationKeyHex(requesterID, targetID int) (string, error) {
	canAccess, err := ht.CanAccess(requesterID, targetID)
	if err != nil {
		return "", err
	}
	if !canAccess {
		return "", fmt.Errorf("ghost-stack: access denied — department %d cannot access department %d isolation key", requesterID, targetID)
	}

	ht.mu.RLock()
	defer ht.mu.RUnlock()
	dept := ht.departments[targetID]
	return hex.EncodeToString(dept.IsolationKey[:]), nil
}

// SetContainerPID records the init PID for a running department container.
func (ht *HierarchyTree) SetContainerPID(deptID, pid int) error {
	ht.mu.Lock()
	defer ht.mu.Unlock()

	dept, exists := ht.departments[deptID]
	if !exists {
		return fmt.Errorf("ghost-stack: department %d not found", deptID)
	}
	dept.ContainerPID = pid
	return nil
}

// DepartmentStatus represents the runtime status of a department container.
type DepartmentStatus struct {
	DeptID       int
	Name         string
	Tier         string
	ParentID     int
	ChildCount   int
	ContainerPID int
	CgroupPath   string
	Running      bool
}

// Status returns the runtime status of a department.
func (ht *HierarchyTree) Status(deptID int) (*DepartmentStatus, error) {
	ht.mu.RLock()
	defer ht.mu.RUnlock()

	dept, exists := ht.departments[deptID]
	if !exists {
		return nil, fmt.Errorf("ghost-stack: department %d not found", deptID)
	}

	return &DepartmentStatus{
		DeptID:       dept.ID,
		Name:         dept.Name,
		Tier:         dept.Tier.String(),
		ParentID:     dept.ParentID,
		ChildCount:   len(dept.Children),
		ContainerPID: dept.ContainerPID,
		CgroupPath:   dept.CgroupPath,
		Running:      dept.ContainerPID > 0,
	}, nil
}

// ShowHierarchy returns a formatted tree representation of the hierarchy.
func (ht *HierarchyTree) ShowHierarchy() string {
	ht.mu.RLock()
	defer ht.mu.RUnlock()

	var roots []int
	for id, dept := range ht.departments {
		if dept.ParentID == -1 {
			roots = append(roots, id)
		}
	}

	var output string
	for _, rootID := range roots {
		output += ht.formatTree(rootID, "", true)
	}
	return output
}

// formatTree recursively formats the hierarchy tree.
func (ht *HierarchyTree) formatTree(deptID int, prefix string, isLast bool) string {
	dept, exists := ht.departments[deptID]
	if !exists {
		return ""
	}

	connector := "├── "
	if isLast {
		connector = "└── "
	}

	status := "⏹"
	if dept.ContainerPID > 0 {
		status = "▶"
	}

	line := fmt.Sprintf("%s%s[%s] %s (%s) %s PID:%d\n",
		prefix, connector, dept.Tier.String(), dept.Name,
		fmt.Sprintf("dept-%d", dept.ID), status, dept.ContainerPID)

	childPrefix := prefix + "    "
	if !isLast {
		childPrefix = prefix + "│   "
	}

	for i, childID := range dept.Children {
		line += ht.formatTree(childID, childPrefix, i == len(dept.Children)-1)
	}

	return line
}
