// Package main — state.go implements the Orchestrator State Manager
// for GHOST-STACK CORE.
//
// Gap 2: Persistent state across restarts.
//
// Tracks the mapping of Department IDs → PIDs, allocated IPs,
// active LUKS volume mount points, and container config.
//
// Storage: local SQLite database on the host at
//   /var/lib/ghost-stack/orchestrator.db
//
// This database is OUTSIDE of any container namespace — it exists
// only on the host filesystem. Containers cannot access it.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	stateDBPath = "/var/lib/ghost-stack/orchestrator.db"
)

// DepartmentState represents the persisted state of a single department.
type DepartmentState struct {
	DeptID        int       `json:"dept_id"`
	DeptName      string    `json:"dept_name"`
	Tier          string    `json:"tier"`
	PID           int       `json:"pid"`
	ContainerIP   string    `json:"container_ip"`
	GatewayIP     string    `json:"gateway_ip"`
	SubnetCIDR    string    `json:"subnet_cidr"`
	CgroupPath    string    `json:"cgroup_path"`
	RootFS        string    `json:"rootfs_path"`
	LUKSMountPath string    `json:"luks_mount_path"`
	LUKSVolPath   string    `json:"luks_volume_path"`
	LUKSDMName    string    `json:"luks_dm_name"`
	ParentDeptID  int       `json:"parent_dept_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Status        string    `json:"status"` // "running", "quarantined", "stopped"
}

// StateManager provides persistent orchestrator state across restarts.
type StateManager struct {
	mu sync.Mutex
	db *sql.DB
}

// NewStateManager opens or creates the state database.
func NewStateManager() (*StateManager, error) {
	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(stateDBPath), 0o700); err != nil {
		return nil, fmt.Errorf("state: mkdir: %w", err)
	}

	db, err := sql.Open("sqlite3", stateDBPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("state: open db: %w", err)
	}

	sm := &StateManager{db: db}
	if err := sm.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: migrate: %w", err)
	}

	return sm, nil
}

// migrate creates or updates the database schema.
func (sm *StateManager) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS departments (
		dept_id        INTEGER PRIMARY KEY,
		dept_name      TEXT NOT NULL,
		tier           TEXT NOT NULL,
		pid            INTEGER DEFAULT 0,
		container_ip   TEXT NOT NULL,
		gateway_ip     TEXT NOT NULL,
		subnet_cidr    TEXT NOT NULL,
		cgroup_path    TEXT DEFAULT '',
		rootfs_path    TEXT DEFAULT '',
		luks_mount     TEXT DEFAULT '',
		luks_volume    TEXT DEFAULT '',
		luks_dm_name   TEXT DEFAULT '',
		parent_dept_id INTEGER DEFAULT -1,
		created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
		status         TEXT DEFAULT 'running'
	);

	CREATE TABLE IF NOT EXISTS ip_allocations (
		ip_address  TEXT PRIMARY KEY,
		dept_id     INTEGER NOT NULL,
		allocated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(dept_id) REFERENCES departments(dept_id)
	);

	CREATE TABLE IF NOT EXISTS ed25519_keys (
		key_name   TEXT PRIMARY KEY,
		public_key BLOB NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_dept_status ON departments(status);
	CREATE INDEX IF NOT EXISTS idx_ip_dept ON ip_allocations(dept_id);
	`
	_, err := sm.db.Exec(schema)
	return err
}

// SaveDepartment persists a department's state.
func (sm *StateManager) SaveDepartment(state *DepartmentState) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		INSERT INTO departments (
			dept_id, dept_name, tier, pid, container_ip, gateway_ip,
			subnet_cidr, cgroup_path, rootfs_path, luks_mount,
			luks_volume, luks_dm_name, parent_dept_id, status, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(dept_id) DO UPDATE SET
			pid = excluded.pid,
			container_ip = excluded.container_ip,
			gateway_ip = excluded.gateway_ip,
			subnet_cidr = excluded.subnet_cidr,
			cgroup_path = excluded.cgroup_path,
			rootfs_path = excluded.rootfs_path,
			luks_mount = excluded.luks_mount,
			luks_volume = excluded.luks_volume,
			luks_dm_name = excluded.luks_dm_name,
			status = excluded.status,
			updated_at = CURRENT_TIMESTAMP
	`,
		state.DeptID, state.DeptName, state.Tier, state.PID,
		state.ContainerIP, state.GatewayIP, state.SubnetCIDR,
		state.CgroupPath, state.RootFS, state.LUKSMountPath,
		state.LUKSVolPath, state.LUKSDMName, state.ParentDeptID,
		state.Status,
	)
	return err
}

// GetDepartment retrieves a single department's state by ID.
func (sm *StateManager) GetDepartment(deptID int) (*DepartmentState, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	row := sm.db.QueryRow(`
		SELECT dept_id, dept_name, tier, pid, container_ip, gateway_ip,
		       subnet_cidr, cgroup_path, rootfs_path, luks_mount,
		       luks_volume, luks_dm_name, parent_dept_id, created_at,
		       updated_at, status
		FROM departments WHERE dept_id = ?
	`, deptID)

	var s DepartmentState
	err := row.Scan(
		&s.DeptID, &s.DeptName, &s.Tier, &s.PID,
		&s.ContainerIP, &s.GatewayIP, &s.SubnetCIDR,
		&s.CgroupPath, &s.RootFS, &s.LUKSMountPath,
		&s.LUKSVolPath, &s.LUKSDMName, &s.ParentDeptID,
		&s.CreatedAt, &s.UpdatedAt, &s.Status,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("state: department %d not found", deptID)
	}
	if err != nil {
		return nil, fmt.Errorf("state: query dept %d: %w", deptID, err)
	}
	return &s, nil
}

// ListDepartments returns all departments with the given status filter.
// Pass "" for status to list all departments.
func (sm *StateManager) ListDepartments(statusFilter string) ([]*DepartmentState, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var rows *sql.Rows
	var err error

	if statusFilter != "" {
		rows, err = sm.db.Query(`
			SELECT dept_id, dept_name, tier, pid, container_ip, gateway_ip,
			       subnet_cidr, cgroup_path, rootfs_path, luks_mount,
			       luks_volume, luks_dm_name, parent_dept_id, created_at,
			       updated_at, status
			FROM departments WHERE status = ?
			ORDER BY dept_id
		`, statusFilter)
	} else {
		rows, err = sm.db.Query(`
			SELECT dept_id, dept_name, tier, pid, container_ip, gateway_ip,
			       subnet_cidr, cgroup_path, rootfs_path, luks_mount,
			       luks_volume, luks_dm_name, parent_dept_id, created_at,
			       updated_at, status
			FROM departments ORDER BY dept_id
		`)
	}
	if err != nil {
		return nil, fmt.Errorf("state: list: %w", err)
	}
	defer rows.Close()

	var result []*DepartmentState
	for rows.Next() {
		var s DepartmentState
		if err := rows.Scan(
			&s.DeptID, &s.DeptName, &s.Tier, &s.PID,
			&s.ContainerIP, &s.GatewayIP, &s.SubnetCIDR,
			&s.CgroupPath, &s.RootFS, &s.LUKSMountPath,
			&s.LUKSVolPath, &s.LUKSDMName, &s.ParentDeptID,
			&s.CreatedAt, &s.UpdatedAt, &s.Status,
		); err != nil {
			continue
		}
		result = append(result, &s)
	}
	return result, nil
}

// UpdatePID updates the PID for a department (used after restart re-discovery).
func (sm *StateManager) UpdatePID(deptID, pid int) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		UPDATE departments SET pid = ?, updated_at = CURRENT_TIMESTAMP WHERE dept_id = ?
	`, pid, deptID)
	return err
}

// UpdateStatus changes the status of a department.
func (sm *StateManager) UpdateStatus(deptID int, status string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, err := sm.db.Exec(`
		UPDATE departments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE dept_id = ?
	`, status, deptID)
	return err
}

// DeleteDepartment removes a department from the state database.
func (sm *StateManager) DeleteDepartment(deptID int) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	tx, err := sm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tx.Exec("DELETE FROM ip_allocations WHERE dept_id = ?", deptID)
	tx.Exec("DELETE FROM departments WHERE dept_id = ?", deptID)

	return tx.Commit()
}

// RecoverRunningDepartments identifies departments that were running before
// a restart. Checks if PIDs are still alive and updates status accordingly.
func (sm *StateManager) RecoverRunningDepartments() ([]*DepartmentState, error) {
	depts, err := sm.ListDepartments("running")
	if err != nil {
		return nil, err
	}

	var alive []*DepartmentState
	for _, dept := range depts {
		// Check if the PID is still alive.
		procPath := fmt.Sprintf("/proc/%d/status", dept.PID)
		if _, err := os.Stat(procPath); err != nil {
			// Process is gone — mark as stopped.
			sm.UpdateStatus(dept.DeptID, "stopped")
			continue
		}
		alive = append(alive, dept)
	}

	return alive, nil
}

// ExportState returns a JSON snapshot of the entire orchestrator state.
// Used for backup and disaster recovery.
func (sm *StateManager) ExportState() ([]byte, error) {
	depts, err := sm.ListDepartments("")
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(depts, "", "  ")
}

// Close closes the state database.
func (sm *StateManager) Close() error {
	return sm.db.Close()
}
