package hierarchy

import (
	"strings"
	"sync"
	"testing"
)

// ═══════════════════════════════════════════════════════════
// Tier Tests
// ═══════════════════════════════════════════════════════════

func TestTierString(t *testing.T) {
	tests := []struct {
		tier Tier
		want string
	}{
		{TierStaff, "STAFF"},
		{TierManager, "MANAGER"},
		{TierDirector, "DIRECTOR"},
		{TierRoot, "ROOT"},
		{Tier(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		got := tt.tier.String()
		if got != tt.want {
			t.Errorf("Tier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════
// UID Mapping Tests
// ═══════════════════════════════════════════════════════════

func TestTierUIDBase(t *testing.T) {
	tests := []struct {
		tier Tier
		want uint32
	}{
		{TierRoot, 100000},
		{TierDirector, 200000},
		{TierManager, 300000},
		{TierStaff, 400000},
	}
	for _, tt := range tests {
		got := TierUIDBase(tt.tier)
		if got != tt.want {
			t.Errorf("TierUIDBase(%s) = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

func TestDepartmentUIDMapping(t *testing.T) {
	mapping := DepartmentUIDMapping(TierManager, 5)

	if mapping.HostStart != 305000 {
		t.Errorf("HostStart = %d, want 305000", mapping.HostStart)
	}
	if mapping.ContainerStart != 0 {
		t.Errorf("ContainerStart = %d, want 0", mapping.ContainerStart)
	}
	if mapping.Size != 1000 {
		t.Errorf("Size = %d, want 1000", mapping.Size)
	}
}

func TestDepartmentUIDMappingNoOverlap(t *testing.T) {
	// Verify no UID range overlap between ANY tier+dept combination.
	type rangeEntry struct {
		start, end uint32
		tier       Tier
		dept       int
	}
	var ranges []rangeEntry

	for _, tier := range []Tier{TierRoot, TierDirector, TierManager, TierStaff} {
		for dept := 0; dept <= 99; dept++ {
			m := DepartmentUIDMapping(tier, dept)
			ranges = append(ranges, rangeEntry{
				start: m.HostStart,
				end:   m.HostStart + m.Size - 1,
				tier:  tier,
				dept:  dept,
			})
		}
	}

	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			a, b := ranges[i], ranges[j]
			if a.start <= b.end && b.start <= a.end {
				t.Fatalf("UID OVERLAP: %s dept-%d [%d-%d] overlaps %s dept-%d [%d-%d]",
					a.tier, a.dept, a.start, a.end,
					b.tier, b.dept, b.start, b.end)
			}
		}
	}
}

func TestDepartmentUIDMappingPanicsOnInvalidID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for deptID > 99")
		}
	}()
	DepartmentUIDMapping(TierStaff, 100)
}

// ═══════════════════════════════════════════════════════════
// HierarchyTree Tests
// ═══════════════════════════════════════════════════════════

func newTestTree(t *testing.T) *HierarchyTree {
	t.Helper()
	ht, err := NewHierarchyTree()
	if err != nil {
		t.Fatalf("NewHierarchyTree() error: %v", err)
	}
	return ht
}

func TestNewHierarchyTree(t *testing.T) {
	ht := newTestTree(t)

	// Master key should be non-zero.
	allZero := true
	for _, b := range ht.masterKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("master key is all zeros — random generation failed")
	}
}

func TestRegisterDepartment_Root(t *testing.T) {
	ht := newTestTree(t)

	dept, err := ht.RegisterDepartment(0, "HQ", TierRoot, -1)
	if err != nil {
		t.Fatalf("RegisterDepartment ROOT: %v", err)
	}

	if dept.ID != 0 || dept.Name != "HQ" || dept.Tier != TierRoot {
		t.Errorf("unexpected dept: %+v", dept)
	}
	if dept.ParentID != -1 {
		t.Errorf("ROOT should have ParentID=-1, got %d", dept.ParentID)
	}
}

func TestRegisterDepartment_Hierarchy(t *testing.T) {
	ht := newTestTree(t)

	// ROOT → DIRECTOR → MANAGER → STAFF
	ht.RegisterDepartment(0, "HQ", TierRoot, -1)
	ht.RegisterDepartment(1, "Engineering", TierDirector, 0)
	ht.RegisterDepartment(10, "Backend", TierManager, 1)
	_, err := ht.RegisterDepartment(100, "dev-alice", TierStaff, 10)
	if err != nil {
		t.Fatalf("full hierarchy registration failed: %v", err)
	}
}

func TestRegisterDepartment_DuplicateID(t *testing.T) {
	ht := newTestTree(t)
	ht.RegisterDepartment(0, "HQ", TierRoot, -1)

	_, err := ht.RegisterDepartment(0, "Duplicate", TierRoot, -1)
	if err == nil {
		t.Error("expected error for duplicate department ID")
	}
}

func TestRegisterDepartment_InvalidParent(t *testing.T) {
	ht := newTestTree(t)

	_, err := ht.RegisterDepartment(1, "Engineering", TierDirector, 999)
	if err == nil {
		t.Error("expected error for non-existent parent")
	}
}

func TestRegisterDepartment_ParentTierViolation(t *testing.T) {
	ht := newTestTree(t)
	ht.RegisterDepartment(0, "HQ", TierRoot, -1)
	ht.RegisterDepartment(10, "Backend", TierManager, 0)

	// STAFF cannot be parent of MANAGER.
	_, err := ht.RegisterDepartment(100, "dev-alice", TierStaff, 0)
	// This should work since ROOT > STAFF.
	if err != nil {
		t.Errorf("ROOT > STAFF should be valid parent: %v", err)
	}

	// STAFF cannot be parent of anything (same tier).
	ht.RegisterDepartment(50, "dev-bob", TierStaff, 10)
	_, err = ht.RegisterDepartment(51, "invalid", TierStaff, 50)
	if err == nil {
		t.Error("expected error: STAFF cannot be parent of STAFF")
	}
}

func TestIsolationKeysAreUnique(t *testing.T) {
	ht := newTestTree(t)
	ht.RegisterDepartment(0, "HQ", TierRoot, -1)
	ht.RegisterDepartment(1, "Engineering", TierDirector, 0)

	dept0, _ := ht.GetDepartment(0)
	dept1, _ := ht.GetDepartment(1)

	if dept0.IsolationKey == dept1.IsolationKey {
		t.Error("departments should have unique isolation keys")
	}
}

// ═══════════════════════════════════════════════════════════
// RBAC Access Control Tests
// ═══════════════════════════════════════════════════════════

func setupRBACTree(t *testing.T) *HierarchyTree {
	t.Helper()
	ht := newTestTree(t)

	// Build test hierarchy:
	// ROOT(0) → DIRECTOR(1) → MANAGER(10) → STAFF(100)
	//                       → MANAGER(11) → STAFF(110)
	ht.RegisterDepartment(0, "HQ", TierRoot, -1)
	ht.RegisterDepartment(1, "Engineering", TierDirector, 0)
	ht.RegisterDepartment(10, "Backend", TierManager, 1)
	ht.RegisterDepartment(11, "Frontend", TierManager, 1)
	ht.RegisterDepartment(100, "dev-alice", TierStaff, 10)
	ht.RegisterDepartment(110, "dev-bob", TierStaff, 11)

	return ht
}

func TestCanAccess_SelfAlwaysAllowed(t *testing.T) {
	ht := setupRBACTree(t)

	for _, id := range []int{0, 1, 10, 100} {
		ok, err := ht.CanAccess(id, id)
		if err != nil || !ok {
			t.Errorf("self-access denied for dept %d", id)
		}
	}
}

func TestCanAccess_RootSeesEverything(t *testing.T) {
	ht := setupRBACTree(t)

	for _, targetID := range []int{0, 1, 10, 11, 100, 110} {
		ok, err := ht.CanAccess(0, targetID)
		if err != nil || !ok {
			t.Errorf("ROOT should access dept %d", targetID)
		}
	}
}

func TestCanAccess_DirectorSeesSubordinates(t *testing.T) {
	ht := setupRBACTree(t)

	// DIRECTOR(1) should see MANAGER(10), MANAGER(11), STAFF(100), STAFF(110).
	for _, targetID := range []int{10, 11, 100, 110} {
		ok, err := ht.CanAccess(1, targetID)
		if err != nil || !ok {
			t.Errorf("DIRECTOR should access subordinate dept %d", targetID)
		}
	}

	// DIRECTOR(1) should NOT see ROOT(0).
	ok, _ := ht.CanAccess(1, 0)
	if ok {
		t.Error("DIRECTOR should NOT access ROOT")
	}
}

func TestCanAccess_ManagerSeesDirectChildren(t *testing.T) {
	ht := setupRBACTree(t)

	// MANAGER(10) sees STAFF(100) (direct child).
	ok, err := ht.CanAccess(10, 100)
	if err != nil || !ok {
		t.Error("MANAGER should access direct child STAFF")
	}

	// MANAGER(10) should NOT see STAFF(110) (different manager).
	ok, _ = ht.CanAccess(10, 110)
	if ok {
		t.Error("MANAGER should NOT access other manager's STAFF")
	}

	// MANAGER(10) should NOT see DIRECTOR(1).
	ok, _ = ht.CanAccess(10, 1)
	if ok {
		t.Error("MANAGER should NOT access DIRECTOR")
	}
}

func TestCanAccess_StaffSeesNothing(t *testing.T) {
	ht := setupRBACTree(t)

	// STAFF(100) cannot see ANYONE else.
	for _, targetID := range []int{0, 1, 10, 11, 110} {
		ok, _ := ht.CanAccess(100, targetID)
		if ok {
			t.Errorf("STAFF should NOT access dept %d", targetID)
		}
	}
}

func TestCanAccess_NonExistentRequester(t *testing.T) {
	ht := setupRBACTree(t)

	_, err := ht.CanAccess(999, 0)
	if err == nil {
		t.Error("expected error for non-existent requester")
	}
}

// ═══════════════════════════════════════════════════════════
// ListVisible Tests
// ═══════════════════════════════════════════════════════════

func TestListVisible_Root(t *testing.T) {
	ht := setupRBACTree(t)

	visible, err := ht.ListVisible(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 6 {
		t.Errorf("ROOT should see 6 departments, got %d", len(visible))
	}
}

func TestListVisible_Staff(t *testing.T) {
	ht := setupRBACTree(t)

	visible, err := ht.ListVisible(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 || visible[0] != 100 {
		t.Errorf("STAFF should see only self, got %v", visible)
	}
}

func TestListVisible_Manager(t *testing.T) {
	ht := setupRBACTree(t)

	visible, err := ht.ListVisible(10)
	if err != nil {
		t.Fatal(err)
	}
	// MANAGER(10) should see self + STAFF(100).
	if len(visible) != 2 {
		t.Errorf("MANAGER should see 2 departments, got %d: %v", len(visible), visible)
	}
}

// ═══════════════════════════════════════════════════════════
// Isolation Key Tests
// ═══════════════════════════════════════════════════════════

func TestGetIsolationKeyHex_Allowed(t *testing.T) {
	ht := setupRBACTree(t)

	key, err := ht.GetIsolationKeyHex(0, 100)
	if err != nil {
		t.Fatalf("ROOT should access STAFF isolation key: %v", err)
	}
	if len(key) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("isolation key hex length = %d, want 64", len(key))
	}
}

func TestGetIsolationKeyHex_Denied(t *testing.T) {
	ht := setupRBACTree(t)

	_, err := ht.GetIsolationKeyHex(100, 0)
	if err == nil {
		t.Error("STAFF should NOT access ROOT isolation key")
	}
}

// ═══════════════════════════════════════════════════════════
// Container PID + Status Tests
// ═══════════════════════════════════════════════════════════

func TestSetContainerPID(t *testing.T) {
	ht := setupRBACTree(t)

	err := ht.SetContainerPID(10, 12345)
	if err != nil {
		t.Fatal(err)
	}

	status, err := ht.Status(10)
	if err != nil {
		t.Fatal(err)
	}
	if status.ContainerPID != 12345 {
		t.Errorf("ContainerPID = %d, want 12345", status.ContainerPID)
	}
	if !status.Running {
		t.Error("department with PID > 0 should be Running=true")
	}
}

func TestShowHierarchy(t *testing.T) {
	ht := setupRBACTree(t)

	output := ht.ShowHierarchy()
	if output == "" {
		t.Error("ShowHierarchy() returned empty string")
	}
	if !strings.Contains(output, "HQ") {
		t.Error("hierarchy tree should contain 'HQ'")
	}
	if !strings.Contains(output, "STAFF") {
		t.Error("hierarchy tree should contain 'STAFF'")
	}
}

// ═══════════════════════════════════════════════════════════
// Concurrency Tests
// ═══════════════════════════════════════════════════════════

func TestConcurrentAccess(t *testing.T) {
	ht := setupRBACTree(t)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ht.CanAccess(0, 100)
			ht.CanAccess(1, 110)
			ht.CanAccess(100, 0)
			ht.ListVisible(0)
			ht.ListVisible(100)
			ht.GetDepartment(10)
			ht.Status(1)
		}()
	}
	wg.Wait()
}
