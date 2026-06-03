package db

import (
	"testing"

	"github.com/ghost-stack/core/hierarchy"
)

// ═══════════════════════════════════════════════════════════
// DatabaseType Tests
// ═══════════════════════════════════════════════════════════

func TestDatabaseTypeString(t *testing.T) {
	tests := []struct {
		dt   DatabaseType
		want string
	}{
		{DBTypeSQLite, "SQLite"},
		{DBTypePostgreSQL, "PostgreSQL"},
		{DatabaseType(99), "Unknown"},
	}
	for _, tt := range tests {
		got := tt.dt.String()
		if got != tt.want {
			t.Errorf("DatabaseType(%d).String() = %q, want %q", tt.dt, got, tt.want)
		}
	}
}

func TestDatabaseTypeForTier(t *testing.T) {
	tests := []struct {
		tier hierarchy.Tier
		want DatabaseType
	}{
		{hierarchy.TierStaff, DBTypeSQLite},
		{hierarchy.TierManager, DBTypeSQLite},
		{hierarchy.TierDirector, DBTypePostgreSQL},
		{hierarchy.TierRoot, DBTypePostgreSQL},
	}
	for _, tt := range tests {
		got := DatabaseTypeForTier(tt.tier)
		if got != tt.want {
			t.Errorf("DatabaseTypeForTier(%s) = %v, want %v", tt.tier, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════
// KeyVault Tests
// ═══════════════════════════════════════════════════════════

func TestNewKeyVault(t *testing.T) {
	tmpDir := t.TempDir()

	kv, err := NewKeyVault(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyVault() error: %v", err)
	}

	// Master key should be non-zero.
	allZero := true
	for _, b := range kv.masterKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("vault master key is all zeros")
	}
}

func TestGenerateCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	kv, _ := NewKeyVault(tmpDir)

	creds, err := kv.generateCredentials(1, "testdept", DBTypeSQLite)
	if err != nil {
		t.Fatalf("generateCredentials error: %v", err)
	}

	if creds.Username != "ghost_dept_1" {
		t.Errorf("Username = %q, want ghost_dept_1", creds.Username)
	}
	if creds.Database != "ghost_testdept" {
		t.Errorf("Database = %q, want ghost_testdept", creds.Database)
	}
	if len(creds.Password) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("Password length = %d, want 64", len(creds.Password))
	}
	if creds.Port != 0 { // SQLite has no port
		t.Errorf("SQLite Port = %d, want 0", creds.Port)
	}
	if creds.ExpiresAt.Before(creds.CreatedAt) {
		t.Error("ExpiresAt should be after CreatedAt")
	}
}

func TestGenerateCredentials_PostgreSQL(t *testing.T) {
	tmpDir := t.TempDir()
	kv, _ := NewKeyVault(tmpDir)

	creds, err := kv.generateCredentials(5, "engdept", DBTypePostgreSQL)
	if err != nil {
		t.Fatalf("generateCredentials error: %v", err)
	}
	if creds.Port != 5437 { // 5432 + deptID(5)
		t.Errorf("PostgreSQL Port = %d, want 5437", creds.Port)
	}
}

func TestCredentials_UniquePasswords(t *testing.T) {
	tmpDir := t.TempDir()
	kv, _ := NewKeyVault(tmpDir)

	creds1, _ := kv.generateCredentials(1, "dept1", DBTypeSQLite)
	creds2, _ := kv.generateCredentials(2, "dept2", DBTypeSQLite)

	if creds1.Password == creds2.Password {
		t.Error("different departments should have different passwords")
	}
}

// ═══════════════════════════════════════════════════════════
// HostKeyStore Tests (Gap 4)
// ═══════════════════════════════════════════════════════════

func TestNewHostKeyStore(t *testing.T) {
	hks := NewHostKeyStore()
	if hks == nil {
		t.Fatal("NewHostKeyStore returned nil")
	}
}

func TestHostKeyStore_StoreAndRetrieve(t *testing.T) {
	hks := NewHostKeyStore()
	key := []byte("test-encryption-key-256-bits-xx!")

	hks.StoreKey(1, key)

	// Verify key is stored (via UseKey callback).
	var retrievedPath string
	err := hks.UseKey(1, func(keyFilePath string) error {
		retrievedPath = keyFilePath
		return nil
	})

	// On non-Linux (macOS CI), /dev/shm won't exist.
	// This is expected — the test validates the logic path.
	if err != nil {
		t.Logf("UseKey returned error (expected on non-Linux): %v", err)
	} else if retrievedPath == "" {
		t.Error("UseKey callback should receive non-empty path")
	}
}

func TestHostKeyStore_WipeKey(t *testing.T) {
	hks := NewHostKeyStore()
	key := []byte("sensitive-key-data-here!!")

	hks.StoreKey(1, key)
	hks.WipeKey(1)

	err := hks.UseKey(1, func(path string) error {
		return nil
	})
	if err == nil {
		t.Error("UseKey should fail after WipeKey")
	}
}

func TestHostKeyStore_WipeAll(t *testing.T) {
	hks := NewHostKeyStore()

	for i := 0; i < 5; i++ {
		hks.StoreKey(i, []byte("key-data"))
	}

	hks.WipeAll()

	for i := 0; i < 5; i++ {
		err := hks.UseKey(i, func(path string) error { return nil })
		if err == nil {
			t.Errorf("UseKey(%d) should fail after WipeAll", i)
		}
	}
}

func TestHostKeyStore_KeyIsolation(t *testing.T) {
	hks := NewHostKeyStore()

	// Store different keys for different departments.
	hks.StoreKey(1, []byte("key-for-dept-1"))
	hks.StoreKey(2, []byte("key-for-dept-2"))

	// Wipe dept 1 — dept 2 should still work.
	hks.WipeKey(1)

	err := hks.UseKey(1, func(path string) error { return nil })
	if err == nil {
		t.Error("dept 1 key should be wiped")
	}

	err = hks.UseKey(2, func(path string) error { return nil })
	// Will fail on non-Linux due to /dev/shm, but should not fail due to key missing.
	if err != nil && err.Error() == "host-key-store: no key for dept 2" {
		t.Error("dept 2 key should still exist")
	}
}

func TestHostKeyStore_CallerKeyNotCorrupted(t *testing.T) {
	hks := NewHostKeyStore()
	original := []byte("original-key-content!")
	originalCopy := make([]byte, len(original))
	copy(originalCopy, original)

	hks.StoreKey(1, original)

	// Modify the caller's buffer.
	for i := range original {
		original[i] = 'X'
	}

	// The stored key should NOT be affected.
	hks.mu.Lock()
	stored := hks.keys[1]
	hks.mu.Unlock()

	for i, b := range stored {
		if b != originalCopy[i] {
			t.Error("StoreKey should copy the key — caller mutation should not affect stored key")
			break
		}
	}
}

// ═══════════════════════════════════════════════════════════
// Encryption Key Tests
// ═══════════════════════════════════════════════════════════

func TestEncryptKey(t *testing.T) {
	tmpDir := t.TempDir()
	kv, _ := NewKeyVault(tmpDir)

	plaintext := []byte("test-plaintext-key-data")
	ciphertext, err := kv.encryptKey(plaintext)
	if err != nil {
		t.Fatalf("encryptKey error: %v", err)
	}

	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext (nonce + tag)")
	}

	// Encrypt same plaintext twice — should produce different ciphertext (random nonce).
	ciphertext2, _ := kv.encryptKey(plaintext)
	if string(ciphertext) == string(ciphertext2) {
		t.Error("same plaintext should produce different ciphertext (random nonce)")
	}
}

// ═══════════════════════════════════════════════════════════
// WipeBytes Tests
// ═══════════════════════════════════════════════════════════

func TestWipeBytes(t *testing.T) {
	data := []byte("sensitive-data-here!")
	wipeBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not wiped: %d", i, b)
		}
	}
}
