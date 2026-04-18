// Package db implements per-department encrypted database management
// with key rotation for GHOST-STACK CORE.
//
// Each department container has its own embedded database:
//   - STAFF/MANAGER level: SQLite
//   - DIRECTOR level: embedded PostgreSQL
//
// Database files are encrypted at rest via LUKS2 dm-crypt per-dept volume.
// Credentials are rotated every 24 hours via the orchestrator key vault.
// Backups are encrypted with department-specific GPG keys.
package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/ghost-stack/core/hierarchy"
)

// CredentialRotationInterval is how often database credentials are rotated.
const CredentialRotationInterval = 24 * time.Hour

// LUKSVolumeSize is the default size for per-department encrypted volumes.
const LUKSVolumeSize = "2G"

// DatabaseType identifies the database engine for a department.
type DatabaseType int

const (
	DBTypeSQLite     DatabaseType = iota // For STAFF and MANAGER tiers.
	DBTypePostgreSQL                     // For DIRECTOR tier.
)

// String returns the database type name.
func (dt DatabaseType) String() string {
	switch dt {
	case DBTypeSQLite:
		return "SQLite"
	case DBTypePostgreSQL:
		return "PostgreSQL"
	default:
		return "Unknown"
	}
}

// DatabaseConfig holds configuration for a department's database.
type DatabaseConfig struct {
	DeptID           int
	DeptName         string
	Tier             hierarchy.Tier
	Type             DatabaseType
	VolumePath       string // Path to LUKS2 dm-crypt volume file.
	MountPoint       string // Where the decrypted volume is mounted.
	GPGKeyID         string // Department-specific GPG key for backups.
	BackupDir        string // Where encrypted backups are stored.
}

// DatabaseCredentials holds the current database credentials.
type DatabaseCredentials struct {
	Username  string
	Password  string
	Database  string
	Host      string
	Port      int
	CreatedAt time.Time
	ExpiresAt time.Time
}

// DepartmentDatabase represents a running database instance for a department.
// CRITICAL: LUKSKey is NEVER stored here — it exists ONLY in HostKeyStore.
// Even if a container is compromised, the encryption key is unreachable.
type DepartmentDatabase struct {
	Config      DatabaseConfig
	Credentials DatabaseCredentials
	Running     bool
	MountedAt   time.Time
}

// HostKeyStore manages LUKS encryption keys exclusively in host memory.
// Keys NEVER enter container namespaces and NEVER touch persistent storage.
// Key material for cryptsetup is written to /dev/shm (tmpfs, RAM-only)
// and immediately wiped after use.
type HostKeyStore struct {
	mu   sync.Mutex
	keys map[int][]byte // DeptID → LUKS key (host memory ONLY).
}

// NewHostKeyStore creates a new host-side key store.
func NewHostKeyStore() *HostKeyStore {
	return &HostKeyStore{
		keys: make(map[int][]byte),
	}
}

// StoreKey stores a LUKS key in host memory only.
// The key is copied — the caller should wipe their copy.
func (hks *HostKeyStore) StoreKey(deptID int, key []byte) {
	hks.mu.Lock()
	defer hks.mu.Unlock()

	// Make a copy so caller can wipe their buffer.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	hks.keys[deptID] = keyCopy
}

// UseKey executes a function with temporary access to the key.
// The key is written to /dev/shm (tmpfs, RAM-backed) as a temporary file,
// the function is called with the tmpfs path, and the file is immediately
// wiped and removed after use.
//
// This ensures the key NEVER touches persistent disk.
func (hks *HostKeyStore) UseKey(deptID int, fn func(keyFilePath string) error) error {
	hks.mu.Lock()
	key, exists := hks.keys[deptID]
	if !exists {
		hks.mu.Unlock()
		return fmt.Errorf("host-key-store: no key for dept %d", deptID)
	}
	// Copy key while holding lock.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	hks.mu.Unlock()

	// Write to /dev/shm (tmpfs — exists only in RAM, never on disk).
	// This is the ONLY place the key is materialized as a file.
	tmpKeyFile := fmt.Sprintf("/dev/shm/ghost-luks-key-%d-%d", deptID, time.Now().UnixNano())
	if err := os.WriteFile(tmpKeyFile, keyCopy, 0o400); err != nil {
		wipeBytes(keyCopy)
		return fmt.Errorf("host-key-store: tmpfs write: %w", err)
	}

	// Execute the provided function with the tmpfs key path.
	fnErr := fn(tmpKeyFile)

	// IMMEDIATELY wipe and remove the tmpfs key file.
	wipeFile(tmpKeyFile)
	os.Remove(tmpKeyFile)
	wipeBytes(keyCopy)

	return fnErr
}

// WipeKey securely erases a department's key from host memory.
func (hks *HostKeyStore) WipeKey(deptID int) {
	hks.mu.Lock()
	defer hks.mu.Unlock()

	if key, exists := hks.keys[deptID]; exists {
		wipeBytes(key)
		delete(hks.keys, deptID)
	}
}

// WipeAll securely erases all keys from host memory.
func (hks *HostKeyStore) WipeAll() {
	hks.mu.Lock()
	defer hks.mu.Unlock()

	for id, key := range hks.keys {
		wipeBytes(key)
		delete(hks.keys, id)
	}
}

// wipeBytes overwrites a byte slice with zeros.
func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// wipeFile overwrites a file with zeros before deletion.
func wipeFile(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}

	zeros := make([]byte, info.Size())
	_ = f.Write(zeros)
	_ = f.Sync()
}

// KeyVault manages encryption keys and database credentials for all departments.
type KeyVault struct {
	mu sync.RWMutex

	// masterKey is the vault's master encryption key.
	masterKey [32]byte
	// databases maps DeptID to DepartmentDatabase.
	databases map[int]*DepartmentDatabase
	// hostKeys manages LUKS keys in host memory ONLY.
	// Keys NEVER enter container namespaces.
	hostKeys *HostKeyStore
	// gpgKeys maps DeptID to GPG key ID.
	gpgKeys map[int]string
	// basePath is the root path for vault storage.
	basePath string
}

// NewKeyVault creates a new key vault with a random master key.
func NewKeyVault(basePath string) (*KeyVault, error) {
	kv := &KeyVault{
		databases: make(map[int]*DepartmentDatabase),
		hostKeys:  NewHostKeyStore(),
		gpgKeys:   make(map[int]string),
		basePath:  basePath,
	}

	if _, err := rand.Read(kv.masterKey[:]); err != nil {
		return nil, fmt.Errorf("ghost-stack/vault: master key generation failed: %w", err)
	}

	// Ensure base directories exist.
	dirs := []string{
		filepath.Join(basePath, "volumes"),
		filepath.Join(basePath, "backups"),
		filepath.Join(basePath, "keys"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("ghost-stack/vault: mkdir %s: %w", d, err)
		}
	}

	return kv, nil
}

// DatabaseTypeForTier returns the appropriate database type for a hierarchy tier.
func DatabaseTypeForTier(tier hierarchy.Tier) DatabaseType {
	switch tier {
	case hierarchy.TierDirector, hierarchy.TierRoot:
		return DBTypePostgreSQL
	default:
		return DBTypeSQLite
	}
}

// InitializeDepartmentDB creates and initializes a per-department encrypted database.
//
// Steps:
//  1. Generate LUKS2 encryption key
//  2. Create encrypted volume (dm-crypt)
//  3. Format and mount the volume
//  4. Initialize the database engine
//  5. Generate initial credentials
//  6. Register in the vault
func (kv *KeyVault) InitializeDepartmentDB(deptID int, deptName string, tier hierarchy.Tier) (*DepartmentDatabase, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	if _, exists := kv.databases[deptID]; exists {
		return nil, fmt.Errorf("ghost-stack/vault: database for dept %d already initialized", deptID)
	}

	dbType := DatabaseTypeForTier(tier)
	volumePath := filepath.Join(kv.basePath, "volumes", fmt.Sprintf("dept-%d.luks2", deptID))
	mountPoint := filepath.Join(kv.basePath, "mounts", fmt.Sprintf("dept-%d", deptID))
	backupDir := filepath.Join(kv.basePath, "backups", fmt.Sprintf("dept-%d", deptID))
	gpgKeyID := fmt.Sprintf("dept-%d@ghoststack.internal", deptID)

	// Create directories.
	for _, d := range []string{mountPoint, backupDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("ghost-stack/vault: mkdir: %w", err)
		}
	}

	// Step 1: Generate LUKS2 encryption key.
	// Key is stored ONLY in HostKeyStore (host memory) — never exposed to containers.
	luksKey := make([]byte, 64) // 512-bit key for LUKS2.
	if _, err := rand.Read(luksKey); err != nil {
		return nil, fmt.Errorf("ghost-stack/vault: LUKS key generation: %w", err)
	}

	// Store key in host-only key store.
	kv.hostKeys.StoreKey(deptID, luksKey)

	// Step 2: Create the encrypted volume.
	// Key file is written to /dev/shm (tmpfs — RAM only) and wiped immediately.
	if err := kv.hostKeys.UseKey(deptID, func(keyFile string) error {
		return createLUKS2VolumeWithKeyFile(volumePath, keyFile)
	}); err != nil {
		wipeBytes(luksKey)
		return nil, fmt.Errorf("ghost-stack/vault: LUKS volume creation: %w", err)
	}

	// Step 3: Open and mount the volume.
	// Again uses /dev/shm for transient key file access.
	dmName := fmt.Sprintf("ghost-dept-%d", deptID)
	if err := kv.hostKeys.UseKey(deptID, func(keyFile string) error {
		return openLUKS2VolumeWithKeyFile(volumePath, dmName, keyFile)
	}); err != nil {
		wipeBytes(luksKey)
		return nil, fmt.Errorf("ghost-stack/vault: LUKS open: %w", err)
	}

	// Wipe the local copy of the key — only HostKeyStore retains it.
	wipeBytes(luksKey)

	if err := mountVolume(dmName, mountPoint); err != nil {
		return nil, fmt.Errorf("ghost-stack/vault: mount: %w", err)
	}

	// Step 4: Initialize database.
	switch dbType {
	case DBTypeSQLite:
		if err := initSQLiteDB(mountPoint, deptName); err != nil {
			return nil, fmt.Errorf("ghost-stack/vault: SQLite init: %w", err)
		}
	case DBTypePostgreSQL:
		if err := initPostgreSQL(mountPoint, deptName); err != nil {
			return nil, fmt.Errorf("ghost-stack/vault: PostgreSQL init: %w", err)
		}
	}

	// Step 5: Generate initial credentials.
	creds, err := kv.generateCredentials(deptID, deptName, dbType)
	if err != nil {
		return nil, fmt.Errorf("ghost-stack/vault: credential generation: %w", err)
	}

	config := DatabaseConfig{
		DeptID:     deptID,
		DeptName:   deptName,
		Tier:       tier,
		Type:       dbType,
		VolumePath: volumePath,
		MountPoint: mountPoint,
		GPGKeyID:   gpgKeyID,
		BackupDir:  backupDir,
	}

	db := &DepartmentDatabase{
		Config:      config,
		Credentials: *creds,
		// NOTE: LUKSKey is NOT stored here — it lives in HostKeyStore only.
		// Container compromise cannot access the encryption key.
		Running:     true,
		MountedAt:   time.Now(),
	}

	kv.databases[deptID] = db
	kv.gpgKeys[deptID] = gpgKeyID

	return db, nil
}

// RotateCredentials generates new database credentials for a department.
// Called every 24 hours by the orchestrator.
func (kv *KeyVault) RotateCredentials(deptID int) (*DatabaseCredentials, error) {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	db, exists := kv.databases[deptID]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/vault: dept %d not initialized", deptID)
	}

	newCreds, err := kv.generateCredentials(deptID, db.Config.DeptName, db.Config.Type)
	if err != nil {
		return nil, fmt.Errorf("ghost-stack/vault: credential rotation: %w", err)
	}

	// Update credentials in the database engine.
	switch db.Config.Type {
	case DBTypeSQLite:
		// SQLite doesn't have user authentication — the file permissions + LUKS
		// provide the security layer. Update the encryption key instead.
		if err := rotateSQLiteKey(db.Config.MountPoint, newCreds.Password); err != nil {
			return nil, fmt.Errorf("ghost-stack/vault: SQLite key rotation: %w", err)
		}
	case DBTypePostgreSQL:
		if err := rotatePostgreSQLCredentials(db.Config.MountPoint, newCreds); err != nil {
			return nil, fmt.Errorf("ghost-stack/vault: PostgreSQL credential rotation: %w", err)
		}
	}

	db.Credentials = *newCreds
	return newCreds, nil
}

// BackupDatabase creates a GPG-encrypted backup of a department's database.
// Only the department's DIRECTOR can decrypt the backup.
func (kv *KeyVault) BackupDatabase(deptID int) (string, error) {
	kv.mu.RLock()
	db, exists := kv.databases[deptID]
	kv.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("ghost-stack/vault: dept %d not initialized", deptID)
	}

	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("dept-%d-backup-%s", deptID, timestamp)

	// Create tarball of the database directory.
	tarPath := filepath.Join(db.Config.BackupDir, backupName+".tar.gz")
	tarCmd := exec.Command("tar", "czf", tarPath, "-C", db.Config.MountPoint, ".")
	if err := tarCmd.Run(); err != nil {
		return "", fmt.Errorf("ghost-stack/vault: backup tar: %w", err)
	}

	// Encrypt with department GPG key.
	gpgPath := tarPath + ".gpg"
	gpgCmd := exec.Command("gpg", "--batch", "--yes",
		"--recipient", db.Config.GPGKeyID,
		"--encrypt", "--output", gpgPath, tarPath)
	if err := gpgCmd.Run(); err != nil {
		return "", fmt.Errorf("ghost-stack/vault: GPG encrypt: %w", err)
	}

	// Remove unencrypted tarball.
	_ = os.Remove(tarPath)

	return gpgPath, nil
}

// GetCredentials returns the current credentials for a department's database.
// Access is controlled by the RBAC hierarchy.
func (kv *KeyVault) GetCredentials(deptID int) (*DatabaseCredentials, error) {
	kv.mu.RLock()
	defer kv.mu.RUnlock()

	db, exists := kv.databases[deptID]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/vault: dept %d not initialized", deptID)
	}

	// Check if credentials have expired.
	if time.Now().After(db.Credentials.ExpiresAt) {
		return nil, fmt.Errorf("ghost-stack/vault: credentials expired, rotation required")
	}

	creds := db.Credentials
	return &creds, nil
}

// ShutdownDatabase safely unmounts and closes the encrypted volume.
func (kv *KeyVault) ShutdownDatabase(deptID int) error {
	kv.mu.Lock()
	defer kv.mu.Unlock()

	db, exists := kv.databases[deptID]
	if !exists {
		return fmt.Errorf("ghost-stack/vault: dept %d not initialized", deptID)
	}

	// Unmount the filesystem.
	umountCmd := exec.Command("umount", db.Config.MountPoint)
	if err := umountCmd.Run(); err != nil {
		return fmt.Errorf("ghost-stack/vault: unmount: %w", err)
	}

	// Close the LUKS device.
	dmName := fmt.Sprintf("ghost-dept-%d", deptID)
	closeCmd := exec.Command("cryptsetup", "close", dmName)
	if err := closeCmd.Run(); err != nil {
		return fmt.Errorf("ghost-stack/vault: LUKS close: %w", err)
	}

	// Wipe LUKS key from host memory via HostKeyStore.
	kv.hostKeys.WipeKey(deptID)

	db.Running = false
	return nil
}

// StartCredentialRotationLoop runs a background goroutine that rotates
// all database credentials every 24 hours.
func (kv *KeyVault) StartCredentialRotationLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(CredentialRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			kv.rotateAllCredentials()
		}
	}
}

// rotateAllCredentials rotates credentials for all active databases.
func (kv *KeyVault) rotateAllCredentials() {
	kv.mu.RLock()
	var deptIDs []int
	for id, db := range kv.databases {
		if db.Running {
			deptIDs = append(deptIDs, id)
		}
	}
	kv.mu.RUnlock()

	for _, id := range deptIDs {
		if _, err := kv.RotateCredentials(id); err != nil {
			fmt.Fprintf(os.Stderr, "ghost-stack/vault: credential rotation failed for dept %d: %v\n", id, err)
		}
	}
}

// --- Internal helper functions ---

// generateCredentials creates new database credentials.
func (kv *KeyVault) generateCredentials(deptID int, deptName string, dbType DatabaseType) (*DatabaseCredentials, error) {
	// Derive password from master key + dept-specific entropy.
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write(kv.masterKey[:])
	h.Write([]byte(fmt.Sprintf("cred:%d:%d", deptID, time.Now().UnixNano())))
	h.Write(entropy)
	password := hex.EncodeToString(h.Sum(nil))

	now := time.Now()

	creds := &DatabaseCredentials{
		Username:  fmt.Sprintf("ghost_dept_%d", deptID),
		Password:  password,
		Database:  fmt.Sprintf("ghost_%s", deptName),
		Host:      "localhost",
		CreatedAt: now,
		ExpiresAt: now.Add(CredentialRotationInterval),
	}

	switch dbType {
	case DBTypeSQLite:
		creds.Port = 0 // No network port for SQLite.
	case DBTypePostgreSQL:
		creds.Port = 5432 + deptID // Offset port per department.
	}

	return creds, nil
}

// encryptKey encrypts a key using AES-256-GCM with the vault master key.
func (kv *KeyVault) encryptKey(plainKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(kv.masterKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
