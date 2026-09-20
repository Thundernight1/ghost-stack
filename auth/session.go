// Package auth implements rotating session tokens with FIDO2 hardware
// binding and company email OTP for GHOST-STACK CORE.
//
// Authentication flow:
//  1. FIDO2 WebAuthn challenge/response (hardware token required)
//  2. Company email OTP verification (company domain only)
//  3. AES-256-GCM encrypted session token issued with 8-hour TTL
//  4. Token cryptographically bound to FIDO2 attestation (device fingerprint)
//  5. Tokens rotate automatically within TTL window
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CompanyEmailDomain is the only allowed email domain for authentication.
// External email providers are blocked at network namespace level.
const CompanyEmailDomain = "xio.cybersurhub.com"

// SessionTTL is the maximum lifetime of a session token.
const SessionTTL = 8 * time.Hour

// TokenRotationInterval is how often tokens are automatically rotated.
const TokenRotationInterval = 1 * time.Hour

// FIDO2Attestation represents the attestation data from a FIDO2 hardware token.
// In production, this comes from the WebAuthn registration/authentication flow.
type FIDO2Attestation struct {
	// CredentialID is the unique credential identifier from the FIDO2 device.
	CredentialID []byte
	// PublicKey is the public key registered during FIDO2 enrollment.
	PublicKey []byte
	// AAGUID is the Authenticator Attestation GUID — identifies the device model.
	AAGUID [16]byte
	// DeviceFingerprint is the hardware fingerprint reader UUID from attestation.
	DeviceFingerprint string
	// AttestationFormat (e.g., "packed", "tpm", "android-key").
	AttestationFormat string
	// SignCount is the signature counter for clone detection.
	SignCount uint32
}

// OTPChallenge holds a pending OTP challenge for email verification.
type OTPChallenge struct {
	Email     string
	Code      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Verified  bool
}

// SessionToken is an AES-256-GCM encrypted, FIDO2-bound session token.
type SessionToken struct {
	// TokenID is the unique token identifier.
	TokenID string
	// DeptID is the department this session is for.
	DeptID int
	// UserEmail is the authenticated user's company email.
	UserEmail string
	// Tier is the user's hierarchy tier.
	Tier string
	// FIDO2DeviceFingerprint binds the token to the specific hardware.
	FIDO2DeviceFingerprint string
	// IssuedAt is when the token was created.
	IssuedAt time.Time
	// ExpiresAt is when the token expires (8 hours from issuance).
	ExpiresAt time.Time
	// RotatedAt tracks when the token was last rotated.
	RotatedAt time.Time
	// EncryptedPayload is the AES-256-GCM encrypted token body.
	EncryptedPayload string
	// HMAC is the HMAC-SHA256 of the entire token for integrity verification.
	HMAC string
}

// SessionManager handles session lifecycle including creation, rotation,
// validation, and revocation.
type SessionManager struct {
	mu sync.RWMutex

	// masterKey is the AES-256 master key for token encryption.
	masterKey [32]byte
	// hmacKey is used for token integrity verification.
	hmacKey [32]byte

	// activeSessions maps TokenID to SessionToken.
	activeSessions map[string]*SessionToken
	// pendingOTPs maps email to OTPChallenge.
	pendingOTPs map[string]*OTPChallenge
	// registeredDevices maps DeviceFingerprint to FIDO2Attestation.
	registeredDevices map[string]*FIDO2Attestation
	// registeredEmails is the set of company-registered emails.
	registeredEmails map[string]bool
	// deviceToUser maps DeviceFingerprint to UserEmail for device binding.
	deviceToUser map[string]string

	// otpSender is the delivery channel for OTP codes (see otp.go).
	otpSender OTPSender
	// pendingWebAuthn maps DeviceFingerprint to a pending login challenge.
	pendingWebAuthn map[string]*webAuthnChallenge
	// webAuthnRPID / webAuthnOrigin configure the Relying Party identity.
	webAuthnRPID   string
	webAuthnOrigin string
}

// NewSessionManager creates a new session manager with random encryption keys.
func NewSessionManager() (*SessionManager, error) {
	sm := &SessionManager{
		activeSessions:    make(map[string]*SessionToken),
		pendingOTPs:       make(map[string]*OTPChallenge),
		registeredDevices: make(map[string]*FIDO2Attestation),
		registeredEmails:  make(map[string]bool),
		deviceToUser:      make(map[string]string),
	}

	// Generate random AES-256 master key.
	if _, err := rand.Read(sm.masterKey[:]); err != nil {
		return nil, fmt.Errorf("ghost-stack/auth: master key generation failed: %w", err)
	}
	// Generate random HMAC key.
	if _, err := rand.Read(sm.hmacKey[:]); err != nil {
		return nil, fmt.Errorf("ghost-stack/auth: HMAC key generation failed: %w", err)
	}

	return sm, nil
}

// RegisterDevice registers a FIDO2 device for a user.
// Only company-registered devices can authenticate.
func (sm *SessionManager) RegisterDevice(email string, attestation *FIDO2Attestation) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isCompanyEmail(email) {
		return fmt.Errorf("ghost-stack/auth: only company email domain (%s) allowed", CompanyEmailDomain)
	}

	if attestation.DeviceFingerprint == "" {
		return fmt.Errorf("ghost-stack/auth: device fingerprint is required")
	}

	sm.registeredDevices[attestation.DeviceFingerprint] = attestation
	sm.registeredEmails[email] = true
	sm.deviceToUser[attestation.DeviceFingerprint] = email
	return nil
}

// NOTE: the old StartAuthentication(deviceFingerprint) entry point was removed.
// It issued an OTP after only a structural attestation check, without any
// hardware proof — anyone who knew a device fingerprint could trigger an OTP.
// Logins must go through the real cryptographic ceremony:
// BeginWebAuthnAuth + CompleteWebAuthnAuth (see webauthn.go).

// CompleteAuthentication verifies the OTP and issues an encrypted session token.
// The token is cryptographically bound to the FIDO2 device fingerprint.
func (sm *SessionManager) CompleteAuthentication(email, otpCode, deviceFingerprint string, deptID int, tier string) (*SessionToken, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Verify company email domain.
	if !sm.isCompanyEmail(email) {
		return nil, fmt.Errorf("ghost-stack/auth: only company email domain (%s) allowed", CompanyEmailDomain)
	}

	// Verify OTP.
	challenge, exists := sm.pendingOTPs[email]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/auth: no pending OTP for %s", email)
	}

	if time.Now().After(challenge.ExpiresAt) {
		delete(sm.pendingOTPs, email)
		return nil, fmt.Errorf("ghost-stack/auth: OTP expired")
	}

	// Constant-time comparison — no timing oracle for guessing the code.
	if subtle.ConstantTimeCompare([]byte(challenge.Code), []byte(otpCode)) != 1 {
		return nil, fmt.Errorf("ghost-stack/auth: invalid OTP")
	}

	// Verify device is still registered and matches.
	if _, exists := sm.registeredDevices[deviceFingerprint]; !exists {
		return nil, fmt.Errorf("ghost-stack/auth: HARD BLOCK — non-registered device")
	}

	registeredEmail := sm.deviceToUser[deviceFingerprint]
	if registeredEmail != email {
		return nil, fmt.Errorf("ghost-stack/auth: device not bound to this user")
	}

	// Mark OTP as verified and clean up.
	challenge.Verified = true
	delete(sm.pendingOTPs, email)

	// Generate session token.
	token, err := sm.createSessionToken(email, deviceFingerprint, deptID, tier)
	if err != nil {
		return nil, err
	}

	sm.activeSessions[token.TokenID] = token
	return token, nil
}

// ValidateSession checks if a session token is valid and not expired.
// Also verifies FIDO2 device binding.
func (sm *SessionManager) ValidateSession(tokenID, deviceFingerprint string) (*SessionToken, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	token, exists := sm.activeSessions[tokenID]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/auth: session not found")
	}

	// Check expiration.
	if time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("ghost-stack/auth: session expired")
	}

	// Verify FIDO2 device binding — token is cryptographically bound to device.
	if token.FIDO2DeviceFingerprint != deviceFingerprint {
		return nil, fmt.Errorf("ghost-stack/auth: HARD BLOCK — session bound to different device")
	}

	// Verify token integrity via HMAC.
	expectedHMAC := sm.computeTokenHMAC(token)
	if !hmac.Equal([]byte(token.HMAC), []byte(expectedHMAC)) {
		return nil, fmt.Errorf("ghost-stack/auth: token integrity check failed — possible tampering")
	}

	// Verify the encrypted payload matches the plaintext envelope. HMAC
	// alone cannot catch a token whose envelope fields were swapped
	// against a different valid encrypted payload.
	if err := sm.verifyTokenPayload(token); err != nil {
		return nil, err
	}

	return token, nil
}

// RotateToken creates a new session token, replacing the old one.
// The new token inherits the FIDO2 device binding.
func (sm *SessionManager) RotateToken(oldTokenID string) (*SessionToken, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	oldToken, exists := sm.activeSessions[oldTokenID]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/auth: session not found for rotation")
	}

	if time.Now().After(oldToken.ExpiresAt) {
		delete(sm.activeSessions, oldTokenID)
		return nil, fmt.Errorf("ghost-stack/auth: session expired, re-authentication required")
	}

	// Create new token with same bindings.
	newToken, err := sm.createSessionToken(
		oldToken.UserEmail,
		oldToken.FIDO2DeviceFingerprint,
		oldToken.DeptID,
		oldToken.Tier,
	)
	if err != nil {
		return nil, err
	}

	// Revoke old token.
	delete(sm.activeSessions, oldTokenID)
	// Install new token.
	sm.activeSessions[newToken.TokenID] = newToken

	return newToken, nil
}

// RevokeSession immediately invalidates a session token.
func (sm *SessionManager) RevokeSession(tokenID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.activeSessions, tokenID)
}

// RevokeAllForDevice revokes all sessions bound to a specific device.
// Used when a device is reported lost/stolen.
func (sm *SessionManager) RevokeAllForDevice(deviceFingerprint string) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	count := 0
	for id, token := range sm.activeSessions {
		if token.FIDO2DeviceFingerprint == deviceFingerprint {
			delete(sm.activeSessions, id)
			count++
		}
	}
	return count
}

// ActiveSessionCount returns the number of active sessions.
func (sm *SessionManager) ActiveSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.activeSessions)
}

// RegisteredDeviceCount returns the number of FIDO2 devices registered.
func (sm *SessionManager) RegisteredDeviceCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.registeredDevices)
}

// --- Internal methods ---

// sessionTokenPayload is the plaintext body sealed inside EncryptedPayload.
// It mirrors the security-relevant envelope fields of SessionToken so
// ValidateSession can prove the encrypted body and the envelope belong
// to the same token.
type sessionTokenPayload struct {
	TokenID           string `json:"token_id"`
	DeptID            int    `json:"dept_id"`
	UserEmail         string `json:"user_email"`
	Tier              string `json:"tier"`
	DeviceFingerprint string `json:"device_fingerprint"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
	Nonce             string `json:"nonce"`
}

// createSessionToken generates an AES-256-GCM encrypted session token
// bound to a FIDO2 device fingerprint.
func (sm *SessionManager) createSessionToken(email, deviceFingerprint string, deptID int, tier string) (*SessionToken, error) {
	// Generate unique token ID.
	tokenIDBytes := make([]byte, 16)
	if _, err := rand.Read(tokenIDBytes); err != nil {
		return nil, fmt.Errorf("token ID generation: %w", err)
	}
	tokenID := hex.EncodeToString(tokenIDBytes)

	now := time.Now()

	// Build token payload.
	payload := sessionTokenPayload{
		TokenID:           tokenID,
		DeptID:            deptID,
		UserEmail:         email,
		Tier:              tier,
		DeviceFingerprint: deviceFingerprint,
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Add(SessionTTL).Unix(),
	}

	// Add random nonce for uniqueness.
	nonceBytes := make([]byte, 12)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	payload.Nonce = hex.EncodeToString(nonceBytes)

	// Serialize payload.
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("payload marshal: %w", err)
	}

	// Encrypt with AES-256-GCM.
	encrypted, err := sm.encryptAES256GCM(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	token := &SessionToken{
		TokenID:                tokenID,
		DeptID:                 deptID,
		UserEmail:              email,
		Tier:                   tier,
		FIDO2DeviceFingerprint: deviceFingerprint,
		IssuedAt:               now,
		ExpiresAt:              now.Add(SessionTTL),
		RotatedAt:              now,
		EncryptedPayload:       base64.StdEncoding.EncodeToString(encrypted),
	}

	// Compute HMAC for integrity verification.
	token.HMAC = sm.computeTokenHMAC(token)

	return token, nil
}

// encryptAES256GCM encrypts plaintext using AES-256-GCM with a random nonce.
func (sm *SessionManager) encryptAES256GCM(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.masterKey[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Nonce is prepended to the ciphertext.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptAES256GCM decrypts AES-256-GCM ciphertext.
func (sm *SessionManager) decryptAES256GCM(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.masterKey[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// computeTokenHMAC computes HMAC-SHA256 of the token for integrity verification.
// It covers every security-relevant field — including the authorization
// fields DeptID/Tier and the rotation timestamp — so a token whose upper
// fields were swapped (e.g. Tier ANALYST → ADMIN) while keeping the same
// encrypted payload no longer verifies.
func (sm *SessionManager) computeTokenHMAC(token *SessionToken) string {
	h := hmac.New(sha256.New, sm.hmacKey[:])
	h.Write([]byte(token.TokenID))
	h.Write([]byte(token.UserEmail))
	h.Write([]byte(token.FIDO2DeviceFingerprint))
	h.Write([]byte(token.Tier))
	h.Write([]byte(token.EncryptedPayload))

	// Include authorization and lifecycle fields.
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(token.DeptID))
	h.Write(buf)
	binary.BigEndian.PutUint64(buf, uint64(token.IssuedAt.Unix()))
	h.Write(buf)
	binary.BigEndian.PutUint64(buf, uint64(token.ExpiresAt.Unix()))
	h.Write(buf)
	binary.BigEndian.PutUint64(buf, uint64(token.RotatedAt.Unix()))
	h.Write(buf)

	return hex.EncodeToString(h.Sum(nil))
}

// verifyTokenPayload decrypts the token's encrypted payload and checks that
// every security-relevant field matches the plaintext envelope. This closes
// the gap where validation checked only the HMAC: a token whose envelope
// fields were swapped against a different (valid) encrypted payload — or a
// payload that was re-encrypted under a leaked master key — is rejected.
func (sm *SessionManager) verifyTokenPayload(token *SessionToken) error {
	raw, err := base64.StdEncoding.DecodeString(token.EncryptedPayload)
	if err != nil {
		return fmt.Errorf("ghost-stack/auth: token payload decode failed: %w", err)
	}
	plaintext, err := sm.decryptAES256GCM(raw)
	if err != nil {
		return fmt.Errorf("ghost-stack/auth: token payload decrypt failed — possible tampering: %w", err)
	}
	var p sessionTokenPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return fmt.Errorf("ghost-stack/auth: token payload corrupt: %w", err)
	}
	if p.TokenID != token.TokenID ||
		p.DeptID != token.DeptID ||
		p.UserEmail != token.UserEmail ||
		p.Tier != token.Tier ||
		p.DeviceFingerprint != token.FIDO2DeviceFingerprint ||
		p.IssuedAt != token.IssuedAt.Unix() ||
		p.ExpiresAt != token.ExpiresAt.Unix() {
		return fmt.Errorf("ghost-stack/auth: token payload does not match envelope — possible tampering")
	}
	return nil
}

// isCompanyEmail checks if the email belongs to the company domain.
func (sm *SessionManager) isCompanyEmail(email string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[1] == CompanyEmailDomain
}

// generateOTP creates a 6-digit cryptographically random OTP.
func generateOTP() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	num := binary.BigEndian.Uint32(b) % 1000000
	return fmt.Sprintf("%06d", num), nil
}

// StartTokenRotationLoop runs a background goroutine that automatically
// rotates tokens approaching their rotation interval.
func (sm *SessionManager) StartTokenRotationLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(TokenRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			sm.rotateExpiringSessions()
		}
	}
}

// rotateExpiringSessions rotates tokens that are within 1 hour of expiration.
func (sm *SessionManager) rotateExpiringSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	var toRotate []string

	for id, token := range sm.activeSessions {
		// Rotate if token has been active for more than the rotation interval.
		if now.Sub(token.RotatedAt) >= TokenRotationInterval {
			toRotate = append(toRotate, id)
		}
	}

	for _, oldID := range toRotate {
		oldToken := sm.activeSessions[oldID]

		newToken, err := sm.createSessionToken(
			oldToken.UserEmail,
			oldToken.FIDO2DeviceFingerprint,
			oldToken.DeptID,
			oldToken.Tier,
		)
		if err != nil {
			continue
		}

		delete(sm.activeSessions, oldID)
		sm.activeSessions[newToken.TokenID] = newToken
	}
}

// CleanupExpiredSessions removes all expired sessions.
func (sm *SessionManager) CleanupExpiredSessions() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	count := 0

	for id, token := range sm.activeSessions {
		if now.After(token.ExpiresAt) {
			delete(sm.activeSessions, id)
			count++
		}
	}

	return count
}
