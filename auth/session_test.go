package auth

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewSessionManager(t *testing.T) {
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatalf("NewSessionManager error: %v", err)
	}
	if sm == nil {
		t.Fatal("expected non-nil SessionManager")
	}
	
	// Verify keys are generated
	zeroKey := [32]byte{}
	if sm.masterKey == zeroKey {
		t.Error("masterKey was not generated")
	}
	if sm.hmacKey == zeroKey {
		t.Error("hmacKey was not generated")
	}
}

func TestIsCompanyEmail(t *testing.T) {
	sm, _ := NewSessionManager()

	tests := []struct {
		email string
		want  bool
	}{
		{"alice@xio.cybersurhub.com", true},
		{"admin.dev@xio.cybersurhub.com", true},
		{"bob@gmail.com", false},
		{"eve@xio.cybersurhub.external", false},
		{"invalid-email", false},
	}

	for _, tt := range tests {
		got := sm.isCompanyEmail(tt.email)
		if got != tt.want {
			t.Errorf("isCompanyEmail(%q) = %v, want %v", tt.email, got, tt.want)
		}
	}
}

func TestRegisterDevice_Success(t *testing.T) {
	sm, _ := NewSessionManager()

	attestation := &FIDO2Attestation{
		DeviceFingerprint: "hw-uuid-1234",
	}

	err := sm.RegisterDevice("alice@xio.cybersurhub.com", attestation)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	if !sm.registeredEmails["alice@xio.cybersurhub.com"] {
		t.Error("email not marked as registered")
	}
	if sm.deviceToUser["hw-uuid-1234"] != "alice@xio.cybersurhub.com" {
		t.Error("device not mapped to user")
	}
}

func TestRegisterDevice_InvalidEmail(t *testing.T) {
	sm, _ := NewSessionManager()

	attestation := &FIDO2Attestation{
		DeviceFingerprint: "hw-uuid-1234",
	}

	err := sm.RegisterDevice("eve@attacker.com", attestation)
	if err == nil {
		t.Error("expected error for external email domain")
	}
}

func TestGenerateOTP(t *testing.T) {
	otp, err := generateOTP()
	if err != nil {
		t.Fatal(err)
	}
	if len(otp) != 6 {
		t.Errorf("expected 6-digit OTP, got %q (len %d)", otp, len(otp))
	}
}

func TestVerifyFIDO2Attestation(t *testing.T) {
	sm, _ := NewSessionManager()

	valid := &FIDO2Attestation{
		CredentialID:      []byte("cred"),
		PublicKey:         []byte("pub"),
		DeviceFingerprint: "fp",
		AAGUID:            [16]byte{1}, // Not all zeros
	}

	if err := sm.verifyFIDO2Attestation(valid); err != nil {
		t.Errorf("expected valid attestation to pass, got: %v", err)
	}

	invalidAAGUID := &FIDO2Attestation{
		CredentialID:      []byte("cred"),
		PublicKey:         []byte("pub"),
		DeviceFingerprint: "fp",
		AAGUID:            [16]byte{}, // All zeros
	}
	if err := sm.verifyFIDO2Attestation(invalidAAGUID); err == nil {
		t.Error("expected error for all-zero AAGUID")
	}
}

func TestAuthenticationFlow(t *testing.T) {
	sm, _ := NewSessionManager()

	email := "bob@xio.cybersurhub.com"
	fingerprint := "hw-uuid-bob-999"

	// 1. Register
	att := &FIDO2Attestation{
		CredentialID:      []byte("cred1"),
		PublicKey:         []byte("pub1"),
		AAGUID:            [16]byte{1},
		DeviceFingerprint: fingerprint,
	}
	_ = sm.RegisterDevice(email, att)

	// 2. Start Auth
	challenge, err := sm.StartAuthentication(fingerprint)
	if err != nil {
		t.Fatalf("StartAuthentication failed: %v", err)
	}
	if challenge.Email != email {
		t.Errorf("challenge email = %q, want %q", challenge.Email, email)
	}

	// 3. Complete Auth
	token, err := sm.CompleteAuthentication(email, challenge.Code, fingerprint, 10, "MANAGER")
	if err != nil {
		t.Fatalf("CompleteAuthentication failed: %v", err)
	}
	if token.UserEmail != email {
		t.Errorf("token email = %q, want %q", token.UserEmail, email)
	}

	// 4. Validate Session
	validToken, err := sm.ValidateSession(token.TokenID, fingerprint)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}
	if validToken.TokenID != token.TokenID {
		t.Errorf("validated token mismatch")
	}

	// 5. Revoke Session
	sm.RevokeSession(token.TokenID)
	_, err = sm.ValidateSession(token.TokenID, fingerprint)
	if err == nil {
		t.Error("expected error after revocation")
	}
}

func TestTokenEncryptionCycle(t *testing.T) {
	sm, _ := NewSessionManager()
	
	plaintext := []byte("secret payload")
	
	encrypted, err := sm.encryptAES256GCM(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	
	decrypted, err := sm.decryptAES256GCM(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted %q != original %q", decrypted, plaintext)
	}
}

// ═══════════════════════════════════════════════════════════
// Extended Security Tests
// ═══════════════════════════════════════════════════════════

// helper creates a SessionManager with a registered device and returns it along
// with the OTP challenge. This avoids duplicating setup logic across tests.
func setupAuthFlow(t *testing.T) (*SessionManager, *OTPChallenge, string, string) {
	t.Helper()
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	email := "operator@xio.cybersurhub.com"
	fp := "hw-uuid-test-0001"

	att := &FIDO2Attestation{
		CredentialID:      []byte("cred-test"),
		PublicKey:         []byte("pub-test"),
		AAGUID:            [16]byte{0xDE, 0xAD},
		DeviceFingerprint: fp,
	}
	if err := sm.RegisterDevice(email, att); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	challenge, err := sm.StartAuthentication(fp)
	if err != nil {
		t.Fatalf("StartAuthentication: %v", err)
	}
	return sm, challenge, email, fp
}

func TestCompleteAuthentication_WrongOTP(t *testing.T) {
	sm, _, email, fp := setupAuthFlow(t)

	_, err := sm.CompleteAuthentication(email, "000000", fp, 1, "ANALYST")
	if err == nil {
		t.Fatal("expected error for wrong OTP")
	}
	if !strings.Contains(err.Error(), "invalid OTP") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestCompleteAuthentication_ExpiredOTP(t *testing.T) {
	sm, challenge, email, fp := setupAuthFlow(t)

	// Manually expire the OTP.
	sm.mu.Lock()
	sm.pendingOTPs[email].ExpiresAt = time.Now().Add(-1 * time.Minute)
	sm.mu.Unlock()

	_, err := sm.CompleteAuthentication(email, challenge.Code, fp, 1, "ANALYST")
	if err == nil {
		t.Fatal("expected error for expired OTP")
	}
	if !strings.Contains(err.Error(), "OTP expired") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestCompleteAuthentication_ExternalEmail(t *testing.T) {
	sm, challenge, _, fp := setupAuthFlow(t)

	_, err := sm.CompleteAuthentication("evil@attacker.com", challenge.Code, fp, 1, "ANALYST")
	if err == nil {
		t.Fatal("expected error for external email")
	}
	if !strings.Contains(err.Error(), CompanyEmailDomain) {
		t.Errorf("error should reference company domain, got: %v", err)
	}
}

func TestValidateSession_WrongDevice(t *testing.T) {
	sm, challenge, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, challenge.Code, fp, 1, "ANALYST")
	if err != nil {
		t.Fatalf("CompleteAuthentication: %v", err)
	}

	_, err = sm.ValidateSession(token.TokenID, "hw-uuid-DIFFERENT-DEVICE")
	if err == nil {
		t.Fatal("expected HARD BLOCK for wrong device")
	}
	if !strings.Contains(err.Error(), "HARD BLOCK") {
		t.Errorf("error should contain HARD BLOCK, got: %v", err)
	}
}

func TestValidateSession_TamperedHMAC(t *testing.T) {
	sm, challenge, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, challenge.Code, fp, 1, "ANALYST")
	if err != nil {
		t.Fatalf("CompleteAuthentication: %v", err)
	}

	// Tamper with the HMAC stored in the active session.
	sm.mu.Lock()
	sm.activeSessions[token.TokenID].HMAC = "deadbeef0000000000000000000000000000000000000000000000000000dead"
	sm.mu.Unlock()

	_, err = sm.ValidateSession(token.TokenID, fp)
	if err == nil {
		t.Fatal("expected integrity check failure")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Errorf("error should mention integrity, got: %v", err)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	sm, challenge, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, challenge.Code, fp, 1, "ANALYST")
	if err != nil {
		t.Fatalf("CompleteAuthentication: %v", err)
	}

	// Manually expire the session.
	sm.mu.Lock()
	sm.activeSessions[token.TokenID].ExpiresAt = time.Now().Add(-1 * time.Hour)
	sm.mu.Unlock()

	_, err = sm.ValidateSession(token.TokenID, fp)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expiry, got: %v", err)
	}
}

func TestRotateToken_Success(t *testing.T) {
	sm, challenge, email, fp := setupAuthFlow(t)

	oldToken, err := sm.CompleteAuthentication(email, challenge.Code, fp, 5, "MANAGER")
	if err != nil {
		t.Fatalf("CompleteAuthentication: %v", err)
	}
	oldID := oldToken.TokenID

	newToken, err := sm.RotateToken(oldID)
	if err != nil {
		t.Fatalf("RotateToken: %v", err)
	}

	if newToken.TokenID == oldID {
		t.Error("rotated token should have a new ID")
	}
	if newToken.UserEmail != email {
		t.Error("rotated token should keep the same email")
	}
	if newToken.FIDO2DeviceFingerprint != fp {
		t.Error("rotated token should keep the same device fingerprint")
	}
	if newToken.DeptID != 5 {
		t.Errorf("rotated token DeptID = %d, want 5", newToken.DeptID)
	}

	// Old token must be revoked.
	_, err = sm.ValidateSession(oldID, fp)
	if err == nil {
		t.Error("old token should be revoked after rotation")
	}

	// New token must be valid.
	_, err = sm.ValidateSession(newToken.TokenID, fp)
	if err != nil {
		t.Errorf("new token should be valid: %v", err)
	}
}

func TestRotateToken_Expired(t *testing.T) {
	sm, challenge, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, challenge.Code, fp, 1, "ANALYST")
	if err != nil {
		t.Fatalf("CompleteAuthentication: %v", err)
	}

	// Expire the token.
	sm.mu.Lock()
	sm.activeSessions[token.TokenID].ExpiresAt = time.Now().Add(-1 * time.Hour)
	sm.mu.Unlock()

	_, err = sm.RotateToken(token.TokenID)
	if err == nil {
		t.Fatal("expected error rotating expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expiry, got: %v", err)
	}

	// Old token should be deleted.
	if sm.ActiveSessionCount() != 0 {
		t.Error("expired token should have been deleted during rotation attempt")
	}
}

func TestRevokeAllForDevice(t *testing.T) {
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	email := "multi@xio.cybersurhub.com"
	fp := "hw-uuid-multi-device"

	att := &FIDO2Attestation{
		CredentialID:      []byte("cred-multi"),
		PublicKey:         []byte("pub-multi"),
		AAGUID:            [16]byte{0x01},
		DeviceFingerprint: fp,
	}
	if err := sm.RegisterDevice(email, att); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	// Create 3 sessions manually by doing full auth flow 3 times.
	for i := 0; i < 3; i++ {
		challenge, err := sm.StartAuthentication(fp)
		if err != nil {
			t.Fatalf("StartAuthentication[%d]: %v", i, err)
		}
		_, err = sm.CompleteAuthentication(email, challenge.Code, fp, i+1, "ANALYST")
		if err != nil {
			t.Fatalf("CompleteAuthentication[%d]: %v", i, err)
		}
	}

	if sm.ActiveSessionCount() != 3 {
		t.Fatalf("expected 3 sessions, got %d", sm.ActiveSessionCount())
	}

	revoked := sm.RevokeAllForDevice(fp)
	if revoked != 3 {
		t.Errorf("revoked = %d, want 3", revoked)
	}
	if sm.ActiveSessionCount() != 0 {
		t.Errorf("active sessions = %d after RevokeAllForDevice, want 0", sm.ActiveSessionCount())
	}
}

func TestCleanupExpiredSessions(t *testing.T) {
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	email := "cleanup@xio.cybersurhub.com"
	fp := "hw-uuid-cleanup"

	att := &FIDO2Attestation{
		CredentialID:      []byte("cred-clean"),
		PublicKey:         []byte("pub-clean"),
		AAGUID:            [16]byte{0x02},
		DeviceFingerprint: fp,
	}
	if err := sm.RegisterDevice(email, att); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	// Create 4 sessions.
	var tokenIDs []string
	for i := 0; i < 4; i++ {
		challenge, err := sm.StartAuthentication(fp)
		if err != nil {
			t.Fatalf("StartAuthentication[%d]: %v", i, err)
		}
		token, err := sm.CompleteAuthentication(email, challenge.Code, fp, 1, "ANALYST")
		if err != nil {
			t.Fatalf("CompleteAuthentication[%d]: %v", i, err)
		}
		tokenIDs = append(tokenIDs, token.TokenID)
	}

	// Expire 3 out of 4.
	sm.mu.Lock()
	for i := 0; i < 3; i++ {
		sm.activeSessions[tokenIDs[i]].ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
	sm.mu.Unlock()

	cleaned := sm.CleanupExpiredSessions()
	if cleaned != 3 {
		t.Errorf("cleaned = %d, want 3", cleaned)
	}
	if sm.ActiveSessionCount() != 1 {
		t.Errorf("active sessions = %d, want 1", sm.ActiveSessionCount())
	}
}

func TestConcurrentSessions(t *testing.T) {
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	const goroutines = 50

	// Pre-register devices for each goroutine.
	type deviceInfo struct {
		email string
		fp    string
	}
	devices := make([]deviceInfo, goroutines)

	for i := 0; i < goroutines; i++ {
		email := "user" + itoa(i) + "@xio.cybersurhub.com"
		fp := "hw-uuid-concurrent-" + itoa(i)
		att := &FIDO2Attestation{
			CredentialID:      []byte("cred-" + itoa(i)),
			PublicKey:         []byte("pub-" + itoa(i)),
			AAGUID:            [16]byte{byte(i + 1)},
			DeviceFingerprint: fp,
		}
		if err := sm.RegisterDevice(email, att); err != nil {
			t.Fatalf("RegisterDevice[%d]: %v", i, err)
		}
		devices[i] = deviceInfo{email: email, fp: fp}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d := devices[idx]

			challenge, err := sm.StartAuthentication(d.fp)
			if err != nil {
				errCh <- err
				return
			}

			token, err := sm.CompleteAuthentication(d.email, challenge.Code, d.fp, idx%10, "ANALYST")
			if err != nil {
				errCh <- err
				return
			}

			_, err = sm.ValidateSession(token.TokenID, d.fp)
			if err != nil {
				errCh <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent error: %v", err)
	}

	if count := sm.ActiveSessionCount(); count != goroutines {
		t.Errorf("active sessions = %d, want %d", count, goroutines)
	}
}

// ═══════════════════════════════════════════════════════════
// Benchmarks
// ═══════════════════════════════════════════════════════════

func BenchmarkTokenCreation(b *testing.B) {
	sm, err := NewSessionManager()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm.createSessionToken("bench@xio.cybersurhub.com", "fp-bench", 1, "ANALYST")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenValidation(b *testing.B) {
	sm, err := NewSessionManager()
	if err != nil {
		b.Fatal(err)
	}

	email := "bench@xio.cybersurhub.com"
	fp := "hw-uuid-bench-valid"

	att := &FIDO2Attestation{
		CredentialID:      []byte("cred-bench"),
		PublicKey:         []byte("pub-bench"),
		AAGUID:            [16]byte{0xFF},
		DeviceFingerprint: fp,
	}
	_ = sm.RegisterDevice(email, att)

	challenge, _ := sm.StartAuthentication(fp)
	token, _ := sm.CompleteAuthentication(email, challenge.Code, fp, 1, "ANALYST")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm.ValidateSession(token.TokenID, fp)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// itoa converts an int to its string representation (avoids strconv import).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		n = -n
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
