package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
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

func TestAuthenticationFlow(t *testing.T) {
	sm, _ := NewSessionManager()

	email := "bob@xio.cybersurhub.com"
	fingerprint := "hw-uuid-bob-999"

	// 1. Register (real P-256 key + COSE public key).
	priv, credID, sender := registerCeremonyDevice(t, sm, email, fingerprint)

	// 2. Real WebAuthn ceremony → OTP delivered via sender.
	otpCode := ceremonyOTP(t, sm, sender, priv, credID, fingerprint, 1)

	// 3. Complete Auth
	token, err := sm.CompleteAuthentication(email, otpCode, fingerprint, 10, "MANAGER")
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

// helper creates a SessionManager with a registered device, runs the real
// WebAuthn ceremony, and returns the manager plus the OTP code as delivered
// through the sender. This avoids duplicating setup logic across tests.
func setupAuthFlow(t *testing.T) (*SessionManager, string, string, string) {
	t.Helper()
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}

	email := "operator@xio.cybersurhub.com"
	fp := "hw-uuid-test-0001"

	priv, credID, sender := registerCeremonyDevice(t, sm, email, fp)
	otpCode := ceremonyOTP(t, sm, sender, priv, credID, fp, 1)
	return sm, otpCode, email, fp
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
	sm, otpCode, email, fp := setupAuthFlow(t)

	// Manually expire the OTP.
	sm.mu.Lock()
	sm.pendingOTPs[email].ExpiresAt = time.Now().Add(-1 * time.Minute)
	sm.mu.Unlock()

	_, err := sm.CompleteAuthentication(email, otpCode, fp, 1, "ANALYST")
	if err == nil {
		t.Fatal("expected error for expired OTP")
	}
	if !strings.Contains(err.Error(), "OTP expired") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestCompleteAuthentication_ExternalEmail(t *testing.T) {
	sm, otpCode, _, fp := setupAuthFlow(t)

	_, err := sm.CompleteAuthentication("evil@attacker.com", otpCode, fp, 1, "ANALYST")
	if err == nil {
		t.Fatal("expected error for external email")
	}
	if !strings.Contains(err.Error(), CompanyEmailDomain) {
		t.Errorf("error should reference company domain, got: %v", err)
	}
}

func TestValidateSession_WrongDevice(t *testing.T) {
	sm, otpCode, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, otpCode, fp, 1, "ANALYST")
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
	sm, otpCode, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, otpCode, fp, 1, "ANALYST")
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

func TestValidateSession_TamperedPayload(t *testing.T) {
	sm, _ := NewSessionManager()
	priv, credID, sender := registerCeremonyDevice(t, sm, "dave@xio.cybersurhub.com", "fp-payload")
	code := ceremonyOTP(t, sm, sender, priv, credID, "fp-payload", 1)
	token, err := sm.CompleteAuthentication("dave@xio.cybersurhub.com", code, "fp-payload", 3, "ANALYST")
	if err != nil {
		t.Fatal(err)
	}

	// Attacker model: envelope privilege fields escalated and the HMAC
	// recomputed (HMAC-key compromise, or a token-creation bug that sealed
	// the wrong envelope). The encrypted payload still says ANALYST — the
	// payload check must catch the envelope/payload mismatch.
	tampered := *token
	tampered.Tier = "ADMIN"
	tampered.DeptID = 99
	tampered.HMAC = sm.computeTokenHMAC(&tampered)
	sm.activeSessions["tampered-payload"] = &tampered

	if _, err := sm.ValidateSession("tampered-payload", "fp-payload"); err == nil {
		t.Fatal("payload/envelope mismatch must be rejected")
	} else if !strings.Contains(err.Error(), "payload") {
		t.Errorf("error should mention payload, got: %v", err)
	}

	// Untouched token still validates.
	if _, err := sm.ValidateSession(token.TokenID, "fp-payload"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	sm, otpCode, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, otpCode, fp, 1, "ANALYST")
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
	sm, otpCode, email, fp := setupAuthFlow(t)

	oldToken, err := sm.CompleteAuthentication(email, otpCode, fp, 5, "MANAGER")
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
	sm, otpCode, email, fp := setupAuthFlow(t)

	token, err := sm.CompleteAuthentication(email, otpCode, fp, 1, "ANALYST")
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

	priv, credID, sender := registerCeremonyDevice(t, sm, email, fp)

	// Create 3 sessions manually by doing full auth flow 3 times.
	for i := 0; i < 3; i++ {
		otpCode := ceremonyOTP(t, sm, sender, priv, credID, fp, uint32(i+1))
		_, err = sm.CompleteAuthentication(email, otpCode, fp, i+1, "ANALYST")
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

	priv, credID, sender := registerCeremonyDevice(t, sm, email, fp)

	// Create 4 sessions.
	var tokenIDs []string
	for i := 0; i < 4; i++ {
		otpCode := ceremonyOTP(t, sm, sender, priv, credID, fp, uint32(i+1))
		token, err := sm.CompleteAuthentication(email, otpCode, fp, 1, "ANALYST")
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
		email  string
		fp     string
		priv   *ecdsa.PrivateKey
		credID []byte
	}
	devices := make([]deviceInfo, goroutines)

	for i := 0; i < goroutines; i++ {
		email := "user" + itoa(i) + "@xio.cybersurhub.com"
		fp := "hw-uuid-concurrent-" + itoa(i)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		credID := []byte("cred-" + itoa(i))
		att := &FIDO2Attestation{
			CredentialID:      credID,
			PublicKey:         marshalCOSEKey(t, &priv.PublicKey),
			AAGUID:            [16]byte{byte(i + 1)},
			DeviceFingerprint: fp,
		}
		if err := sm.RegisterDevice(email, att); err != nil {
			t.Fatalf("RegisterDevice[%d]: %v", i, err)
		}
		devices[i] = deviceInfo{email: email, fp: fp, priv: priv, credID: credID}
	}
	sm.ConfigureWebAuthn(ceremonyRPID, ceremonyOrigin)
	router := &routeSender{}
	sm.SetOTPSender(router)

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d := devices[idx]

			// Real WebAuthn ceremony per goroutine.
			chal, err := sm.BeginWebAuthnAuth(d.fp)
			if err != nil {
				errCh <- err
				return
			}
			assertion, err := buildTestAssertion(d.priv, d.credID, chal, 1)
			if err != nil {
				errCh <- err
				return
			}
			otpChal, err := sm.CompleteWebAuthnAuth(d.fp, assertion)
			if err != nil {
				errCh <- err
				return
			}
			if otpChal.Code != "" {
				errCh <- fmt.Errorf("OTP code leaked to API caller")
				return
			}
			code := router.lastCode(d.email)
			if code == "" {
				errCh <- fmt.Errorf("no OTP delivered for %s", d.email)
				return
			}

			token, err := sm.CompleteAuthentication(d.email, code, d.fp, idx%10, "ANALYST")
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

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	sm.ConfigureWebAuthn(ceremonyRPID, ceremonyOrigin)
	sender := &recordingSender{}
	sm.SetOTPSender(sender)
	credID := []byte("cred-bench")
	att := &FIDO2Attestation{
		CredentialID:      credID,
		PublicKey:         coseP256PublicKey(&priv.PublicKey),
		AAGUID:            [16]byte{0xFF},
		DeviceFingerprint: fp,
	}
	if err := sm.RegisterDevice(email, att); err != nil {
		b.Fatal(err)
	}

	chal, err := sm.BeginWebAuthnAuth(fp)
	if err != nil {
		b.Fatal(err)
	}
	assertion, err := buildTestAssertion(priv, credID, chal, 1)
	if err != nil {
		b.Fatal(err)
	}
	otpChal, err := sm.CompleteWebAuthnAuth(fp, assertion)
	if err != nil {
		b.Fatal(err)
	}
	if otpChal.Code != "" {
		b.Fatal("OTP code leaked to API caller")
	}
	code := sender.code[len(sender.code)-1]
	token, err := sm.CompleteAuthentication(email, code, fp, 1, "ANALYST")
	if err != nil {
		b.Fatal(err)
	}

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
