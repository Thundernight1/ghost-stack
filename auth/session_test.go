package auth

import (
	"testing"
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
		{"alice@ghoststack.internal", true},
		{"admin.dev@ghoststack.internal", true},
		{"bob@gmail.com", false},
		{"eve@ghoststack.external", false},
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

	err := sm.RegisterDevice("alice@ghoststack.internal", attestation)
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}

	if !sm.registeredEmails["alice@ghoststack.internal"] {
		t.Error("email not marked as registered")
	}
	if sm.deviceToUser["hw-uuid-1234"] != "alice@ghoststack.internal" {
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

	email := "bob@ghoststack.internal"
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
