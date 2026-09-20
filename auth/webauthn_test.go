package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

// recordingSender is an OTPSender stub that records deliveries.
type recordingSender struct {
	to   []string
	code []string
}

func (r *recordingSender) SendOTP(email, code string, expiresAt time.Time) error {
	r.to = append(r.to, email)
	r.code = append(r.code, code)
	return nil
}

// marshalCOSEKey encodes a P-256 public key as a COSE_Key (EC2/ES256).
func marshalCOSEKey(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	xp := make([]byte, 32)
	yp := make([]byte, 32)
	copy(xp[32-len(xb):], xb)
	copy(yp[32-len(yb):], yb)

	var out []byte
	out = append(out, 0xa5)       // map(5)
	out = append(out, 0x01, 0x02) // 1: 2 (kty EC2)
	out = append(out, 0x03, 0x26) // 3: -7 (alg ES256)
	out = append(out, 0x20, 0x01) // -1: 1 (crv P-256)
	out = append(out, 0x21, 0x58, 0x20)
	out = append(out, xp...) // -2: x
	out = append(out, 0x22, 0x58, 0x20)
	out = append(out, yp...) // -3: y
	return out
}

type testFixture struct {
	sm     *SessionManager
	priv   *ecdsa.PrivateKey
	fp     string
	email  string
	credID []byte
	sender *recordingSender
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatal(err)
	}
	sm.ConfigureWebAuthn("test.local", "https://test.local")
	sender := &recordingSender{}
	sm.SetOTPSender(sender)

	fp := "fp-webauthn-1"
	email := "bob@xio.cybersurhub.com"
	credID := []byte("credential-id-123")
	att := &FIDO2Attestation{
		CredentialID:      credID,
		PublicKey:         marshalCOSEKey(t, &priv.PublicKey),
		AAGUID:            [16]byte{9},
		DeviceFingerprint: fp,
	}
	if err := sm.RegisterDevice(email, att); err != nil {
		t.Fatal(err)
	}
	return &testFixture{sm: sm, priv: priv, fp: fp, email: email, credID: credID, sender: sender}
}

// buildAssertion crafts a valid assertion for the given challenge.
func (f *testFixture) buildAssertion(t *testing.T, challenge []byte, signCount uint32, origin string) *WebAuthnAssertion {
	t.Helper()
	clientData, _ := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    origin,
	})
	rpHash := sha256.Sum256([]byte("test.local"))
	authData := make([]byte, 37)
	copy(authData[:32], rpHash[:])
	authData[32] = 0x01 // UP flag
	binary.BigEndian.PutUint32(authData[33:37], signCount)

	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(authData, clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, f.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return &WebAuthnAssertion{
		CredentialID:      f.credID,
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		Signature:         sig,
	}
}

func TestWebAuthnCeremony_Success(t *testing.T) {
	f := newTestFixture(t)

	chal, err := f.sm.BeginWebAuthnAuth(f.fp)
	if err != nil {
		t.Fatalf("BeginWebAuthnAuth: %v", err)
	}
	assertion := f.buildAssertion(t, chal, 1, "https://test.local")

	otpChal, err := f.sm.CompleteWebAuthnAuth(f.fp, assertion)
	if err != nil {
		t.Fatalf("CompleteWebAuthnAuth: %v", err)
	}
	if otpChal.Email != f.email {
		t.Errorf("OTP email = %q, want %q", otpChal.Email, f.email)
	}
	// The code must have been DELIVERED through the sender — and must NOT
	// be returned to the API caller.
	if otpChal.Code != "" {
		t.Fatal("OTP code leaked to API caller")
	}
	if len(f.sender.to) != 1 || f.sender.to[0] != f.email {
		t.Fatalf("sender deliveries = %v, want one to %s", f.sender.to, f.email)
	}
	if len(f.sender.code) != 1 {
		t.Fatal("OTP was not delivered through the sender")
	}

	// ...and the OTP must complete authentication end-to-end.
	token, err := f.sm.CompleteAuthentication(f.email, f.sender.code[0], f.fp, 10, "MANAGER")
	if err != nil {
		t.Fatalf("CompleteAuthentication: %v", err)
	}
	if token.Tier != "MANAGER" || token.DeptID != 10 {
		t.Errorf("unexpected token fields: %+v", token)
	}
}

func TestWebAuthnCeremony_BadSignature(t *testing.T) {
	f := newTestFixture(t)
	chal, _ := f.sm.BeginWebAuthnAuth(f.fp)
	assertion := f.buildAssertion(t, chal, 1, "https://test.local")
	assertion.Signature[10] ^= 0xff // corrupt the signature

	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, assertion); err == nil {
		t.Fatal("expected rejection of forged signature")
	}
}

func TestWebAuthnCeremony_WrongChallenge(t *testing.T) {
	f := newTestFixture(t)
	chal, _ := f.sm.BeginWebAuthnAuth(f.fp)
	other := make([]byte, 32)
	copy(other, chal)
	other[0] ^= 0xff
	assertion := f.buildAssertion(t, other, 1, "https://test.local")

	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, assertion); err == nil {
		t.Fatal("expected rejection of wrong challenge")
	}
}

func TestWebAuthnCeremony_WrongOrigin(t *testing.T) {
	f := newTestFixture(t)
	chal, _ := f.sm.BeginWebAuthnAuth(f.fp)
	assertion := f.buildAssertion(t, chal, 1, "https://evil.example")

	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, assertion); err == nil {
		t.Fatal("expected rejection of wrong origin")
	}
}

func TestWebAuthnCeremony_ChallengeSingleUse(t *testing.T) {
	f := newTestFixture(t)
	chal, _ := f.sm.BeginWebAuthnAuth(f.fp)
	assertion := f.buildAssertion(t, chal, 1, "https://test.local")

	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, assertion); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Replaying the same challenge+assertion must fail (challenge consumed).
	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, assertion); err == nil {
		t.Fatal("expected rejection of replayed challenge")
	}
}

func TestWebAuthnCeremony_CloneDetection(t *testing.T) {
	f := newTestFixture(t)

	// First login with counter=5.
	chal1, _ := f.sm.BeginWebAuthnAuth(f.fp)
	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, f.buildAssertion(t, chal1, 5, "https://test.local")); err != nil {
		t.Fatalf("first login: %v", err)
	}
	// Second login with counter NOT increasing → cloned authenticator.
	chal2, _ := f.sm.BeginWebAuthnAuth(f.fp)
	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, f.buildAssertion(t, chal2, 5, "https://test.local")); err == nil {
		t.Fatal("expected clone-detection rejection for stagnant counter")
	}
	// Counter increasing again → fine.
	chal3, _ := f.sm.BeginWebAuthnAuth(f.fp)
	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, f.buildAssertion(t, chal3, 6, "https://test.local")); err != nil {
		t.Fatalf("increasing counter rejected: %v", err)
	}
}

func TestWebAuthnCeremony_CredentialMismatch(t *testing.T) {
	f := newTestFixture(t)
	chal, _ := f.sm.BeginWebAuthnAuth(f.fp)
	assertion := f.buildAssertion(t, chal, 1, "https://test.local")
	assertion.CredentialID = []byte("someone-elses-credential")

	if _, err := f.sm.CompleteWebAuthnAuth(f.fp, assertion); err == nil {
		t.Fatal("expected rejection of mismatched credential ID")
	}
}

func TestWebAuthnCeremony_UnregisteredDevice(t *testing.T) {
	f := newTestFixture(t)
	if _, err := f.sm.BeginWebAuthnAuth("ghost-device"); err == nil {
		t.Fatal("expected HARD BLOCK for unregistered device")
	}
}

func TestCoseKeyToECDSA_RejectsGarbage(t *testing.T) {
	if _, err := coseKeyToECDSA([]byte("not-cbor")); err == nil {
		t.Fatal("expected error for garbage COSE key")
	}
	// Valid CBOR but not a P-256 key: map{1:2, 3:-7, -1:1, -2:h'00'*32, -3:h'00'*32}
	// → point at infinity, not on curve.
	bad := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	bad = append(bad, make([]byte, 32)...)
	bad = append(bad, 0x22, 0x58, 0x20)
	bad = append(bad, make([]byte, 32)...)
	if _, err := coseKeyToECDSA(bad); err == nil {
		t.Fatal("expected error for off-curve COSE key")
	}
}

func TestTokenHMAC_CoversAuthzFields(t *testing.T) {
	sm, _ := NewSessionManager()
	token, err := sm.createSessionToken("a@xio.cybersurhub.com", "fp", 3, "ANALYST")
	if err != nil {
		t.Fatal(err)
	}
	sm.activeSessions[token.TokenID] = token

	// Tamper with the authorization fields only.
	tampered := *token
	tampered.Tier = "ADMIN"
	tampered.DeptID = 99
	sm.activeSessions["tampered"] = &tampered

	if _, err := sm.ValidateSession("tampered", "fp"); err == nil {
		t.Fatal("HMAC must fail when Tier/DeptID are swapped")
	}
	// Untouched token still validates.
	if _, err := sm.ValidateSession(token.TokenID, "fp"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestIssueOTP_DeliversViaSender(t *testing.T) {
	sm, _ := NewSessionManager()
	sender := &recordingSender{}
	sm.SetOTPSender(sender)

	chal, err := sm.issueOTP("carol@xio.cybersurhub.com")
	if err != nil {
		t.Fatal(err)
	}
	if chal.Code != "" {
		t.Fatal("OTP code leaked to API caller")
	}
	if len(sender.to) != 1 {
		t.Fatal("OTP was not delivered through the sender")
	}
	// The server-side record must hold the delivered code.
	sm.mu.RLock()
	stored := sm.pendingOTPs["carol@xio.cybersurhub.com"]
	sm.mu.RUnlock()
	if stored == nil || stored.Code != sender.code[0] {
		t.Fatal("server-side OTP record does not match delivered code")
	}
}
