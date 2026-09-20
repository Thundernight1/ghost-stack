package auth

// Ceremony test helpers.
//
// These helpers run the REAL WebAuthn login ceremony in tests
// (BeginWebAuthnAuth → signed ECDSA assertion → CompleteWebAuthnAuth).
// There is no assertion-less shortcut: the old StartAuthentication path
// was removed because it issued OTPs without hardware proof.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// Test Relying Party identity used by all ceremony helpers.
const (
	ceremonyRPID   = "test.local"
	ceremonyOrigin = "https://test.local"
)

// coseP256PublicKey encodes a P-256 public key as a COSE_Key (EC2/ES256).
// testing.T-free variant for use in benchmarks.
func coseP256PublicKey(pub *ecdsa.PublicKey) []byte {
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

// registerCeremonyDevice generates a P-256 key pair, registers the device
// with its real COSE public key, configures the test Relying Party and
// attaches a recording OTP sender. Returns the private key, the credential
// ID and the sender.
func registerCeremonyDevice(t *testing.T, sm *SessionManager, email, fp string) (*ecdsa.PrivateKey, []byte, *recordingSender) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sm.ConfigureWebAuthn(ceremonyRPID, ceremonyOrigin)
	sender := &recordingSender{}
	sm.SetOTPSender(sender)
	credID := []byte("cred-" + fp)
	att := &FIDO2Attestation{
		CredentialID:      credID,
		PublicKey:         coseP256PublicKey(&priv.PublicKey),
		AAGUID:            [16]byte{0xDE, 0xAD},
		DeviceFingerprint: fp,
	}
	if err := sm.RegisterDevice(email, att); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	return priv, credID, sender
}

// buildTestAssertion crafts a valid WebAuthn assertion for the challenge.
// It returns an error instead of failing the test so it is safe to call
// from worker goroutines.
func buildTestAssertion(priv *ecdsa.PrivateKey, credID, challenge []byte, signCount uint32) (*WebAuthnAssertion, error) {
	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    ceremonyOrigin,
	})
	if err != nil {
		return nil, err
	}
	rpHash := sha256.Sum256([]byte(ceremonyRPID))
	authData := make([]byte, 37)
	copy(authData[:32], rpHash[:])
	authData[32] = 0x01 // user-present flag
	binary.BigEndian.PutUint32(authData[33:37], signCount)

	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(authData, clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	return &WebAuthnAssertion{
		CredentialID:      credID,
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
		Signature:         sig,
	}, nil
}

// ceremonyOTP runs the full WebAuthn login ceremony and returns the OTP
// code as DELIVERED through the sender. It fails the test if the code
// leaks through the API return value. signCount must increase across
// ceremonies for the same device (authenticator clone detection).
func ceremonyOTP(t *testing.T, sm *SessionManager, sender *recordingSender, priv *ecdsa.PrivateKey, credID []byte, fp string, signCount uint32) string {
	t.Helper()
	before := len(sender.code)
	chal, err := sm.BeginWebAuthnAuth(fp)
	if err != nil {
		t.Fatalf("BeginWebAuthnAuth: %v", err)
	}
	assertion, err := buildTestAssertion(priv, credID, chal, signCount)
	if err != nil {
		t.Fatalf("buildTestAssertion: %v", err)
	}
	otpChal, err := sm.CompleteWebAuthnAuth(fp, assertion)
	if err != nil {
		t.Fatalf("CompleteWebAuthnAuth: %v", err)
	}
	if otpChal.Code != "" {
		t.Fatal("OTP code leaked to API caller — it must travel via the sender only")
	}
	if len(sender.code) != before+1 {
		t.Fatal("OTP was not delivered through the sender")
	}
	return sender.code[len(sender.code)-1]
}

// routeSender multiplexes OTP deliveries to per-email recorders.
// Concurrency-safe; used by tests that run ceremonies in parallel where a
// single recordingSender cannot map deliveries back to callers.
type routeSender struct {
	mu    sync.Mutex
	codes map[string][]string
}

// SendOTP implements OTPSender.
func (r *routeSender) SendOTP(email, code string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.codes == nil {
		r.codes = make(map[string][]string)
	}
	r.codes[email] = append(r.codes[email], code)
	return nil
}

// lastCode returns the most recently delivered code for email.
func (r *routeSender) lastCode(email string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.codes[email]
	if len(c) == 0 {
		return ""
	}
	return c[len(c)-1]
}
