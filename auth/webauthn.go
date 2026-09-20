// Package auth — real WebAuthn (FIDO2) assertion verification.
//
// This file implements cryptographic verification of WebAuthn authentication
// assertions, per the W3C WebAuthn Level 2 ceremony:
//
//  1. clientDataJSON: type must be "webauthn.get", challenge must match the
//     server-issued challenge (constant-time), origin must match the RP.
//  2. authenticatorData: rpIdHash must equal SHA-256(RP ID), the User Present
//     flag must be set, and the signature counter must increase
//     monotonically (clone detection).
//  3. signature: ECDSA (ES256) over authenticatorData || SHA-256(clientDataJSON),
//     verified with the COSE-encoded public key registered for the device.
//  4. credential binding: the asserted credential ID must equal the
//     credential registered for the device.
//
// No third-party WebAuthn library is used: COSE keys need only a small,
// auditable CBOR subset (maps with integer keys, byte strings, small ints),
// which is implemented below. The signature itself uses crypto/ecdsa.
package auth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"time"
)

// WebAuthnAssertion is the client's response to a server-issued challenge
// (navigator.credentials.get() result, transmitted as raw bytes).
type WebAuthnAssertion struct {
	// CredentialID is the credential the authenticator used to sign.
	CredentialID []byte
	// AuthenticatorData is the raw authenticator data (rpIdHash|flags|signCount|...).
	AuthenticatorData []byte
	// ClientDataJSON is the raw JSON the client built.
	ClientDataJSON []byte
	// Signature is the ASN.1-DER ECDSA signature (ES256).
	Signature []byte
}

// webAuthnChallenge is a pending server-issued login challenge.
type webAuthnChallenge struct {
	Challenge []byte
	ExpiresAt int64 // unix
}

// DefaultWebAuthnRPID and DefaultWebAuthnOrigin are used until the operator
// configures the real values via ConfigureWebAuthn.
const (
	DefaultWebAuthnRPID   = "ghost-stack.local"
	DefaultWebAuthnOrigin = "https://ghost-stack.local"
)

// ConfigureWebAuthn sets the Relying Party ID and the expected origin for
// assertion verification. Must be called with production values.
func (sm *SessionManager) ConfigureWebAuthn(rpID, origin string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.webAuthnRPID = rpID
	sm.webAuthnOrigin = origin
}

func (sm *SessionManager) rpID() string {
	if sm.webAuthnRPID != "" {
		return sm.webAuthnRPID
	}
	return DefaultWebAuthnRPID
}

func (sm *SessionManager) rpOrigin() string {
	if sm.webAuthnOrigin != "" {
		return sm.webAuthnOrigin
	}
	return DefaultWebAuthnOrigin
}

// BeginWebAuthnAuth issues a fresh 32-byte challenge for the device.
// The authenticator signs it; CompleteWebAuthnAuth verifies the result.
// Challenges are single-use and expire after 2 minutes.
func (sm *SessionManager) BeginWebAuthnAuth(deviceFingerprint string) ([]byte, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.registeredDevices[deviceFingerprint]; !exists {
		return nil, fmt.Errorf("ghost-stack/auth: HARD BLOCK — device %s is not company-registered", deviceFingerprint)
	}

	chal := make([]byte, 32)
	if _, err := rand.Read(chal); err != nil {
		return nil, fmt.Errorf("ghost-stack/auth: challenge generation: %w", err)
	}
	if sm.pendingWebAuthn == nil {
		sm.pendingWebAuthn = make(map[string]*webAuthnChallenge)
	}
	sm.pendingWebAuthn[deviceFingerprint] = &webAuthnChallenge{
		Challenge: chal,
		ExpiresAt: time.Now().Unix() + 120,
	}
	out := make([]byte, 32)
	copy(out, chal)
	return out, nil
}

// CompleteWebAuthnAuth verifies the assertion cryptographically and, on
// success, issues + delivers the email OTP (second factor).
func (sm *SessionManager) CompleteWebAuthnAuth(deviceFingerprint string, assertion *WebAuthnAssertion) (*OTPChallenge, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	attestation, exists := sm.registeredDevices[deviceFingerprint]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/auth: HARD BLOCK — device %s is not company-registered", deviceFingerprint)
	}

	pending, exists := sm.pendingWebAuthn[deviceFingerprint]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/auth: no pending WebAuthn challenge — call BeginWebAuthnAuth first")
	}
	delete(sm.pendingWebAuthn, deviceFingerprint) // single-use
	if time.Now().Unix() > pending.ExpiresAt {
		return nil, fmt.Errorf("ghost-stack/auth: WebAuthn challenge expired")
	}

	// Credential binding: the assertion must come from the registered credential.
	if !bytes.Equal(assertion.CredentialID, attestation.CredentialID) {
		return nil, fmt.Errorf("ghost-stack/auth: HARD BLOCK — assertion credential does not match registered credential")
	}

	// Real cryptographic verification (may update attestation.SignCount).
	if err := sm.verifyAssertion(attestation, pending.Challenge, assertion); err != nil {
		return nil, fmt.Errorf("ghost-stack/auth: WebAuthn assertion rejected: %w", err)
	}

	email, exists := sm.deviceToUser[deviceFingerprint]
	if !exists {
		return nil, fmt.Errorf("ghost-stack/auth: device not bound to any user")
	}

	return sm.issueOTP(email)
}

// verifyAssertion runs the full WebAuthn assertion ceremony. On success it
// advances the stored signature counter (clone detection state).
func (sm *SessionManager) verifyAssertion(att *FIDO2Attestation, expectedChallenge []byte, a *WebAuthnAssertion) error {
	if a == nil {
		return fmt.Errorf("nil assertion")
	}

	// --- 1. clientDataJSON ---
	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(a.ClientDataJSON, &clientData); err != nil {
		return fmt.Errorf("clientDataJSON: %w", err)
	}
	if clientData.Type != "webauthn.get" {
		return fmt.Errorf("clientData type = %q, want \"webauthn.get\"", clientData.Type)
	}
	chalBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		return fmt.Errorf("clientData challenge: %w", err)
	}
	if subtle.ConstantTimeCompare(chalBytes, expectedChallenge) != 1 {
		return fmt.Errorf("challenge mismatch")
	}
	if clientData.Origin != sm.rpOrigin() {
		return fmt.Errorf("origin = %q, want %q", clientData.Origin, sm.rpOrigin())
	}

	// --- 2. authenticatorData ---
	if len(a.AuthenticatorData) < 37 {
		return fmt.Errorf("authenticatorData too short (%d bytes)", len(a.AuthenticatorData))
	}
	rpIDHash := sha256.Sum256([]byte(sm.rpID()))
	if !bytes.Equal(a.AuthenticatorData[:32], rpIDHash[:]) {
		return fmt.Errorf("rpIdHash mismatch")
	}
	flags := a.AuthenticatorData[32]
	if flags&0x01 == 0 {
		return fmt.Errorf("user-present flag not set")
	}
	signCount := binary.BigEndian.Uint32(a.AuthenticatorData[33:37])
	// Clone detection: counter must increase. A device that never
	// implements the counter reports 0 forever — accept (0,0) only.
	if signCount <= att.SignCount && (att.SignCount != 0 || signCount != 0) {
		return fmt.Errorf("signature counter did not increase (got %d, last %d) — possible cloned authenticator",
			signCount, att.SignCount)
	}

	// --- 3. signature ---
	pub, err := coseKeyToECDSA(att.PublicKey)
	if err != nil {
		return fmt.Errorf("registered COSE key: %w", err)
	}
	clientHash := sha256.Sum256(a.ClientDataJSON)
	signed := append(append([]byte{}, a.AuthenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], a.Signature) {
		return fmt.Errorf("ECDSA signature invalid")
	}

	// Ceremony passed — persist the new counter for clone detection.
	att.SignCount = signCount
	return nil
}

// ---------------------------------------------------------------------------
// Minimal CBOR decoder — just enough for COSE EC2 public keys.
// ---------------------------------------------------------------------------

// cborValue is a decoded CBOR item. Maps are restricted to integer keys,
// which is all COSE_Key needs.
type cborValue struct {
	isUint bool
	u      uint64
	isNint bool
	n      int64
	b      []byte               // byte string
	m      map[int64]*cborValue // map with integer keys
	isMap  bool
}

type cborDecoder struct {
	data []byte
	pos  int
}

func (d *cborDecoder) readArg(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		return d.readN(1)
	case ai == 25:
		return d.readN(2)
	case ai == 26:
		return d.readN(4)
	case ai == 27:
		return d.readN(8)
	default:
		return 0, fmt.Errorf("cbor: indefinite lengths not supported")
	}
}

func (d *cborDecoder) readN(n int) (uint64, error) {
	if d.pos+n > len(d.data) {
		return 0, fmt.Errorf("cbor: truncated")
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(d.data[d.pos+i])
	}
	d.pos += n
	return v, nil
}

// maxCBORDepth bounds decoder recursion: hostile nesting would otherwise
// exhaust the goroutine stack and panic the handler.
const maxCBORDepth = 32

func decodeCBORItem(d *cborDecoder) (*cborValue, error) {
	return decodeCBORItemDepth(d, 0)
}

func decodeCBORItemDepth(d *cborDecoder, depth int) (*cborValue, error) {
	if d.pos >= len(d.data) {
		return nil, fmt.Errorf("cbor: truncated")
	}
	ib := d.data[d.pos]
	d.pos++
	major := ib >> 5
	ai := ib & 0x1f

	switch major {
	case 0: // unsigned int
		v, err := d.readArg(ai)
		return &cborValue{isUint: true, u: v}, err
	case 1: // negative int
		v, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		if v > math.MaxInt64 {
			return nil, fmt.Errorf("cbor: negative int out of range")
		}
		return &cborValue{isNint: true, n: -1 - int64(v)}, nil // #nosec G115 -- v <= math.MaxInt64 verified above
	case 2: // byte string
		l, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		// d.pos is always within [0, len(d.data)] (decoder invariant), so the
		// subtraction cannot go negative.
		remaining := uint64(len(d.data) - d.pos) // #nosec G115
		if l > remaining {
			return nil, fmt.Errorf("cbor: byte string overruns")
		}
		b := append([]byte{}, d.data[d.pos:d.pos+int(l)]...) // #nosec G115 -- l <= len(d.data)-d.pos, int(l) cannot overflow
		d.pos += int(l)                                      // #nosec G115 -- same bound as above
		return &cborValue{b: b}, nil
	case 5: // map
		l, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		// Never preallocate from an attacker-controlled length: a huge hint
		// would exhaust memory before the first item is even decoded.
		// COSE keys carry a handful of entries; grow naturally instead.
		if depth >= maxCBORDepth {
			return nil, fmt.Errorf("cbor: max nesting depth exceeded")
		}
		m := make(map[int64]*cborValue)
		for i := uint64(0); i < l; i++ {
			k, err := decodeCBORItemDepth(d, depth+1)
			if err != nil {
				return nil, err
			}
			var key int64
			switch {
			case k.isUint:
				if k.u > math.MaxInt64 {
					return nil, fmt.Errorf("cbor: map key out of range")
				}
				key = int64(k.u) // #nosec G115 -- k.u <= math.MaxInt64 verified above
			case k.isNint:
				key = k.n
			default:
				return nil, fmt.Errorf("cbor: non-integer map key")
			}
			v, err := decodeCBORItemDepth(d, depth+1)
			if err != nil {
				return nil, err
			}
			m[key] = v
		}
		return &cborValue{isMap: true, m: m}, nil
	default:
		return nil, fmt.Errorf("cbor: unsupported major type %d", major)
	}
}

// coseKeyToECDSA parses a COSE_Key (EC2, ES256, P-256) into an ECDSA public key.
func coseKeyToECDSA(raw []byte) (*ecdsa.PublicKey, error) {
	v, err := decodeCBORItem(&cborDecoder{data: raw})
	if err != nil {
		return nil, fmt.Errorf("cbor decode: %w", err)
	}
	if !v.isMap {
		return nil, fmt.Errorf("COSE key is not a map")
	}
	get := func(k int64) *cborValue { return v.m[k] }

	if kty := get(1); kty == nil || !kty.isUint || kty.u != 2 {
		return nil, fmt.Errorf("COSE kty != EC2")
	}
	if alg := get(3); alg == nil || !alg.isNint || alg.n != -7 {
		return nil, fmt.Errorf("COSE alg != ES256")
	}
	if crv := get(-1); crv == nil || !crv.isUint || crv.u != 1 {
		return nil, fmt.Errorf("COSE crv != P-256")
	}
	x := get(-2)
	y := get(-3)
	if x == nil || y == nil || len(x.b) != 32 || len(y.b) != 32 {
		return nil, fmt.Errorf("COSE x/y coordinates invalid")
	}

	curve := elliptic.P256()
	bx := new(big.Int).SetBytes(x.b)
	by := new(big.Int).SetBytes(y.b)
	// elliptic.Curve.IsOnCurve is deprecated (low-level, unsafe API).
	// crypto/ecdh performs the on-curve check inside NewPublicKey.
	uncompressed := make([]byte, 0, 65)
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, x.b...)
	uncompressed = append(uncompressed, y.b...)
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("COSE point not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: bx, Y: by}, nil
}
