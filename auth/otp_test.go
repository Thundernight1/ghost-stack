package auth

import (
	"errors"
	"testing"
	"time"
)

// Without a configured OTPSender, issuance must fail closed: no code may
// be handed out through any fallback channel, and no half-issued pending
// record may be left behind (regression test).
func TestIssueOTP_FailsClosedWithoutSender(t *testing.T) {
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately no SetOTPSender call.

	chal, err := sm.issueOTP("dave@xio.cybersurhub.com")
	if err == nil {
		t.Fatal("expected fail-closed error when no OTP sender is configured")
	}
	if chal != nil {
		t.Fatal("expected nil challenge on failed issuance")
	}

	// Rollback check: the pending record created before delivery must be gone.
	sm.mu.RLock()
	_, exists := sm.pendingOTPs["dave@xio.cybersurhub.com"]
	sm.mu.RUnlock()
	if exists {
		t.Fatal("pending OTP record leaked after failed issuance")
	}
}

// A sender whose delivery fails must also roll back the pending record.
func TestIssueOTP_RollsBackOnDeliveryError(t *testing.T) {
	sm, err := NewSessionManager()
	if err != nil {
		t.Fatal(err)
	}
	sm.SetOTPSender(&failingSender{})

	if _, err := sm.issueOTP("erin@xio.cybersurhub.com"); err == nil {
		t.Fatal("expected error when sender delivery fails")
	}
	sm.mu.RLock()
	_, exists := sm.pendingOTPs["erin@xio.cybersurhub.com"]
	sm.mu.RUnlock()
	if exists {
		t.Fatal("pending OTP record leaked after delivery failure")
	}
}

type failingSender struct{}

func (failingSender) SendOTP(email, code string, expiresAt time.Time) error {
	return errors.New("test delivery failure")
}
