// Package auth — OTP delivery.
//
// The OTP second factor is delivered through a configurable OTPSender.
// Production wires an SMTPSender pointed at the internal company relay
// (company domain only — the network namespace's nftables egress filter
// blocks external providers). Tests inject a recording stub.
//
// The OTP code is NEVER returned to the API caller: issueOTP hands back a
// redacted challenge (Code == ""). The code lives only in the server-side
// pendingOTPs record and travels to the user through the OTPSender.
// Fail-closed: if no sender is configured, issuance fails outright —
// there is no fallback channel the code could leak through.
package auth

import (
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

// OTPSender delivers a one-time code to the user's company email.
type OTPSender interface {
	SendOTP(email, code string, expiresAt time.Time) error
}

// SetOTPSender configures the delivery channel for OTP codes.
// Issuance fails closed until a sender is set.
func (sm *SessionManager) SetOTPSender(sender OTPSender) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.otpSender = sender
}

// sendOTP delivers the code through the configured sender.
// Fail-closed: without a sender there is no delivery channel, so issuance
// must fail instead of leaking the code through any fallback.
func (sm *SessionManager) sendOTP(email, code string, expiresAt time.Time) error {
	sender := sm.otpSender // read under caller's lock
	if sender == nil {
		return fmt.Errorf("ghost-stack/auth: no OTP sender configured — refusing to issue code")
	}
	return sender.SendOTP(email, code, expiresAt)
}

// issueOTP creates, stores, and delivers an OTP challenge for email.
// Caller must hold sm.mu.
func (sm *SessionManager) issueOTP(email string) (*OTPChallenge, error) {
	if !sm.isCompanyEmail(email) {
		return nil, fmt.Errorf("ghost-stack/auth: only company email domain (%s) allowed", CompanyEmailDomain)
	}

	code, err := generateOTP()
	if err != nil {
		return nil, fmt.Errorf("ghost-stack/auth: OTP generation failed: %w", err)
	}

	challenge := &OTPChallenge{
		Email:     email,
		Code:      code,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Verified:  false,
	}
	sm.pendingOTPs[email] = challenge

	if err := sm.sendOTP(email, code, challenge.ExpiresAt); err != nil {
		delete(sm.pendingOTPs, email)
		return nil, fmt.Errorf("ghost-stack/auth: OTP delivery failed: %w", err)
	}
	// Return a redacted copy: the code must travel to the user only through
	// the OTPSender, never through the API return value. The full challenge
	// (with code) stays in sm.pendingOTPs for CompleteAuthentication.
	redacted := *challenge
	redacted.Code = ""
	return &redacted, nil
}

// SMTPSender delivers OTP codes via an SMTP relay (STARTTLS).
// Point it at the internal company relay; delivery is restricted to the
// company domain.
type SMTPSender struct {
	// Addr is the relay address, e.g. "smtp.xio.cybersurhub.com:587".
	Addr string
	// From is the envelope sender, e.g. "no-reply@xio.cybersurhub.com".
	From string
	// Auth authenticates to the relay. Nil means no SMTP AUTH.
	Auth smtp.Auth
}

// SendOTP implements OTPSender.
func (s *SMTPSender) SendOTP(email, code string, expiresAt time.Time) error {
	if !strings.HasSuffix(strings.ToLower(email), "@"+CompanyEmailDomain) {
		return fmt.Errorf("ghost-stack/auth: refusing OTP delivery outside company domain: %s", email)
	}
	if s.Addr == "" || s.From == "" {
		return fmt.Errorf("ghost-stack/auth: SMTP sender not configured")
	}

	subject := "GHOST-STACK login code"
	body := fmt.Sprintf("Your GHOST-STACK one-time login code is:\r\n\r\n  %s\r\n\r\nIt expires at %s. Never share this code.\r\n",
		code, expiresAt.UTC().Format("15:04:05 MST"))
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		s.From, email, subject, body)

	if err := smtp.SendMail(s.Addr, s.Auth, s.From, []string{email}, []byte(msg)); err != nil {
		return fmt.Errorf("ghost-stack/auth: smtp send: %w", err)
	}
	return nil
}
