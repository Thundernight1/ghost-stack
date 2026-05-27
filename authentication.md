---
title: "Authentication and company email domain"
description: "Configure FIDO2 hardware-bound sessions and the xio.cybersurhub.com domain allowlist for GHOST-STACK CORE."
---

GHOST-STACK CORE gates all device registration and session issuance behind a single company email domain. Only addresses ending in **`@xio.cybersurhub.com`** can enroll a FIDO2 device, complete OTP verification, or receive a session token. External providers are blocked both at the application layer and by the network namespace's egress filter.

Use this page when you provision a new operator, onboard a hardware token, or troubleshoot an authentication failure.

## When this applies

The domain check runs on every authentication-related call:

- **Device registration** — `RegisterDevice` rejects any address outside the allowed domain.
- **OTP issuance** — `InitiateAuthentication` only generates an OTP for company emails.
- **Session creation** — `CompleteAuthentication` re-verifies the domain before binding a session to the FIDO2 device fingerprint.

If you see `only company email domain (xio.cybersurhub.com) allowed`, the supplied address does not match the configured domain.

## Configure the company domain

The domain is defined as a package constant in `auth/session.go`:

```go
// CompanyEmailDomain is the only allowed email domain for authentication.
// External email providers are blocked at network namespace level.
const CompanyEmailDomain = "xio.cybersurhub.com"
```

To change the domain for your deployment:

1. Update `CompanyEmailDomain` in `auth/session.go`.
2. Rebuild the orchestrator with `make build`.
3. Update the network namespace egress allowlist so the internal SMTP relay can still deliver OTP mail.
4. Re-enroll any existing operators — previously registered addresses outside the new domain will be rejected on next login.

## Authentication flow

The full flow combines hardware attestation, OTP, and AES-256-GCM session tokens:

1. **FIDO2 WebAuthn** — the operator presents a registered hardware token.
2. **Company email OTP** — a 5-minute OTP is sent to the operator's `@xio.cybersurhub.com` address via the internal SMTP relay.
3. **Session token** — on successful OTP verification, an AES-256-GCM token is issued with an 8-hour TTL.
4. **Hardware binding** — the token is cryptographically bound to the FIDO2 device fingerprint and rotates hourly within the TTL window.

## Example: register and authenticate

```go
sm := auth.NewSessionManager(masterKey)

// 1. Register a FIDO2 device for a company email.
err := sm.RegisterDevice("alice@xio.cybersurhub.com", attestation)
if err != nil {
    log.Fatalf("registration failed: %v", err)
}

// 2. Request an OTP. The relay only delivers to xio.cybersurhub.com.
challenge, err := sm.InitiateAuthentication("alice@xio.cybersurhub.com")
if err != nil {
    log.Fatalf("otp init failed: %v", err)
}

// 3. Complete authentication and receive a hardware-bound session token.
token, err := sm.CompleteAuthentication(
    "alice@xio.cybersurhub.com",
    challenge.Code,
    attestation.DeviceFingerprint,
    0,        // department ID
    "ROOT",   // hierarchy tier
)
if err != nil {
    log.Fatalf("auth failed: %v", err)
}
```

A request from `eve@xio.cybersurhub.external` (or any other domain) is rejected at step 1 before an OTP is ever generated.

## Troubleshooting

| Error | Cause | Resolution |
|---|---|---|
| `only company email domain (xio.cybersurhub.com) allowed` | Address does not end in the configured domain. | Use a `@xio.cybersurhub.com` address or update `CompanyEmailDomain` and rebuild. |
| `no pending OTP for <email>` | OTP was never requested or already consumed. | Call `InitiateAuthentication` again. |
| `OTP expired` | OTP older than 5 minutes. | Request a new OTP. |
| `HARD BLOCK — non-registered device` | FIDO2 fingerprint is not enrolled. | Register the device with `RegisterDevice` before authenticating. |
| `device not bound to this user` | FIDO2 device belongs to a different operator. | Use the operator's own hardware token. |
