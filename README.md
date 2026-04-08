# Passkey Demo

Minimal WebAuthn/FIDO2 passkey example — Go backend, vanilla JS frontend.

## Run

```bash
go run .
# open http://localhost:8080
```

> Requires a browser and OS that support platform passkeys (Chrome/Safari on a device with biometrics or Windows Hello).

---

## Flow

### Registration

```
Browser                    Server                   Authenticator
  │                          │                            │
  ├─ POST /register/begin ──►│                            │
  │  {username}              │                            │
  │◄─ CreationOptions ───────┤                            │
  │  {challenge, rpId, user} │                            │
  │                          │                            │
  ├─ credentials.create() ───────────────────────────────►│
  │                          │         user verifies (biometric/PIN)
  │◄─ PublicKeyCredential ────────────────────────────────┤
  │  {pubKey, attestation,   │         keypair generated; privKey stays on device
  │   signed clientDataJSON} │                            │
  │                          │                            │
  ├─ POST /register/finish ─►│                            │
  │                          ├─ verify signature          │
  │                          ├─ store pubKey              │
  │◄─ {status: ok} ──────────┤                            │
```

### Authentication

```
Browser                    Server                   Authenticator
  │                          │                            │
  ├─ POST /login/begin ─────►│                            │
  │                          │                            │
  │◄─ RequestOptions ────────┤                            │
  │  {challenge, rpId}       │                            │
  │                          │                            │
  ├─ credentials.get() ──────────────────────────────────►│
  │                          │         user verifies (biometric/PIN)
  │◄─ Assertion ──────────────────────────────────────────┤
  │  {signed challenge,      │                  signed with privKey
  │   userHandle}            │                            │
  │                          │                            │
  ├─ POST /login/finish ────►│                            │
  │                          ├─ look up user by userHandle│
  │                          ├─ verify(signature, pubKey) │
  │◄─ {status: ok, username}─┤                            │
```

---

## Structure

```
passkey/
├── main.go        — WebAuthn config, HTTP handlers, session stores
├── store.go       — In-memory user store (username ↔ credentials)
└── static/
    └── index.html — Vanilla JS frontend
```
