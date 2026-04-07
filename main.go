package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	wa        *webauthn.WebAuthn
	users     *UserStore
	regSess   = newRegSessionStore()
	loginSess = newLoginSessionStore()
)

// ---- Registration ceremony session ----

type regEntry struct {
	data     *webauthn.SessionData
	username string
}

type regSessionStore struct {
	mu sync.Mutex
	m  map[string]*regEntry
}

func newRegSessionStore() *regSessionStore {
	return &regSessionStore{m: make(map[string]*regEntry)}
}

func (s *regSessionStore) set(token string, e *regEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[token] = e
	slog.Debug("reg session stored", "token_prefix", token[:8], "username", e.username)
}

// pop atomically retrieves and deletes, making each session single-use.
func (s *regSessionStore) pop(token string) (*regEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[token]
	if ok {
		delete(s.m, token)
		slog.Debug("reg session consumed", "token_prefix", token[:8], "username", e.username)
	} else {
		slog.Warn("reg session not found or already consumed", "token_prefix", token[:8])
	}
	return e, ok
}

// ---- Login ceremony session ----

type loginSessionStore struct {
	mu sync.Mutex
	m  map[string]*webauthn.SessionData
}

func newLoginSessionStore() *loginSessionStore {
	return &loginSessionStore{m: make(map[string]*webauthn.SessionData)}
}

func (s *loginSessionStore) set(token string, data *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[token] = data
	slog.Debug("login session stored", "token_prefix", token[:8], "challenge_prefix", data.Challenge[:8])
}

func (s *loginSessionStore) pop(token string) (*webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.m[token]
	if ok {
		delete(s.m, token)
		slog.Debug("login session consumed", "token_prefix", token[:8], "challenge_prefix", data.Challenge[:8])
	} else {
		slog.Warn("login session not found or already consumed", "token_prefix", token[:8])
	}
	return data, ok
}

// ---- Helpers ----

func newToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: failed to encode response", "error", err)
	}
}

func writeError(w http.ResponseWriter, msg string, code int) {
	slog.Error("sending error response", "status", code, "error", msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---- HTTP logging middleware ----

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

func sessionCookie(name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300, // 5-minute ceremony window
	}
}

// ---- Handlers ----

// POST /register/begin
// Body: {"username": "alice"}
// Returns: PublicKeyCredentialCreationOptions (wrapped in {"publicKey": ...})
func handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	slog.Info("register/begin: request received", "remote", r.RemoteAddr)

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		slog.Warn("register/begin: invalid or missing username", "remote", r.RemoteAddr)
		writeError(w, "username required", http.StatusBadRequest)
		return
	}
	if len(req.Username) > 64 {
		slog.Warn("register/begin: username too long", "username_len", len(req.Username))
		writeError(w, "username too long", http.StatusBadRequest)
		return
	}
	slog.Info("register/begin: decoded request", "username", req.Username)

	user, created := users.GetOrCreate(req.Username)
	if created {
		slog.Info("register/begin: new user created", "username", user.Name, "user_id", hex.EncodeToString(user.ID))
	} else {
		slog.Info("register/begin: existing user found", "username", user.Name, "user_id", hex.EncodeToString(user.ID), "existing_credentials", len(user.Credentials))
	}

	exclusions := webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()
	slog.Info("register/begin: excluding already-registered credentials", "count", len(exclusions))

	// Exclude already-registered credentials to prevent double-registration
	// on the same authenticator.
	opts, session, err := wa.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		slog.Error("register/begin: BeginRegistration failed", "username", req.Username, "error", err)
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token := newToken()
	slog.Info("register/begin: session created", "username", req.Username, "token_prefix", token[:8], "challenge_prefix", session.Challenge[:8])
	regSess.set(token, &regEntry{data: session, username: req.Username})
	http.SetCookie(w, sessionCookie("reg_session", token))
	writeJSON(w, opts)
	slog.Info("register/begin: options sent to client", "username", req.Username)
}

// POST /register/finish
// Body: PublicKeyCredential (registration response from navigator.credentials.create)
// Uses reg_session cookie set by /register/begin
func handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	slog.Info("register/finish: request received", "remote", r.RemoteAddr)

	cookie, err := r.Cookie("reg_session")
	if err != nil {
		slog.Warn("register/finish: missing reg_session cookie", "remote", r.RemoteAddr)
		writeError(w, "missing session cookie", http.StatusBadRequest)
		return
	}
	slog.Debug("register/finish: session cookie found", "token_prefix", cookie.Value[:8])

	entry, ok := regSess.pop(cookie.Value)
	if !ok {
		writeError(w, "session not found or expired", http.StatusBadRequest)
		return
	}
	slog.Info("register/finish: session resolved", "username", entry.username, "challenge_prefix", entry.data.Challenge[:8])

	user, ok := users.Get(entry.username)
	if !ok {
		slog.Error("register/finish: user not found after session lookup", "username", entry.username)
		writeError(w, "user not found", http.StatusInternalServerError)
		return
	}
	slog.Debug("register/finish: user found", "username", user.Name, "user_id", hex.EncodeToString(user.ID))

	credential, err := wa.FinishRegistration(user, *entry.data, r)
	if err != nil {
		slog.Error("register/finish: FinishRegistration failed", "username", user.Name, "error", err)
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	slog.Info("register/finish: credential verified",
		"username", user.Name,
		"credential_id", hex.EncodeToString(credential.ID),
		"attestation_type", credential.AttestationType,
		"user_present", credential.Flags.UserPresent,
		"user_verified", credential.Flags.UserVerified,
		"backup_eligible", credential.Flags.BackupEligible,
		"backup_state", credential.Flags.BackupState,
		"sign_count", credential.Authenticator.SignCount,
	)

	users.AddCredential(user.Name, *credential)
	slog.Info("register/finish: registration complete", "username", user.Name)
	writeJSON(w, map[string]string{"status": "ok", "username": user.Name})
}

// POST /login/begin
// No body required — uses discoverable (passkey) flow.
// Returns: PublicKeyCredentialRequestOptions (wrapped in {"publicKey": ...})
func handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	slog.Info("login/begin: request received", "remote", r.RemoteAddr)

	opts, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("login/begin: BeginDiscoverableLogin failed", "error", err)
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token := newToken()
	slog.Info("login/begin: session created", "token_prefix", token[:8], "challenge_prefix", session.Challenge[:8])
	loginSess.set(token, session)
	http.SetCookie(w, sessionCookie("login_session", token))
	writeJSON(w, opts)
	slog.Info("login/begin: options sent to client")
}

// POST /login/finish
// Body: PublicKeyCredential (assertion response from navigator.credentials.get)
// Uses login_session cookie set by /login/begin
func handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	slog.Info("login/finish: request received", "remote", r.RemoteAddr)

	cookie, err := r.Cookie("login_session")
	if err != nil {
		slog.Warn("login/finish: missing login_session cookie", "remote", r.RemoteAddr)
		writeError(w, "missing session cookie", http.StatusBadRequest)
		return
	}
	slog.Debug("login/finish: session cookie found", "token_prefix", cookie.Value[:8])

	session, ok := loginSess.pop(cookie.Value)
	if !ok {
		writeError(w, "session not found or expired", http.StatusBadRequest)
		return
	}
	slog.Info("login/finish: session resolved", "challenge_prefix", session.Challenge[:8])

	// DiscoverableUserHandler: called by the library with the credential's
	// rawID and the userHandle (= user.WebAuthnID() stored by the authenticator).
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		slog.Info("login/finish: DiscoverableUserHandler called",
			"raw_id", hex.EncodeToString(rawID),
			"user_handle", hex.EncodeToString(userHandle),
		)
		user, ok := users.GetByID(userHandle)
		if !ok {
			slog.Warn("login/finish: no user found for userHandle", "user_handle", hex.EncodeToString(userHandle))
			return nil, fmt.Errorf("user not found")
		}
		slog.Info("login/finish: user resolved from userHandle", "username", user.Name, "credentials", len(user.Credentials))
		return user, nil
	}

	user, credential, err := wa.FinishPasskeyLogin(handler, *session, r)
	if err != nil {
		slog.Error("login/finish: FinishPasskeyLogin failed", "error", err)
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	slog.Info("login/finish: signature verified",
		"username", user.WebAuthnName(),
		"credential_id", hex.EncodeToString(credential.ID),
		"sign_count", credential.Authenticator.SignCount,
		"clone_warning", credential.Authenticator.CloneWarning,
		"user_verified", credential.Flags.UserVerified,
	)
	if credential.Authenticator.CloneWarning {
		slog.Warn("login/finish: CLONE WARNING — sign counter did not increase; possible cloned authenticator",
			"username", user.WebAuthnName(),
			"credential_id", hex.EncodeToString(credential.ID),
		)
	}

	// Persist updated sign counter; a decrease indicates a cloned authenticator.
	users.UpdateCredential(user.WebAuthnID(), credential)
	slog.Info("login/finish: login complete", "username", user.WebAuthnName())

	writeJSON(w, map[string]string{
		"status":   "ok",
		"username": user.WebAuthnName(),
	})
}

// ---- Entry point ----

func main() {
	// Use text handler at DEBUG level so all severity levels are visible.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	slog.Info("starting passkey demo server")

	var err error
	wa, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Passkey Demo",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
		// Require resident/discoverable credentials so the passkey login
		// flow works without the user having to supply a username.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	slog.Info("webauthn configured",
		"rpid", "localhost",
		"origins", []string{"http://localhost:8080"},
		"resident_key", "required",
		"user_verification", "preferred",
	)

	users = NewUserStore()
	slog.Info("user store initialized")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register/begin", handleRegisterBegin)
	mux.HandleFunc("POST /register/finish", handleRegisterFinish)
	mux.HandleFunc("POST /login/begin", handleLoginBegin)
	mux.HandleFunc("POST /login/finish", handleLoginFinish)
	mux.Handle("/", http.FileServer(http.Dir("static")))
	slog.Info("routes registered")

	addr := ":8080"
	slog.Info("listening", "addr", addr, "url", "http://localhost"+addr)
	log.Fatal(http.ListenAndServe(addr, loggingMiddleware(mux)))
}
