package main

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User implements webauthn.User and serves as the credential record.
type User struct {
	ID           []byte
	Name         string
	Credentials  []webauthn.Credential
	PasswordHash []byte // bcrypt hash; nil if no password set
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// UserStore is a thread-safe in-memory store keyed by username and user ID.
type UserStore struct {
	mu     sync.RWMutex
	byName map[string]*User
	byID   map[string]*User // string([]byte id) → *User
}

func NewUserStore() *UserStore {
	return &UserStore{
		byName: make(map[string]*User),
		byID:   make(map[string]*User),
	}
}

// GetOrCreate returns an existing user or creates a new one with a random 16-byte ID.
// The bool return is true when a new user was created.
func (s *UserStore) GetOrCreate(name string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byName[name]; ok {
		slog.Debug("user store: existing user found", "username", name, "user_id", hex.EncodeToString(u.ID), "credentials", len(u.Credentials))
		return u, false
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	u := &User{ID: id, Name: name}
	s.byName[name] = u
	s.byID[string(id)] = u
	slog.Info("user store: new user created", "username", name, "user_id", hex.EncodeToString(id))
	return u, true
}

func (s *UserStore) Get(name string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[name]
	return u, ok
}

// GetByID looks up a user by their WebAuthn user handle (u.ID).
func (s *UserStore) GetByID(id []byte) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[string(id)]
	if !ok {
		slog.Debug("user store: GetByID: no user found", "user_id", hex.EncodeToString(id))
	}
	return u, ok
}

// SetPassword stores a bcrypt hash for the named user.
func (s *UserStore) SetPassword(name string, hash []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byName[name]
	if !ok {
		slog.Error("user store: SetPassword: user not found", "username", name)
		return
	}
	u.PasswordHash = hash
	slog.Info("user store: password hash set", "username", name)
}

// AddCredential appends a new credential to the named user.
func (s *UserStore) AddCredential(name string, cred webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.byName[name]
	if u == nil {
		slog.Error("user store: AddCredential called for unknown user", "username", name)
		return
	}
	u.Credentials = append(u.Credentials, cred)
	slog.Info("user store: credential added",
		"username", name,
		"credential_id", hex.EncodeToString(cred.ID),
		"total_credentials", len(u.Credentials),
	)
}

// UpdateCredential replaces an existing credential (e.g. updated sign counter).
func (s *UserStore) UpdateCredential(userID []byte, updated *webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[string(userID)]
	if !ok {
		slog.Error("user store: UpdateCredential called for unknown user", "user_id", hex.EncodeToString(userID))
		return
	}
	for i, c := range u.Credentials {
		if string(c.ID) == string(updated.ID) {
			oldCount := c.Authenticator.SignCount
			u.Credentials[i] = *updated
			slog.Info("user store: credential sign counter updated",
				"username", u.Name,
				"credential_id", hex.EncodeToString(updated.ID),
				"old_sign_count", oldCount,
				"new_sign_count", updated.Authenticator.SignCount,
				"clone_warning", updated.Authenticator.CloneWarning,
			)
			return
		}
	}
	slog.Warn("user store: UpdateCredential: credential ID not found on user",
		"username", u.Name,
		"credential_id", hex.EncodeToString(updated.ID),
	)
}
