package domain

import (
	"strings"
	"time"
)

// SessionInput carries fields used to issue a session.
type SessionInput struct {
	ID          string
	PrincipalID string
	ClientID    string
	SecretHash  []byte
	ExpiresAt   time.Time
	Metadata    map[string]string
}

// Session stores an authenticated runtime binding between a principal and a client.
type Session struct {
	ID               string
	PrincipalID      string
	ClientID         string
	SecretHash       []byte
	IssuedAt         time.Time
	ExpiresAt        time.Time
	LastSeenAt       time.Time
	RevokedAt        *time.Time
	RevocationReason string
	Metadata         map[string]string
}

// NewSession validates and constructs an issued session.
func NewSession(in SessionInput, now time.Time) (Session, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return Session{}, ErrInvalidID
	}
	principalID := strings.TrimSpace(in.PrincipalID)
	if principalID == "" {
		return Session{}, ErrInvalidID
	}
	clientID := strings.TrimSpace(in.ClientID)
	if clientID == "" {
		return Session{}, ErrInvalidID
	}
	if len(in.SecretHash) == 0 {
		return Session{}, ErrInvalidSessionSecretHash
	}
	if in.ExpiresAt.IsZero() || !in.ExpiresAt.UTC().After(now.UTC()) {
		return Session{}, ErrInvalidSessionExpiry
	}

	ts := now.UTC()
	secretHash := make([]byte, len(in.SecretHash))
	copy(secretHash, in.SecretHash)
	return Session{
		ID:          id,
		PrincipalID: principalID,
		ClientID:    clientID,
		SecretHash:  secretHash,
		IssuedAt:    ts,
		ExpiresAt:   in.ExpiresAt.UTC(),
		LastSeenAt:  ts,
		Metadata:    copyMap(in.Metadata),
	}, nil
}

// IsExpired reports whether the session is expired.
func (s Session) IsExpired(now time.Time) bool {
	return !now.UTC().Before(s.ExpiresAt.UTC())
}

// IsRevoked reports whether the session is revoked.
func (s Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

// CanUse reports whether the session can be used at the provided time.
func (s Session) CanUse(now time.Time) error {
	if s.IsRevoked() {
		return ErrSessionRevoked
	}
	if s.IsExpired(now) {
		return ErrSessionExpired
	}
	return nil
}

// Touch updates the session last-seen timestamp.
func (s *Session) Touch(now time.Time) {
	if s == nil {
		return
	}
	s.LastSeenAt = now.UTC()
}

// Revoke marks the session as revoked.
func (s *Session) Revoke(reason string, now time.Time) {
	if s == nil {
		return
	}
	ts := now.UTC()
	s.RevokedAt = &ts
	s.RevocationReason = strings.TrimSpace(reason)
}
