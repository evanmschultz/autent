package domain

import (
	"strings"
	"time"
)

// StoredSessionInput carries fields used to construct one stored session record.
type StoredSessionInput struct {
	ID          string
	PrincipalID string
	ClientID    string
	SecretHash  []byte
	ExpiresAt   time.Time
	Metadata    map[string]string
}

// Session stores caller-safe session metadata for one authenticated principal-client binding.
type Session struct {
	ID               string
	PrincipalID      string
	ClientID         string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	LastSeenAt       time.Time
	RevokedAt        *time.Time
	RevocationReason string
	Metadata         map[string]string
}

// StoredSession stores verifier-side session state, including the hashed session secret.
type StoredSession struct {
	Session
	SecretHash []byte
}

// View returns the caller-safe session metadata for one stored session record.
func (s StoredSession) View() Session {
	return Session{
		ID:               s.ID,
		PrincipalID:      s.PrincipalID,
		ClientID:         s.ClientID,
		IssuedAt:         s.IssuedAt,
		ExpiresAt:        s.ExpiresAt,
		LastSeenAt:       s.LastSeenAt,
		RevokedAt:        copyTimePtr(s.RevokedAt),
		RevocationReason: s.RevocationReason,
		Metadata:         copyMap(s.Metadata),
	}
}

// NewStoredSession validates and constructs one stored session record.
func NewStoredSession(in StoredSessionInput, now time.Time) (StoredSession, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return StoredSession{}, ErrInvalidID
	}
	principalID := strings.TrimSpace(in.PrincipalID)
	if principalID == "" {
		return StoredSession{}, ErrInvalidID
	}
	clientID := strings.TrimSpace(in.ClientID)
	if clientID == "" {
		return StoredSession{}, ErrInvalidID
	}
	if len(in.SecretHash) == 0 {
		return StoredSession{}, ErrInvalidSessionSecretHash
	}
	if in.ExpiresAt.IsZero() || !in.ExpiresAt.UTC().After(now.UTC()) {
		return StoredSession{}, ErrInvalidSessionExpiry
	}

	ts := now.UTC()
	secretHash := make([]byte, len(in.SecretHash))
	copy(secretHash, in.SecretHash)
	return StoredSession{
		Session: Session{
			ID:          id,
			PrincipalID: principalID,
			ClientID:    clientID,
			IssuedAt:    ts,
			ExpiresAt:   in.ExpiresAt.UTC(),
			LastSeenAt:  ts,
			Metadata:    copyMap(in.Metadata),
		},
		SecretHash: secretHash,
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
