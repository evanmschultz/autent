package domain

import (
	"errors"
	"testing"
	"time"
)

// TestNewStoredSession verifies stored-session construction and lifecycle helpers.
func TestNewStoredSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	session, err := NewStoredSession(StoredSessionInput{
		ID:          "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewStoredSession() error = %v", err)
	}

	if err := session.CanUse(now.Add(30 * time.Minute)); err != nil {
		t.Fatalf("session.CanUse() error = %v", err)
	}
	session.Touch(now.Add(10 * time.Minute))
	if got := session.LastSeenAt; !got.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("session.LastSeenAt = %v, want %v", got, now.Add(10*time.Minute))
	}
	session.Revoke("manual revoke", now.Add(20*time.Minute))
	if !session.IsRevoked() {
		t.Fatal("session should be revoked")
	}
	if err := session.CanUse(now.Add(30 * time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("session.CanUse() error = %v, want ErrSessionRevoked", err)
	}
}

// TestNewStoredSessionRejectsInvalidValues verifies stored-session validation failures.
func TestNewStoredSessionRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   StoredSessionInput
		want error
	}{
		{name: "missing id", in: StoredSessionInput{PrincipalID: "p1", ClientID: "c1", SecretHash: []byte("hash"), ExpiresAt: now.Add(time.Hour)}, want: ErrInvalidID},
		{name: "missing hash", in: StoredSessionInput{ID: "s1", PrincipalID: "p1", ClientID: "c1", ExpiresAt: now.Add(time.Hour)}, want: ErrInvalidSessionSecretHash},
		{name: "expired", in: StoredSessionInput{ID: "s1", PrincipalID: "p1", ClientID: "c1", SecretHash: []byte("hash"), ExpiresAt: now}, want: ErrInvalidSessionExpiry},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewStoredSession(test.in, now)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewStoredSession() error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestStoredSessionViewRedactsVerifierState verifies stored sessions can be converted into caller-safe views.
func TestStoredSessionViewRedactsVerifierState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	session, err := NewStoredSession(StoredSessionInput{
		ID:          "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
		Metadata: map[string]string{
			"scope": "current",
		},
	}, now)
	if err != nil {
		t.Fatalf("NewStoredSession() error = %v", err)
	}

	view := session.View()
	if view.ID != session.ID || view.PrincipalID != session.PrincipalID || view.ClientID != session.ClientID {
		t.Fatalf("view = %+v, want ids copied from session", view)
	}
	if view.Metadata["scope"] != "current" {
		t.Fatalf("view.Metadata = %+v, want copied metadata", view.Metadata)
	}

	view.Metadata["scope"] = "changed"
	if session.Metadata["scope"] != "current" {
		t.Fatalf("session.Metadata mutated through view: %+v", session.Metadata)
	}
}
