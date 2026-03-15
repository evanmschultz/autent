package domain

import (
	"errors"
	"testing"
	"time"
)

// TestNewSession verifies session construction and lifecycle helpers.
func TestNewSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	session, err := NewSession(SessionInput{
		ID:          "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
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

// TestNewSessionRejectsInvalidValues verifies session validation failures.
func TestNewSessionRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   SessionInput
		want error
	}{
		{name: "missing id", in: SessionInput{PrincipalID: "p1", ClientID: "c1", SecretHash: []byte("hash"), ExpiresAt: now.Add(time.Hour)}, want: ErrInvalidID},
		{name: "missing hash", in: SessionInput{ID: "s1", PrincipalID: "p1", ClientID: "c1", ExpiresAt: now.Add(time.Hour)}, want: ErrInvalidSessionSecretHash},
		{name: "expired", in: SessionInput{ID: "s1", PrincipalID: "p1", ClientID: "c1", SecretHash: []byte("hash"), ExpiresAt: now}, want: ErrInvalidSessionExpiry},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewSession(test.in, now)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewSession() error = %v, want %v", err, test.want)
			}
		})
	}
}
