package domain

import (
	"errors"
	"testing"
	"time"
)

// TestGrantLifecycle verifies grant construction and resolution transitions.
func TestGrantLifecycle(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	grant, err := NewGrant(GrantInput{
		ID:          "grant-1",
		SessionID:   "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		Action:      "mutate",
		Resource: ResourceRef{
			Namespace: "project:demo",
			Type:      "tool",
			ID:        "gopls.rename",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := grant.Approve("reviewer-1", "approved", 1, now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Approve() error = %v", err)
	}
	if err := grant.CanAuthorize(now.Add(2 * time.Minute)); err != nil {
		t.Fatalf("grant.CanAuthorize() error = %v", err)
	}
	if err := grant.Redeem(now.Add(2 * time.Minute)); err != nil {
		t.Fatalf("grant.Redeem() error = %v", err)
	}
	if err := grant.CanAuthorize(now.Add(3 * time.Minute)); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("grant.CanAuthorize(after redeem) error = %v, want ErrGrantExpired", err)
	}
	if err := grant.Deny("reviewer-2", "deny", now.Add(3*time.Minute)); !errors.Is(err, ErrInvalidGrantState) {
		t.Fatalf("grant.Deny() error = %v, want ErrInvalidGrantState", err)
	}
}

// TestGrantExpire verifies pending grants transition to expired when stale.
func TestGrantExpire(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	grant, err := NewGrant(GrantInput{
		ID:          "grant-1",
		SessionID:   "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		Action:      "mutate",
		Resource: ResourceRef{
			Type: "tool",
			ID:   "gopls.rename",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Minute),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	grant.Expire(now.Add(2 * time.Minute))
	if grant.State != GrantStateExpired {
		t.Fatalf("grant.State = %q, want expired", grant.State)
	}
}
