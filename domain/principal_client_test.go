package domain

import (
	"errors"
	"testing"
	"time"
)

// TestNewPrincipal verifies principal construction and normalization.
func TestNewPrincipal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	principal, err := NewPrincipal(PrincipalInput{
		ID:          " principal-1 ",
		Type:        PrincipalTypeAgent,
		DisplayName: " Agent One ",
		Aliases:     []string{"alpha", "alpha", " beta "},
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}

	if principal.ID != "principal-1" {
		t.Fatalf("principal.ID = %q, want principal-1", principal.ID)
	}
	if principal.DisplayName != "Agent One" {
		t.Fatalf("principal.DisplayName = %q, want Agent One", principal.DisplayName)
	}
	if len(principal.Aliases) != 2 {
		t.Fatalf("len(principal.Aliases) = %d, want 2", len(principal.Aliases))
	}
	if !principal.IsActive() {
		t.Fatal("principal should default to active")
	}
}

// TestNewPrincipalRejectsInvalidValues verifies principal validation failures.
func TestNewPrincipalRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   PrincipalInput
		want error
	}{
		{name: "missing id", in: PrincipalInput{Type: PrincipalTypeUser, DisplayName: "User"}, want: ErrInvalidID},
		{name: "missing type", in: PrincipalInput{ID: "p1", DisplayName: "User"}, want: ErrInvalidPrincipalType},
		{name: "missing display name", in: PrincipalInput{ID: "p1", Type: PrincipalTypeUser}, want: ErrInvalidDisplayName},
		{name: "invalid status", in: PrincipalInput{ID: "p1", Type: PrincipalTypeUser, DisplayName: "User", Status: Status("bogus")}, want: ErrInvalidStatus},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewPrincipal(test.in, now)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewPrincipal() error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestPrincipalUpdateStatus verifies principal status transitions.
func TestPrincipalUpdateStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	principal, err := NewPrincipal(PrincipalInput{
		ID:          "p1",
		Type:        PrincipalTypeUser,
		DisplayName: "User",
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	if err := principal.UpdateStatus(StatusDisabled, now.Add(time.Minute)); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	if principal.IsActive() {
		t.Fatal("principal should be disabled")
	}
}

// TestNewClient verifies client construction and normalization.
func TestNewClient(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	client, err := NewClient(ClientInput{
		ID:          " client-1 ",
		DisplayName: " Demo Client ",
		Type:        " MCP ",
	}, now)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.ID != "client-1" {
		t.Fatalf("client.ID = %q, want client-1", client.ID)
	}
	if client.DisplayName != "Demo Client" {
		t.Fatalf("client.DisplayName = %q, want Demo Client", client.DisplayName)
	}
	if client.Type != "mcp" {
		t.Fatalf("client.Type = %q, want mcp", client.Type)
	}
	if !client.IsActive() {
		t.Fatal("client should default to active")
	}
}

// TestNewClientRejectsInvalidValues verifies client validation failures.
func TestNewClientRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   ClientInput
		want error
	}{
		{name: "missing id", in: ClientInput{DisplayName: "Client", Type: "mcp"}, want: ErrInvalidID},
		{name: "missing display name", in: ClientInput{ID: "c1", Type: "mcp"}, want: ErrInvalidDisplayName},
		{name: "missing type", in: ClientInput{ID: "c1", DisplayName: "Client"}, want: ErrInvalidClientType},
		{name: "invalid status", in: ClientInput{ID: "c1", DisplayName: "Client", Type: "mcp", Status: Status("bogus")}, want: ErrInvalidStatus},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewClient(test.in, now)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewClient() error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestClientUpdateStatus verifies client status transitions.
func TestClientUpdateStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	client, err := NewClient(ClientInput{
		ID:          "c1",
		DisplayName: "Client",
		Type:        "cli",
	}, now)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.UpdateStatus(StatusDisabled, now.Add(time.Minute)); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	if client.IsActive() {
		t.Fatal("client should be disabled")
	}
}
