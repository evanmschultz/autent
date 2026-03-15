package domain

import (
	"strings"
	"time"
)

// GrantState identifies the lifecycle state of a grant.
type GrantState string

const (
	// GrantStatePending indicates a grant is awaiting a decision.
	GrantStatePending GrantState = "pending"
	// GrantStateApproved indicates a grant has been approved.
	GrantStateApproved GrantState = "approved"
	// GrantStateDenied indicates a grant has been denied.
	GrantStateDenied GrantState = "denied"
	// GrantStateExpired indicates a grant has expired.
	GrantStateExpired GrantState = "expired"
	// GrantStateCanceled indicates a grant has been canceled.
	GrantStateCanceled GrantState = "canceled"
)

// GrantInput carries fields used to construct a new grant request.
type GrantInput struct {
	ID             string
	SessionID      string
	PrincipalID    string
	ClientID       string
	Action         Action
	Resource       ResourceRef
	Fingerprint    string
	RequestedScope map[string]string
	Reason         string
	ExpiresAt      time.Time
}

// GrantQuery identifies one grant lookup by normalized request fingerprint.
type GrantQuery struct {
	PrincipalID string
	ClientID    string
	Action      Action
	Resource    ResourceRef
	Fingerprint string
	State       GrantState
}

// Grant stores one explicit approval request and resolution.
type Grant struct {
	ID             string
	SessionID      string
	PrincipalID    string
	ClientID       string
	Action         Action
	Resource       ResourceRef
	Fingerprint    string
	RequestedScope map[string]string
	Reason         string
	State          GrantState
	UsageLimit     int
	UsageCount     int
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ResolvedAt     *time.Time
	ResolvedBy     string
	ResolutionNote string
}

// NewGrant validates and constructs a grant request.
func NewGrant(in GrantInput, now time.Time) (Grant, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return Grant{}, ErrInvalidID
	}
	if strings.TrimSpace(in.PrincipalID) == "" || strings.TrimSpace(in.ClientID) == "" {
		return Grant{}, ErrInvalidID
	}
	if err := NormalizeAction(in.Action).Validate(); err != nil {
		return Grant{}, err
	}
	if err := in.Resource.Validate(); err != nil {
		return Grant{}, err
	}
	fingerprint := strings.TrimSpace(in.Fingerprint)
	if fingerprint == "" {
		return Grant{}, ErrInvalidID
	}
	if in.ExpiresAt.IsZero() || !in.ExpiresAt.UTC().After(now.UTC()) {
		return Grant{}, ErrGrantExpired
	}
	return Grant{
		ID:             id,
		SessionID:      strings.TrimSpace(in.SessionID),
		PrincipalID:    strings.TrimSpace(in.PrincipalID),
		ClientID:       strings.TrimSpace(in.ClientID),
		Action:         NormalizeAction(in.Action),
		Resource:       in.Resource,
		Fingerprint:    fingerprint,
		RequestedScope: copyMap(in.RequestedScope),
		Reason:         strings.TrimSpace(in.Reason),
		State:          GrantStatePending,
		CreatedAt:      now.UTC(),
		ExpiresAt:      in.ExpiresAt.UTC(),
	}, nil
}

// IsExpired reports whether the grant is expired at the provided time.
func (g Grant) IsExpired(now time.Time) bool {
	return !now.UTC().Before(g.ExpiresAt.UTC())
}

// CanAuthorize reports whether the grant can authorize a request.
func (g Grant) CanAuthorize(now time.Time) error {
	if g.IsExpired(now) {
		return ErrGrantExpired
	}
	if g.State != GrantStateApproved {
		return ErrInvalidGrantState
	}
	if g.UsageLimit > 0 && g.UsageCount >= g.UsageLimit {
		return ErrGrantExpired
	}
	return nil
}

// Approve transitions a grant to approved.
func (g *Grant) Approve(resolvedBy, note string, usageLimit int, now time.Time) error {
	if g == nil {
		return ErrInvalidGrantState
	}
	if g.State != GrantStatePending {
		return ErrInvalidGrantState
	}
	ts := now.UTC()
	g.State = GrantStateApproved
	g.UsageLimit = usageLimit
	g.ResolvedAt = &ts
	g.ResolvedBy = strings.TrimSpace(resolvedBy)
	g.ResolutionNote = strings.TrimSpace(note)
	return nil
}

// Deny transitions a grant to denied.
func (g *Grant) Deny(resolvedBy, note string, now time.Time) error {
	if g == nil {
		return ErrInvalidGrantState
	}
	if g.State != GrantStatePending {
		return ErrInvalidGrantState
	}
	ts := now.UTC()
	g.State = GrantStateDenied
	g.ResolvedAt = &ts
	g.ResolvedBy = strings.TrimSpace(resolvedBy)
	g.ResolutionNote = strings.TrimSpace(note)
	return nil
}

// Cancel transitions a grant to canceled.
func (g *Grant) Cancel(resolvedBy, note string, now time.Time) error {
	if g == nil {
		return ErrInvalidGrantState
	}
	if g.State != GrantStatePending {
		return ErrInvalidGrantState
	}
	ts := now.UTC()
	g.State = GrantStateCanceled
	g.ResolvedAt = &ts
	g.ResolvedBy = strings.TrimSpace(resolvedBy)
	g.ResolutionNote = strings.TrimSpace(note)
	return nil
}

// Expire transitions a grant to expired when it is stale.
func (g *Grant) Expire(now time.Time) {
	if g == nil || g.State != GrantStatePending {
		return
	}
	if g.IsExpired(now) {
		g.State = GrantStateExpired
	}
}

// Redeem records one successful authorization through the grant.
func (g *Grant) Redeem(now time.Time) error {
	if g == nil {
		return ErrInvalidGrantState
	}
	if err := g.CanAuthorize(now); err != nil {
		return err
	}
	g.UsageCount++
	return nil
}
