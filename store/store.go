// Package store contains shared persistence ports for autent.
package store

import (
	"context"

	"github.com/evanmschultz/autent/domain"
)

// PrincipalStore persists principals.
type PrincipalStore interface {
	CreatePrincipal(ctx context.Context, principal domain.Principal) error
	GetPrincipal(ctx context.Context, id string) (domain.Principal, error)
	ListPrincipals(ctx context.Context) ([]domain.Principal, error)
}

// ClientStore persists clients.
type ClientStore interface {
	CreateClient(ctx context.Context, client domain.Client) error
	GetClient(ctx context.Context, id string) (domain.Client, error)
	ListClients(ctx context.Context) ([]domain.Client, error)
}

// SessionStore persists sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, session domain.Session) error
	GetSession(ctx context.Context, id string) (domain.Session, error)
	UpdateSession(ctx context.Context, session domain.Session) error
	ListSessions(ctx context.Context) ([]domain.Session, error)
}

// PolicyStore persists authorization rules.
type PolicyStore interface {
	ReplaceRules(ctx context.Context, rules []domain.Rule) error
	ListRules(ctx context.Context) ([]domain.Rule, error)
}

// GrantStore persists grant lifecycle state.
type GrantStore interface {
	CreateGrant(ctx context.Context, grant domain.Grant) error
	GetGrant(ctx context.Context, id string) (domain.Grant, error)
	UpdateGrant(ctx context.Context, grant domain.Grant) error
	FindGrant(ctx context.Context, query domain.GrantQuery) (domain.Grant, error)
	ListGrants(ctx context.Context) ([]domain.Grant, error)
}

// AuditStore persists append-only audit events.
type AuditStore interface {
	AppendAuditEvent(ctx context.Context, event domain.AuditEvent) error
	ListAuditEvents(ctx context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error)
}

// Repository combines all store ports and supports transactional work.
type Repository interface {
	PrincipalStore
	ClientStore
	SessionStore
	PolicyStore
	GrantStore
	AuditStore

	WithinTx(ctx context.Context, fn func(Repository) error) error
}
