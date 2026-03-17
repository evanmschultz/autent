package autent

import "github.com/evanmschultz/autent/app"

// SessionSecretManager re-exports the primary session secret contract for embedders.
type SessionSecretManager = app.SessionSecretManager

// Config re-exports the primary service configuration type for embedders.
type Config = app.Config

// Service re-exports the primary autent service type for embedders.
type Service = app.Service

// SessionView re-exports the caller-safe session view returned by the service.
type SessionView = app.SessionView

// SessionState re-exports the caller-facing session state filter values.
type SessionState = app.SessionState

const (
	// SessionStateAny re-exports the unfiltered session lifecycle selector.
	SessionStateAny = app.SessionStateAny
	// SessionStateActive re-exports the active-session lifecycle selector.
	SessionStateActive = app.SessionStateActive
	// SessionStateRevoked re-exports the revoked-session lifecycle selector.
	SessionStateRevoked = app.SessionStateRevoked
	// SessionStateExpired re-exports the expired-session lifecycle selector.
	SessionStateExpired = app.SessionStateExpired
)

// SessionFilter re-exports the caller-facing session list filter.
type SessionFilter = app.SessionFilter

// IssuedSession re-exports the issued-session bundle returned by the service.
type IssuedSession = app.IssuedSession

// ValidatedSession re-exports the validated-session bundle returned by the service.
type ValidatedSession = app.ValidatedSession

// IssueSessionInput re-exports the session-issuance input shape.
type IssueSessionInput = app.IssueSessionInput

// AuthorizeInput re-exports the authorization input shape.
type AuthorizeInput = app.AuthorizeInput

// RequestGrantInput re-exports the grant-request input shape.
type RequestGrantInput = app.RequestGrantInput

// ResolveGrantInput re-exports the grant-resolution input shape.
type ResolveGrantInput = app.ResolveGrantInput

// UpdatePrincipalStatusInput re-exports the principal-status update input shape.
type UpdatePrincipalStatusInput = app.UpdatePrincipalStatusInput

// UpdateClientStatusInput re-exports the client-status update input shape.
type UpdateClientStatusInput = app.UpdateClientStatusInput

// NewService constructs the primary autent application service.
func NewService(cfg Config) (*Service, error) {
	return app.NewService(cfg)
}
