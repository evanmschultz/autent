package domain

import "time"

// AuditEventType identifies one auditable operation.
type AuditEventType string

const (
	// AuditEventPrincipalCreated records principal creation.
	AuditEventPrincipalCreated AuditEventType = "principal_created"
	// AuditEventClientCreated records client creation.
	AuditEventClientCreated AuditEventType = "client_created"
	// AuditEventSessionIssued records session issuance.
	AuditEventSessionIssued AuditEventType = "session_issued"
	// AuditEventSessionValidated records successful session validation.
	AuditEventSessionValidated AuditEventType = "session_validated"
	// AuditEventSessionRevoked records session revocation.
	AuditEventSessionRevoked AuditEventType = "session_revoked"
	// AuditEventAuthzAllowed records an allow decision.
	AuditEventAuthzAllowed AuditEventType = "authz_allowed"
	// AuditEventAuthzDenied records a deny-like decision.
	AuditEventAuthzDenied AuditEventType = "authz_denied"
	// AuditEventGrantRequested records grant creation.
	AuditEventGrantRequested AuditEventType = "grant_requested"
	// AuditEventGrantApproved records grant approval.
	AuditEventGrantApproved AuditEventType = "grant_approved"
	// AuditEventGrantDenied records grant denial.
	AuditEventGrantDenied AuditEventType = "grant_denied"
	// AuditEventGrantCanceled records grant cancellation.
	AuditEventGrantCanceled AuditEventType = "grant_canceled"
	// AuditEventPolicyMutated records policy replacement.
	AuditEventPolicyMutated AuditEventType = "policy_mutated"
)

// AuditEvent stores one append-only audit record.
type AuditEvent struct {
	ID           string
	Type         AuditEventType
	OccurredAt   time.Time
	PrincipalID  string
	ClientID     string
	SessionID    string
	Action       Action
	Resource     ResourceRef
	DecisionCode DecisionCode
	Reason       string
	Metadata     map[string]string
}

// AuditFilter narrows audit event listing queries.
type AuditFilter struct {
	PrincipalID string
	ClientID    string
	SessionID   string
	Type        AuditEventType
	Limit       int
}
