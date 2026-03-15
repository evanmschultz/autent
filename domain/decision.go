package domain

// DecisionCode identifies an authorization decision outcome.
type DecisionCode string

const (
	// DecisionAllow indicates the request is allowed.
	DecisionAllow DecisionCode = "allow"
	// DecisionDeny indicates the request is denied.
	DecisionDeny DecisionCode = "deny"
	// DecisionGrantRequired indicates the request may proceed only after explicit grant approval.
	DecisionGrantRequired DecisionCode = "grant_required"
	// DecisionSessionRequired indicates a valid session is required.
	DecisionSessionRequired DecisionCode = "session_required"
	// DecisionSessionExpired indicates the presented session is expired.
	DecisionSessionExpired DecisionCode = "session_expired"
	// DecisionInvalid indicates the request or session secret is invalid.
	DecisionInvalid DecisionCode = "invalid"
)

// Decision stores the result of an authorization evaluation.
type Decision struct {
	Code         DecisionCode
	Reason       string
	RuleIDs      []string
	GrantID      string
	AuditEventID string
}
