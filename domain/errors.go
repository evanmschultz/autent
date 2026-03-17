package domain

import "errors"

var (
	// ErrAlreadyExists reports that a unique record already exists.
	ErrAlreadyExists = errors.New("already exists")
	// ErrInvalidID reports that a required identifier is blank or malformed.
	ErrInvalidID = errors.New("invalid id")
	// ErrInvalidDisplayName reports that a required display name is blank.
	ErrInvalidDisplayName = errors.New("invalid display name")
	// ErrInvalidStatus reports that a status value is unsupported.
	ErrInvalidStatus = errors.New("invalid status")
	// ErrInvalidPrincipalType reports that a principal type is unsupported.
	ErrInvalidPrincipalType = errors.New("invalid principal type")
	// ErrInvalidClientType reports that a client type is unsupported.
	ErrInvalidClientType = errors.New("invalid client type")
	// ErrInvalidSessionExpiry reports that a session expiry is invalid.
	ErrInvalidSessionExpiry = errors.New("invalid session expiry")
	// ErrInvalidSessionSecretHash reports that a session secret hash is missing.
	ErrInvalidSessionSecretHash = errors.New("invalid session secret hash")
	// ErrInvalidSessionSecret reports that a presented session secret is invalid.
	ErrInvalidSessionSecret = errors.New("invalid session secret")
	// ErrSessionNotFound reports that a session record does not exist.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionExpired reports that a session is expired.
	ErrSessionExpired = errors.New("session expired")
	// ErrSessionRevoked reports that a session is revoked.
	ErrSessionRevoked = errors.New("session revoked")
	// ErrPrincipalNotFound reports that a principal record does not exist.
	ErrPrincipalNotFound = errors.New("principal not found")
	// ErrPrincipalDisabled reports that a principal is disabled.
	ErrPrincipalDisabled = errors.New("principal disabled")
	// ErrClientNotFound reports that a client record does not exist.
	ErrClientNotFound = errors.New("client not found")
	// ErrClientDisabled reports that a client is disabled.
	ErrClientDisabled = errors.New("client disabled")
	// ErrInvalidAction reports that an action is blank.
	ErrInvalidAction = errors.New("invalid action")
	// ErrInvalidResource reports that a resource reference is incomplete.
	ErrInvalidResource = errors.New("invalid resource")
	// ErrInvalidPattern reports that a string pattern is malformed.
	ErrInvalidPattern = errors.New("invalid pattern")
	// ErrInvalidCondition reports that a rule condition is malformed.
	ErrInvalidCondition = errors.New("invalid condition")
	// ErrInvalidRule reports that a policy rule is malformed.
	ErrInvalidRule = errors.New("invalid rule")
	// ErrGrantNotFound reports that a grant record does not exist.
	ErrGrantNotFound = errors.New("grant not found")
	// ErrGrantExpired reports that a grant is expired.
	ErrGrantExpired = errors.New("grant expired")
	// ErrInvalidGrantState reports that a grant state is unsupported or invalid for the transition.
	ErrInvalidGrantState = errors.New("invalid grant state")
	// ErrInvalidFilter reports that a list or query filter is malformed.
	ErrInvalidFilter = errors.New("invalid filter")
	// ErrInvalidConfig reports that service wiring is incomplete or malformed.
	ErrInvalidConfig = errors.New("invalid config")
)
