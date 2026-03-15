// Package app contains autent application use-cases and orchestration ports.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/evanmschultz/autent/domain"
	"github.com/evanmschultz/autent/store"
)

// SessionSecretManager issues and verifies opaque session secrets.
type SessionSecretManager interface {
	Issue() (string, []byte, error)
	Verify(secret string, hash []byte) bool
}

// Config provides the dependencies required by the auth service.
type Config struct {
	Repository  store.Repository
	Secrets     SessionSecretManager
	IDGenerator func() string
	Clock       func() time.Time
	SessionTTL  time.Duration
	GrantTTL    time.Duration
}

// IssuedSession bundles a persisted session with the returned opaque secret.
type IssuedSession struct {
	Session domain.Session
	Secret  string
}

// ValidatedSession bundles a valid session with its principal and client.
type ValidatedSession struct {
	Session   domain.Session
	Principal domain.Principal
	Client    domain.Client
}

// IssueSessionInput carries fields used to issue a new session.
type IssueSessionInput struct {
	PrincipalID string
	ClientID    string
	TTL         time.Duration
	Metadata    map[string]string
}

// AuthorizeInput carries one authorization request into the service.
type AuthorizeInput struct {
	SessionID     string
	SessionSecret string
	Action        domain.Action
	Resource      domain.ResourceRef
	Context       map[string]string
}

// RequestGrantInput carries fields used to create a grant request.
type RequestGrantInput struct {
	SessionID     string
	SessionSecret string
	Action        domain.Action
	Resource      domain.ResourceRef
	Context       map[string]string
	Reason        string
	TTL           time.Duration
}

// ResolveGrantInput carries fields used to resolve an existing grant.
type ResolveGrantInput struct {
	GrantID    string
	Approve    bool
	Actor      string
	Note       string
	UsageLimit int
}

// Service orchestrates autent use-cases across domain types and ports.
type Service struct {
	repo       store.Repository
	secrets    SessionSecretManager
	idGen      func() string
	clock      func() time.Time
	sessionTTL time.Duration
	grantTTL   time.Duration
}

// NewService validates dependencies and constructs the app service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Repository == nil {
		return nil, fmt.Errorf("repository: %w", domain.ErrInvalidConfig)
	}
	if cfg.Secrets == nil {
		return nil, fmt.Errorf("secrets: %w", domain.ErrInvalidConfig)
	}
	if cfg.IDGenerator == nil {
		return nil, fmt.Errorf("id generator: %w", domain.ErrInvalidConfig)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	if cfg.GrantTTL <= 0 {
		cfg.GrantTTL = time.Hour
	}
	return &Service{
		repo:       cfg.Repository,
		secrets:    cfg.Secrets,
		idGen:      cfg.IDGenerator,
		clock:      cfg.Clock,
		sessionTTL: cfg.SessionTTL,
		grantTTL:   cfg.GrantTTL,
	}, nil
}

// RegisterPrincipal validates and stores a principal.
func (s *Service) RegisterPrincipal(ctx context.Context, in domain.PrincipalInput) (domain.Principal, error) {
	if strings.TrimSpace(in.ID) == "" {
		in.ID = s.idGen()
	}
	principal, err := domain.NewPrincipal(in, s.clock())
	if err != nil {
		return domain.Principal{}, err
	}
	err = s.repo.WithinTx(ctx, func(tx store.Repository) error {
		if err := tx.CreatePrincipal(ctx, principal); err != nil {
			return err
		}
		_, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:          s.idGen(),
			Type:        domain.AuditEventPrincipalCreated,
			OccurredAt:  s.clock().UTC(),
			PrincipalID: principal.ID,
			Reason:      "principal_created",
		})
		return err
	})
	if err != nil {
		return domain.Principal{}, err
	}
	return principal, nil
}

// RegisterClient validates and stores a client.
func (s *Service) RegisterClient(ctx context.Context, in domain.ClientInput) (domain.Client, error) {
	if strings.TrimSpace(in.ID) == "" {
		in.ID = s.idGen()
	}
	client, err := domain.NewClient(in, s.clock())
	if err != nil {
		return domain.Client{}, err
	}
	err = s.repo.WithinTx(ctx, func(tx store.Repository) error {
		if err := tx.CreateClient(ctx, client); err != nil {
			return err
		}
		_, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:         s.idGen(),
			Type:       domain.AuditEventClientCreated,
			OccurredAt: s.clock().UTC(),
			ClientID:   client.ID,
			Reason:     "client_created",
		})
		return err
	})
	if err != nil {
		return domain.Client{}, err
	}
	return client, nil
}

// ListPrincipals returns all stored principals.
func (s *Service) ListPrincipals(ctx context.Context) ([]domain.Principal, error) {
	return s.repo.ListPrincipals(ctx)
}

// ListClients returns all stored clients.
func (s *Service) ListClients(ctx context.Context) ([]domain.Client, error) {
	return s.repo.ListClients(ctx)
}

// ReplaceRules validates and replaces the persisted rule set.
func (s *Service) ReplaceRules(ctx context.Context, rules []domain.Rule) error {
	normalized := make([]domain.Rule, len(rules))
	for i, rule := range rules {
		validated, err := domain.ValidateAndNormalizeRule(rule)
		if err != nil {
			return err
		}
		normalized[i] = validated
	}
	sortRules(normalized)
	return s.repo.WithinTx(ctx, func(tx store.Repository) error {
		if err := tx.ReplaceRules(ctx, normalized); err != nil {
			return err
		}
		_, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:         s.idGen(),
			Type:       domain.AuditEventPolicyMutated,
			OccurredAt: s.clock().UTC(),
			Reason:     "policy_replaced",
			Metadata: map[string]string{
				"rule_count": fmt.Sprintf("%d", len(normalized)),
			},
		})
		return err
	})
}

// PutRule upserts one rule by replacing the current set with one updated copy.
func (s *Service) PutRule(ctx context.Context, rule domain.Rule) (domain.Rule, error) {
	validated, err := domain.ValidateAndNormalizeRule(rule)
	if err != nil {
		return domain.Rule{}, err
	}
	existing, err := s.repo.ListRules(ctx)
	if err != nil {
		return domain.Rule{}, err
	}
	replaced := false
	for i := range existing {
		if existing[i].ID == validated.ID {
			existing[i] = validated
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, validated)
	}
	if err := s.ReplaceRules(ctx, existing); err != nil {
		return domain.Rule{}, err
	}
	return validated, nil
}

// ListRules returns the stored rule set.
func (s *Service) ListRules(ctx context.Context) ([]domain.Rule, error) {
	return s.repo.ListRules(ctx)
}

// IssueSession creates a new session for an active principal and client.
func (s *Service) IssueSession(ctx context.Context, in IssueSessionInput) (IssuedSession, error) {
	principal, err := s.repo.GetPrincipal(ctx, strings.TrimSpace(in.PrincipalID))
	if err != nil {
		return IssuedSession{}, err
	}
	if !principal.IsActive() {
		return IssuedSession{}, domain.ErrPrincipalDisabled
	}
	client, err := s.repo.GetClient(ctx, strings.TrimSpace(in.ClientID))
	if err != nil {
		return IssuedSession{}, err
	}
	if !client.IsActive() {
		return IssuedSession{}, domain.ErrClientDisabled
	}

	secret, hash, err := s.secrets.Issue()
	if err != nil {
		return IssuedSession{}, err
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.sessionTTL
	}
	session, err := domain.NewSession(domain.SessionInput{
		ID:          s.idGen(),
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SecretHash:  hash,
		ExpiresAt:   s.clock().Add(ttl),
		Metadata:    copyContext(in.Metadata),
	}, s.clock())
	if err != nil {
		return IssuedSession{}, err
	}
	err = s.repo.WithinTx(ctx, func(tx store.Repository) error {
		if err := tx.CreateSession(ctx, session); err != nil {
			return err
		}
		_, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:          s.idGen(),
			Type:        domain.AuditEventSessionIssued,
			OccurredAt:  s.clock().UTC(),
			PrincipalID: principal.ID,
			ClientID:    client.ID,
			SessionID:   session.ID,
			Reason:      "session_issued",
		})
		return err
	})
	if err != nil {
		return IssuedSession{}, err
	}
	return IssuedSession{Session: session, Secret: secret}, nil
}

// ValidateSession verifies a presented session id and secret.
func (s *Service) ValidateSession(ctx context.Context, sessionID, secret string) (ValidatedSession, error) {
	var validated ValidatedSession
	err := s.repo.WithinTx(ctx, func(tx store.Repository) error {
		session, err := tx.GetSession(ctx, strings.TrimSpace(sessionID))
		if err != nil {
			return err
		}
		if !s.secrets.Verify(secret, session.SecretHash) {
			return domain.ErrInvalidSessionSecret
		}
		if err := session.CanUse(s.clock()); err != nil {
			return err
		}
		principal, err := tx.GetPrincipal(ctx, session.PrincipalID)
		if err != nil {
			return err
		}
		if !principal.IsActive() {
			return domain.ErrPrincipalDisabled
		}
		client, err := tx.GetClient(ctx, session.ClientID)
		if err != nil {
			return err
		}
		if !client.IsActive() {
			return domain.ErrClientDisabled
		}

		session.Touch(s.clock())
		if err := tx.UpdateSession(ctx, session); err != nil {
			return err
		}
		if _, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:          s.idGen(),
			Type:        domain.AuditEventSessionValidated,
			OccurredAt:  s.clock().UTC(),
			PrincipalID: principal.ID,
			ClientID:    client.ID,
			SessionID:   session.ID,
			Reason:      "session_validated",
		}); err != nil {
			return err
		}
		validated = ValidatedSession{
			Session:   session,
			Principal: principal,
			Client:    client,
		}
		return nil
	})
	if err != nil {
		return ValidatedSession{}, err
	}
	return validated, nil
}

// RevokeSession revokes a persisted session.
func (s *Service) RevokeSession(ctx context.Context, sessionID, reason string) (domain.Session, error) {
	var session domain.Session
	err := s.repo.WithinTx(ctx, func(tx store.Repository) error {
		loaded, err := tx.GetSession(ctx, strings.TrimSpace(sessionID))
		if err != nil {
			return err
		}
		loaded.Revoke(reason, s.clock())
		if err := tx.UpdateSession(ctx, loaded); err != nil {
			return err
		}
		if _, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:          s.idGen(),
			Type:        domain.AuditEventSessionRevoked,
			OccurredAt:  s.clock().UTC(),
			PrincipalID: loaded.PrincipalID,
			ClientID:    loaded.ClientID,
			SessionID:   loaded.ID,
			Reason:      "session_revoked",
			Metadata: map[string]string{
				"revocation_reason": strings.TrimSpace(reason),
			},
		}); err != nil {
			return err
		}
		session = loaded
		return nil
	})
	if err != nil {
		return domain.Session{}, err
	}
	return session, nil
}

// Authorize validates the session and evaluates a request against policy and grants.
func (s *Service) Authorize(ctx context.Context, in AuthorizeInput) (domain.Decision, error) {
	normalizedAction := domain.NormalizeAction(in.Action)
	validated, decision, err := s.validateForDecision(ctx, in.SessionID, in.SessionSecret)
	if err != nil || decision.Code != "" {
		if err != nil {
			return domain.Decision{}, err
		}
		return s.recordUnvalidatedDecision(ctx, strings.TrimSpace(in.SessionID), normalizedAction, in.Resource, decision)
	}
	if err := normalizedAction.Validate(); err != nil {
		return s.recordDecision(ctx, validated, normalizedAction, in.Resource, domain.Decision{
			Code:   domain.DecisionInvalid,
			Reason: "invalid_action",
		})
	}
	if err := in.Resource.Validate(); err != nil {
		return s.recordDecision(ctx, validated, normalizedAction, in.Resource, domain.Decision{
			Code:   domain.DecisionInvalid,
			Reason: "invalid_resource",
		})
	}

	req := domain.AuthorizationRequest{
		SessionID: validated.Session.ID,
		Principal: validated.Principal,
		Client:    validated.Client,
		Action:    normalizedAction,
		Resource:  in.Resource,
		Context:   copyContext(in.Context),
	}
	rules, err := s.repo.ListRules(ctx)
	if err != nil {
		return domain.Decision{}, err
	}
	evaluation := evaluateRules(req, rules)
	fingerprint := requestFingerprint(validated.Principal.ID, validated.Client.ID, req.Action, req.Resource, req.Context)

	switch {
	case evaluation.allowRule != nil:
		return s.recordDecision(ctx, validated, req.Action, req.Resource, domain.Decision{
			Code:   domain.DecisionAllow,
			Reason: "allowed_by_policy",
			RuleIDs: []string{
				evaluation.allowRule.ID,
			},
		})
	case evaluation.grantRule != nil:
		decision, found, err := s.authorizeWithGrant(ctx, validated, req, fingerprint, *evaluation.grantRule)
		if err != nil {
			return domain.Decision{}, err
		}
		if found {
			return decision, nil
		}
		return s.recordDecision(ctx, validated, req.Action, req.Resource, domain.Decision{
			Code:   domain.DecisionGrantRequired,
			Reason: "grant_required",
			RuleIDs: []string{
				evaluation.grantRule.ID,
			},
		})
	case evaluation.denyRule != nil:
		return s.recordDecision(ctx, validated, req.Action, req.Resource, domain.Decision{
			Code:   domain.DecisionDeny,
			Reason: "denied_by_policy",
			RuleIDs: []string{
				evaluation.denyRule.ID,
			},
		})
	default:
		return s.recordDecision(ctx, validated, req.Action, req.Resource, domain.Decision{
			Code:   domain.DecisionDeny,
			Reason: "deny_by_default",
		})
	}
}

// RequestGrant creates one pending grant request for a valid session and request.
func (s *Service) RequestGrant(ctx context.Context, in RequestGrantInput) (domain.Grant, error) {
	decision, err := s.Authorize(ctx, AuthorizeInput{
		SessionID:     in.SessionID,
		SessionSecret: in.SessionSecret,
		Action:        in.Action,
		Resource:      in.Resource,
		Context:       in.Context,
	})
	if err != nil {
		return domain.Grant{}, err
	}
	if decision.Code != domain.DecisionGrantRequired {
		return domain.Grant{}, fmt.Errorf("request grant: expected grant_required, got %s", decision.Code)
	}
	validated, err := s.ValidateSession(ctx, in.SessionID, in.SessionSecret)
	if err != nil {
		return domain.Grant{}, err
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.grantTTL
	}
	grant, err := domain.NewGrant(domain.GrantInput{
		ID:             s.idGen(),
		SessionID:      validated.Session.ID,
		PrincipalID:    validated.Principal.ID,
		ClientID:       validated.Client.ID,
		Action:         domain.NormalizeAction(in.Action),
		Resource:       in.Resource,
		Fingerprint:    requestFingerprint(validated.Principal.ID, validated.Client.ID, in.Action, in.Resource, in.Context),
		RequestedScope: copyContext(in.Context),
		Reason:         strings.TrimSpace(in.Reason),
		ExpiresAt:      s.clock().Add(ttl),
	}, s.clock())
	if err != nil {
		return domain.Grant{}, err
	}
	err = s.repo.WithinTx(ctx, func(tx store.Repository) error {
		if err := tx.CreateGrant(ctx, grant); err != nil {
			return err
		}
		_, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:          s.idGen(),
			Type:        domain.AuditEventGrantRequested,
			OccurredAt:  s.clock().UTC(),
			PrincipalID: validated.Principal.ID,
			ClientID:    validated.Client.ID,
			SessionID:   validated.Session.ID,
			Action:      grant.Action,
			Resource:    grant.Resource,
			Reason:      "grant_requested",
			Metadata: map[string]string{
				"grant_id": grant.ID,
			},
		})
		return err
	})
	if err != nil {
		return domain.Grant{}, err
	}
	return grant, nil
}

// ResolveGrant updates the state of an existing grant.
func (s *Service) ResolveGrant(ctx context.Context, in ResolveGrantInput) (domain.Grant, error) {
	var updated domain.Grant
	err := s.repo.WithinTx(ctx, func(tx store.Repository) error {
		grant, err := tx.GetGrant(ctx, strings.TrimSpace(in.GrantID))
		if err != nil {
			return err
		}
		if in.Approve {
			if err := grant.Approve(in.Actor, in.Note, in.UsageLimit, s.clock()); err != nil {
				return err
			}
		} else {
			if err := grant.Deny(in.Actor, in.Note, s.clock()); err != nil {
				return err
			}
		}
		if err := tx.UpdateGrant(ctx, grant); err != nil {
			return err
		}
		eventType := domain.AuditEventGrantDenied
		if grant.State == domain.GrantStateApproved {
			eventType = domain.AuditEventGrantApproved
		}
		if _, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:          s.idGen(),
			Type:        eventType,
			OccurredAt:  s.clock().UTC(),
			PrincipalID: grant.PrincipalID,
			ClientID:    grant.ClientID,
			SessionID:   grant.SessionID,
			Action:      grant.Action,
			Resource:    grant.Resource,
			Reason:      string(grant.State),
			Metadata: map[string]string{
				"grant_id": grant.ID,
				"actor":    strings.TrimSpace(in.Actor),
			},
		}); err != nil {
			return err
		}
		updated = grant
		return nil
	})
	if err != nil {
		return domain.Grant{}, err
	}
	return updated, nil
}

// authorizeWithGrant redeems one approved grant and records the allow decision atomically.
func (s *Service) authorizeWithGrant(ctx context.Context, validated ValidatedSession, req domain.AuthorizationRequest, fingerprint string, rule domain.Rule) (domain.Decision, bool, error) {
	var decision domain.Decision
	err := s.repo.WithinTx(ctx, func(tx store.Repository) error {
		grant, err := tx.FindGrant(ctx, domain.GrantQuery{
			PrincipalID: validated.Principal.ID,
			ClientID:    validated.Client.ID,
			Action:      req.Action,
			Resource:    req.Resource,
			Fingerprint: fingerprint,
			State:       domain.GrantStateApproved,
		})
		switch {
		case err == nil:
		case errors.Is(err, domain.ErrGrantNotFound):
			return domain.ErrGrantNotFound
		default:
			return err
		}
		if err := grant.Redeem(s.clock()); err != nil {
			return err
		}
		if err := tx.UpdateGrant(ctx, grant); err != nil {
			return err
		}
		recorded, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:           s.idGen(),
			Type:         domain.AuditEventAuthzAllowed,
			OccurredAt:   s.clock().UTC(),
			PrincipalID:  validated.Principal.ID,
			ClientID:     validated.Client.ID,
			SessionID:    validated.Session.ID,
			Action:       req.Action,
			Resource:     req.Resource,
			DecisionCode: domain.DecisionAllow,
			Reason:       "allowed_by_grant",
			Metadata: map[string]string{
				"grant_id": grant.ID,
			},
		})
		if err != nil {
			return err
		}
		decision = domain.Decision{
			Code:         domain.DecisionAllow,
			Reason:       "allowed_by_grant",
			RuleIDs:      []string{rule.ID},
			GrantID:      grant.ID,
			AuditEventID: recorded.ID,
		}
		return nil
	})
	switch {
	case err == nil:
		return decision, true, nil
	case errors.Is(err, domain.ErrGrantNotFound), errors.Is(err, domain.ErrGrantExpired):
		return domain.Decision{}, false, nil
	default:
		return domain.Decision{}, false, err
	}
}

// ListGrants returns all stored grants.
func (s *Service) ListGrants(ctx context.Context) ([]domain.Grant, error) {
	return s.repo.ListGrants(ctx)
}

// ListAuditEvents returns audit events from the repository.
func (s *Service) ListAuditEvents(ctx context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	return s.repo.ListAuditEvents(ctx, filter)
}

// validateForDecision maps session failures into stable decision codes.
func (s *Service) validateForDecision(ctx context.Context, sessionID, secret string) (ValidatedSession, domain.Decision, error) {
	validated, err := s.ValidateSession(ctx, sessionID, secret)
	switch {
	case err == nil:
		return validated, domain.Decision{}, nil
	case errors.Is(err, domain.ErrSessionNotFound):
		return ValidatedSession{}, domain.Decision{Code: domain.DecisionSessionRequired, Reason: "session_not_found"}, nil
	case errors.Is(err, domain.ErrSessionExpired):
		return ValidatedSession{}, domain.Decision{Code: domain.DecisionSessionExpired, Reason: "session_expired"}, nil
	case errors.Is(err, domain.ErrSessionRevoked):
		return ValidatedSession{}, domain.Decision{Code: domain.DecisionInvalid, Reason: "session_revoked"}, nil
	case errors.Is(err, domain.ErrInvalidSessionSecret):
		return ValidatedSession{}, domain.Decision{Code: domain.DecisionInvalid, Reason: "invalid_session_secret"}, nil
	case errors.Is(err, domain.ErrPrincipalDisabled):
		return ValidatedSession{}, domain.Decision{Code: domain.DecisionInvalid, Reason: "principal_disabled"}, nil
	case errors.Is(err, domain.ErrClientDisabled):
		return ValidatedSession{}, domain.Decision{Code: domain.DecisionInvalid, Reason: "client_disabled"}, nil
	default:
		return ValidatedSession{}, domain.Decision{}, err
	}
}

// appendAuditTx appends one audit event through the provided repository.
func (s *Service) appendAuditTx(ctx context.Context, repo store.Repository, event domain.AuditEvent) (domain.AuditEvent, error) {
	if strings.TrimSpace(event.ID) == "" {
		event.ID = s.idGen()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.clock().UTC()
	}
	event.Metadata = copyContext(event.Metadata)
	if err := repo.AppendAuditEvent(ctx, event); err != nil {
		return domain.AuditEvent{}, err
	}
	return event, nil
}

// recordDecision appends one authz decision audit event and returns the final decision.
func (s *Service) recordDecision(ctx context.Context, validated ValidatedSession, action domain.Action, resource domain.ResourceRef, decision domain.Decision) (domain.Decision, error) {
	eventType := domain.AuditEventAuthzDenied
	if decision.Code == domain.DecisionAllow {
		eventType = domain.AuditEventAuthzAllowed
	}
	var event domain.AuditEvent
	err := s.repo.WithinTx(ctx, func(tx store.Repository) error {
		recorded, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:           s.idGen(),
			Type:         eventType,
			OccurredAt:   s.clock().UTC(),
			PrincipalID:  validated.Principal.ID,
			ClientID:     validated.Client.ID,
			SessionID:    validated.Session.ID,
			Action:       domain.NormalizeAction(action),
			Resource:     resource,
			DecisionCode: decision.Code,
			Reason:       decision.Reason,
		})
		if err != nil {
			return err
		}
		event = recorded
		return nil
	})
	if err != nil {
		return domain.Decision{}, err
	}
	decision.AuditEventID = event.ID
	return decision, nil
}

// recordUnvalidatedDecision appends one deny-like audit event when full validation did not succeed.
func (s *Service) recordUnvalidatedDecision(ctx context.Context, sessionID string, action domain.Action, resource domain.ResourceRef, decision domain.Decision) (domain.Decision, error) {
	var event domain.AuditEvent
	err := s.repo.WithinTx(ctx, func(tx store.Repository) error {
		recorded, err := s.appendAuditTx(ctx, tx, domain.AuditEvent{
			ID:           s.idGen(),
			Type:         domain.AuditEventAuthzDenied,
			OccurredAt:   s.clock().UTC(),
			SessionID:    strings.TrimSpace(sessionID),
			Action:       action,
			Resource:     resource,
			DecisionCode: decision.Code,
			Reason:       decision.Reason,
		})
		if err != nil {
			return err
		}
		event = recorded
		return nil
	})
	if err != nil {
		return domain.Decision{}, err
	}
	decision.AuditEventID = event.ID
	return decision, nil
}

// evaluateRules identifies the highest-priority deny, allow, and grantable matches.
func evaluateRules(req domain.AuthorizationRequest, rules []domain.Rule) ruleEvaluation {
	var denyMatch *domain.Rule
	var allowMatch *domain.Rule
	var grantMatch *domain.Rule

	sorted := make([]domain.Rule, len(rules))
	copy(sorted, rules)
	sortRules(sorted)

	for idx := range sorted {
		rule := sorted[idx]
		if !rule.Matches(req) {
			continue
		}
		switch {
		case rule.Effect == domain.EffectDeny && denyMatch == nil:
			denyMatch = &rule
		case rule.Effect == domain.EffectAllow && rule.Escalation == nil && allowMatch == nil:
			allowMatch = &rule
		case rule.Effect == domain.EffectAllow && rule.Escalation != nil && rule.Escalation.Allowed && grantMatch == nil:
			grantMatch = &rule
		}
	}

	if denyMatch != nil {
		allowPriority := -1
		grantPriority := -1
		if allowMatch != nil {
			allowPriority = allowMatch.Priority
		}
		if grantMatch != nil {
			grantPriority = grantMatch.Priority
		}
		if denyMatch.Priority >= allowPriority && denyMatch.Priority >= grantPriority {
			return ruleEvaluation{denyRule: denyMatch}
		}
	}
	if allowMatch != nil && (grantMatch == nil || allowMatch.Priority >= grantMatch.Priority) {
		return ruleEvaluation{allowRule: allowMatch}
	}
	if grantMatch != nil {
		return ruleEvaluation{grantRule: grantMatch}
	}
	return ruleEvaluation{}
}

// requestFingerprint builds a stable request fingerprint for grant reuse.
func requestFingerprint(principalID, clientID string, action domain.Action, resource domain.ResourceRef, context map[string]string) string {
	keys := make([]string, 0, len(context))
	for key := range context {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.WriteString(strings.TrimSpace(principalID))
	builder.WriteString("|")
	builder.WriteString(strings.TrimSpace(clientID))
	builder.WriteString("|")
	builder.WriteString(string(domain.NormalizeAction(action)))
	builder.WriteString("|")
	builder.WriteString(strings.TrimSpace(resource.Namespace))
	builder.WriteString("|")
	builder.WriteString(strings.TrimSpace(resource.Type))
	builder.WriteString("|")
	builder.WriteString(strings.TrimSpace(resource.ID))
	for _, key := range keys {
		builder.WriteString("|")
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(context[key])
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// copyContext returns a defensive copy of one string context map.
func copyContext(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	maps.Copy(out, in)
	return out
}

// sortRules orders rules by priority descending and id ascending.
func sortRules(rules []domain.Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority > rules[j].Priority
	})
}

// ruleEvaluation stores the best-matching deny, allow, and grantable rule.
type ruleEvaluation struct {
	denyRule  *domain.Rule
	allowRule *domain.Rule
	grantRule *domain.Rule
}
