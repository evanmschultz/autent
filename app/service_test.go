package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/evanmschultz/autent/domain"
	"github.com/evanmschultz/autent/inmem"
	"github.com/evanmschultz/autent/store"
	"github.com/evanmschultz/autent/token"
)

// TestNewServiceRequiresDependencies verifies the service rejects incomplete wiring.
func TestNewServiceRequiresDependencies(t *testing.T) {
	t.Parallel()

	_, err := NewService(Config{
		Secrets:     token.OpaqueSecretManager{},
		IDGenerator: func() string { return "generated-id" },
	})
	if !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("NewService() error = %v, want ErrInvalidConfig", err)
	}
}

// TestNewServiceDefaultsIDGenerator verifies the service can construct without a caller-supplied ID generator.
func TestNewServiceDefaultsIDGenerator(t *testing.T) {
	t.Parallel()

	service, err := NewService(Config{
		Repository: inmem.NewRepository(),
		Secrets:    token.OpaqueSecretManager{},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if service.idGen == nil {
		t.Fatal("service.idGen = nil, want default generator")
	}
}

// TestServiceIssueValidateRevokeSession verifies the core session lifecycle.
func TestServiceIssueValidateRevokeSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	clockNow := now
	service := newTestService(t, func() time.Time { return clockNow })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}
	validated, err := service.ValidateSession(context.Background(), issued.Session.ID, issued.Secret)
	if err != nil {
		t.Fatalf("ValidateSession() error = %v", err)
	}
	if validated.Principal.ID != principal.ID {
		t.Fatalf("validated.Principal.ID = %q, want %q", validated.Principal.ID, principal.ID)
	}
	if validated.Session.ID != issued.Session.ID {
		t.Fatalf("validated.Session.ID = %q, want %q", validated.Session.ID, issued.Session.ID)
	}
	if _, err := service.ValidateSession(context.Background(), issued.Session.ID, "wrong-secret"); !errors.Is(err, domain.ErrInvalidSessionSecret) {
		t.Fatalf("ValidateSession(wrong secret) error = %v, want ErrInvalidSessionSecret", err)
	}
	if _, err := service.RevokeSession(context.Background(), issued.Session.ID, "operator_revoke"); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if _, err := service.ValidateSession(context.Background(), issued.Session.ID, issued.Secret); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("ValidateSession(revoked) error = %v, want ErrSessionRevoked", err)
	}
}

// TestServiceAuthorizeExpiredSessionReturnsDecision verifies expired sessions map to a stable decision code.
func TestServiceAuthorizeExpiredSessionReturnsDecision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	clockNow := now
	service := newTestService(t, func() time.Time { return clockNow })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}

	clockNow = now.Add(2 * time.Minute)
	decision, err := service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "read",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Code != domain.DecisionSessionExpired || decision.Reason != "session_expired" {
		t.Fatalf("decision = %+v, want session_expired", decision)
	}
}

// TestServiceAuthorizeGrantFlow verifies deny, grant, approval, and retry behavior.
func TestServiceAuthorizeGrantFlow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}
	rule, err := domain.ValidateAndNormalizeRule(domain.Rule{
		ID:     "rule-1",
		Effect: domain.EffectAllow,
		PrincipalIDs: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: principal.ID},
		},
		ClientIDs: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: client.ID},
		},
		Actions: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: "mutate"},
		},
		Resources: []domain.ResourcePattern{
			{
				Namespace: domain.StringPattern{Operator: domain.MatchExact, Value: "project:demo"},
				Type:      domain.StringPattern{Operator: domain.MatchExact, Value: "task"},
				ID:        domain.StringPattern{Operator: domain.MatchExact, Value: "task-1"},
			},
		},
		Conditions: []domain.Condition{
			{Key: "scope", Operator: domain.ConditionEquals, Value: "current"},
		},
		Escalation: &domain.EscalationRequirement{Allowed: true},
		Priority:   10,
	})
	if err != nil {
		t.Fatalf("ValidateAndNormalizeRule() error = %v", err)
	}
	if _, err := service.PutRule(context.Background(), rule); err != nil {
		t.Fatalf("PutRule() error = %v", err)
	}

	decision, err := service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Context: map[string]string{"scope": "current"},
	})
	if err != nil {
		t.Fatalf("Authorize(grant required) error = %v", err)
	}
	if decision.Code != domain.DecisionGrantRequired {
		t.Fatalf("decision.Code = %q, want %q", decision.Code, domain.DecisionGrantRequired)
	}

	grant, err := service.RequestGrant(context.Background(), RequestGrantInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Context: map[string]string{"scope": "current"},
		Reason:  "need mutation once",
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	if _, err := service.ResolveGrant(context.Background(), ResolveGrantInput{
		GrantID:    grant.ID,
		Approve:    true,
		Actor:      "approver-1",
		Note:       "approved for one use",
		UsageLimit: 1,
	}); err != nil {
		t.Fatalf("ResolveGrant(approve) error = %v", err)
	}

	decision, err = service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Context: map[string]string{"scope": "current"},
	})
	if err != nil {
		t.Fatalf("Authorize(after approval) error = %v", err)
	}
	if decision.Code != domain.DecisionAllow || decision.GrantID == "" {
		t.Fatalf("decision = %+v, want allow with grant id", decision)
	}

	decision, err = service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Context: map[string]string{"scope": "current"},
	})
	if err != nil {
		t.Fatalf("Authorize(after grant redemption) error = %v", err)
	}
	if decision.Code != domain.DecisionGrantRequired {
		t.Fatalf("decision.Code after redemption = %q, want %q", decision.Code, domain.DecisionGrantRequired)
	}
}

// TestServiceListSessionsFilters verifies caller-safe session listing and generic filters.
func TestServiceListSessionsFilters(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	clockNow := now
	service := newTestService(t, func() time.Time { return clockNow })

	principalOne, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal(principal-1) error = %v", err)
	}
	principalTwo, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-2",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User Two",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal(principal-2) error = %v", err)
	}
	clientOne, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI One",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient(client-1) error = %v", err)
	}
	clientTwo, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-2",
		DisplayName: "CLI Two",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient(client-2) error = %v", err)
	}

	activeSession, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principalOne.ID,
		ClientID:    clientOne.ID,
		TTL:         2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueSession(active) error = %v", err)
	}

	clockNow = now.Add(5 * time.Minute)
	revokedSession, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principalOne.ID,
		ClientID:    clientTwo.ID,
		TTL:         2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueSession(revoked) error = %v", err)
	}
	if _, err := service.RevokeSession(context.Background(), revokedSession.Session.ID, "operator_done"); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	clockNow = now.Add(10 * time.Minute)
	expiredSession, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principalTwo.ID,
		ClientID:    clientOne.ID,
		TTL:         time.Minute,
	})
	if err != nil {
		t.Fatalf("IssueSession(expired) error = %v", err)
	}

	clockNow = now.Add(20 * time.Minute)
	activeSessions, err := service.ListSessions(context.Background(), SessionFilter{State: SessionStateActive})
	if err != nil {
		t.Fatalf("ListSessions(active) error = %v", err)
	}
	if len(activeSessions) != 1 || activeSessions[0].ID != activeSession.Session.ID {
		t.Fatalf("activeSessions = %+v, want only %q", activeSessions, activeSession.Session.ID)
	}

	revokedSessions, err := service.ListSessions(context.Background(), SessionFilter{State: SessionStateRevoked})
	if err != nil {
		t.Fatalf("ListSessions(revoked) error = %v", err)
	}
	if len(revokedSessions) != 1 || revokedSessions[0].ID != revokedSession.Session.ID {
		t.Fatalf("revokedSessions = %+v, want only %q", revokedSessions, revokedSession.Session.ID)
	}

	expiredSessions, err := service.ListSessions(context.Background(), SessionFilter{State: SessionStateExpired})
	if err != nil {
		t.Fatalf("ListSessions(expired) error = %v", err)
	}
	if len(expiredSessions) != 1 || expiredSessions[0].ID != expiredSession.Session.ID {
		t.Fatalf("expiredSessions = %+v, want only %q", expiredSessions, expiredSession.Session.ID)
	}

	principalFiltered, err := service.ListSessions(context.Background(), SessionFilter{
		PrincipalID: principalOne.ID,
		Limit:       1,
	})
	if err != nil {
		t.Fatalf("ListSessions(principal filter) error = %v", err)
	}
	if len(principalFiltered) != 1 {
		t.Fatalf("len(principalFiltered) = %d, want 1", len(principalFiltered))
	}
	if principalFiltered[0].PrincipalID != principalOne.ID {
		t.Fatalf("principalFiltered[0].PrincipalID = %q, want %q", principalFiltered[0].PrincipalID, principalOne.ID)
	}

	if _, err := service.ListSessions(context.Background(), SessionFilter{State: SessionState("bogus")}); !errors.Is(err, domain.ErrInvalidFilter) {
		t.Fatalf("ListSessions(invalid filter) error = %v, want ErrInvalidFilter", err)
	}
}

// TestServiceDenyWinsAtEqualPriority verifies explicit deny beats allow at equal priority.
func TestServiceDenyWinsAtEqualPriority(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}

	allowRule, err := domain.ValidateAndNormalizeRule(domain.Rule{
		ID:     "allow-rule",
		Effect: domain.EffectAllow,
		Actions: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: "read"},
		},
		Resources: []domain.ResourcePattern{
			{
				Namespace: domain.StringPattern{Operator: domain.MatchExact, Value: "project:demo"},
				Type:      domain.StringPattern{Operator: domain.MatchExact, Value: "task"},
				ID:        domain.StringPattern{Operator: domain.MatchExact, Value: "task-1"},
			},
		},
		Priority: 10,
	})
	if err != nil {
		t.Fatalf("ValidateAndNormalizeRule(allow) error = %v", err)
	}
	denyRule, err := domain.ValidateAndNormalizeRule(domain.Rule{
		ID:     "deny-rule",
		Effect: domain.EffectDeny,
		Actions: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: "read"},
		},
		Resources: []domain.ResourcePattern{
			{
				Namespace: domain.StringPattern{Operator: domain.MatchExact, Value: "project:demo"},
				Type:      domain.StringPattern{Operator: domain.MatchExact, Value: "task"},
				ID:        domain.StringPattern{Operator: domain.MatchExact, Value: "task-1"},
			},
		},
		Priority: 10,
	})
	if err != nil {
		t.Fatalf("ValidateAndNormalizeRule(deny) error = %v", err)
	}
	if _, err := service.PutRule(context.Background(), allowRule); err != nil {
		t.Fatalf("PutRule(allow) error = %v", err)
	}
	if _, err := service.PutRule(context.Background(), denyRule); err != nil {
		t.Fatalf("PutRule(deny) error = %v", err)
	}

	decision, err := service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "read",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Code != domain.DecisionDeny {
		t.Fatalf("decision.Code = %q, want %q", decision.Code, domain.DecisionDeny)
	}
}

// TestServiceGrantRulePriorityBeatsLowerAllow verifies higher-priority grant rules override lower plain allows.
func TestServiceGrantRulePriorityBeatsLowerAllow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}

	if _, err := service.PutRule(context.Background(), domain.Rule{
		ID:     "allow-low",
		Effect: domain.EffectAllow,
		Actions: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: "mutate"},
		},
		Resources: []domain.ResourcePattern{
			{
				Namespace: domain.StringPattern{Operator: domain.MatchExact, Value: "project:demo"},
				Type:      domain.StringPattern{Operator: domain.MatchExact, Value: "task"},
				ID:        domain.StringPattern{Operator: domain.MatchExact, Value: "task-1"},
			},
		},
		Priority: 10,
	}); err != nil {
		t.Fatalf("PutRule(allow-low) error = %v", err)
	}
	if _, err := service.PutRule(context.Background(), domain.Rule{
		ID:     "grant-high",
		Effect: domain.EffectAllow,
		Actions: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: "mutate"},
		},
		Resources: []domain.ResourcePattern{
			{
				Namespace: domain.StringPattern{Operator: domain.MatchExact, Value: "project:demo"},
				Type:      domain.StringPattern{Operator: domain.MatchExact, Value: "task"},
				ID:        domain.StringPattern{Operator: domain.MatchExact, Value: "task-1"},
			},
		},
		Escalation: &domain.EscalationRequirement{Allowed: true},
		Priority:   20,
	}); err != nil {
		t.Fatalf("PutRule(grant-high) error = %v", err)
	}

	decision, err := service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Code != domain.DecisionGrantRequired {
		t.Fatalf("decision.Code = %q, want %q", decision.Code, domain.DecisionGrantRequired)
	}
}

// TestServiceAuthorizeAuditsInvalidRequest verifies invalid requests are denied and audited.
func TestServiceAuthorizeAuditsInvalidRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	repo := inmem.NewStore()
	service := newServiceWithRepository(t, repo, func() time.Time { return now })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}

	decision, err := service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Code != domain.DecisionInvalid || decision.AuditEventID == "" {
		t.Fatalf("decision = %+v, want invalid with audit id", decision)
	}
}

// TestServiceAuthorizeMissingSessionAudited verifies session failures produce decisions and audit events.
func TestServiceAuthorizeMissingSessionAudited(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })

	decision, err := service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     "missing-session",
		SessionSecret: "missing-secret",
		Action:        "read",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Code != domain.DecisionSessionRequired || decision.AuditEventID == "" {
		t.Fatalf("decision = %+v, want session_required with audit id", decision)
	}
}

// TestServiceAuthorizeDisabledPrincipalReturnsDecision verifies disabled principals map to stable decisions.
func TestServiceAuthorizeDisabledPrincipalReturnsDecision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	baseRepo := inmem.NewStore()
	setupService := newServiceWithRepository(t, baseRepo, func() time.Time { return now })

	principal, err := setupService.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := setupService.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := setupService.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}

	service := newServiceWithRepository(t, disabledPrincipalRepository{Repository: baseRepo}, func() time.Time { return now })
	decision, err := service.Authorize(context.Background(), AuthorizeInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "read",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Code != domain.DecisionInvalid || decision.Reason != "principal_disabled" {
		t.Fatalf("decision = %+v, want invalid principal_disabled", decision)
	}
}

// TestServiceUpdateStatuses verifies principal and client status updates.
func TestServiceUpdateStatuses(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	updatedPrincipal, err := service.UpdatePrincipalStatus(context.Background(), UpdatePrincipalStatusInput{
		PrincipalID: principal.ID,
		Status:      domain.StatusDisabled,
		Actor:       "operator-1",
		Reason:      "offboarded",
	})
	if err != nil {
		t.Fatalf("UpdatePrincipalStatus() error = %v", err)
	}
	if updatedPrincipal.Status != domain.StatusDisabled {
		t.Fatalf("updatedPrincipal.Status = %q, want disabled", updatedPrincipal.Status)
	}
	updatedClient, err := service.UpdateClientStatus(context.Background(), UpdateClientStatusInput{
		ClientID: client.ID,
		Status:   domain.StatusDisabled,
		Actor:    "operator-1",
		Reason:   "paused",
	})
	if err != nil {
		t.Fatalf("UpdateClientStatus() error = %v", err)
	}
	if updatedClient.Status != domain.StatusDisabled {
		t.Fatalf("updatedClient.Status = %q, want disabled", updatedClient.Status)
	}
}

// TestServiceCancelGrant verifies pending grants can be canceled.
func TestServiceCancelGrant(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	service := newTestService(t, func() time.Time { return now })

	principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	})
	if err != nil {
		t.Fatalf("RegisterPrincipal() error = %v", err)
	}
	client, err := service.RegisterClient(context.Background(), domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	issued, err := service.IssueSession(context.Background(), IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}
	if _, err := service.PutRule(context.Background(), domain.Rule{
		ID:     "grantable",
		Effect: domain.EffectAllow,
		Actions: []domain.StringPattern{
			{Operator: domain.MatchExact, Value: "mutate"},
		},
		Resources: []domain.ResourcePattern{
			{
				Namespace: domain.StringPattern{Operator: domain.MatchExact, Value: "project:demo"},
				Type:      domain.StringPattern{Operator: domain.MatchExact, Value: "task"},
				ID:        domain.StringPattern{Operator: domain.MatchExact, Value: "task-1"},
			},
		},
		Escalation: &domain.EscalationRequirement{Allowed: true},
	}); err != nil {
		t.Fatalf("PutRule() error = %v", err)
	}
	grant, err := service.RequestGrant(context.Background(), RequestGrantInput{
		SessionID:     issued.Session.ID,
		SessionSecret: issued.Secret,
		Action:        "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
	})
	if err != nil {
		t.Fatalf("RequestGrant() error = %v", err)
	}
	canceled, err := service.CancelGrant(context.Background(), grant.ID, "operator-1", "no longer needed")
	if err != nil {
		t.Fatalf("CancelGrant() error = %v", err)
	}
	if canceled.State != domain.GrantStateCanceled {
		t.Fatalf("canceled.State = %q, want canceled", canceled.State)
	}
}

// newTestService constructs a service backed by the in-memory repository.
func newTestService(t *testing.T, clock func() time.Time) *Service {
	t.Helper()

	return newServiceWithRepository(t, inmem.NewRepository(), clock)
}

// newServiceWithRepository constructs a service backed by one caller-supplied repository.
func newServiceWithRepository(t *testing.T, repo store.Repository, clock func() time.Time) *Service {
	t.Helper()

	nextID := 0
	service, err := NewService(Config{
		Repository: repo,
		Secrets:    token.OpaqueSecretManager{},
		Clock:      clock,
		IDGenerator: func() string {
			nextID++
			return fmt.Sprintf("generated-id-%d", nextID)
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

// disabledPrincipalRepository forces principal lookups to appear disabled for negative-path tests.
type disabledPrincipalRepository struct {
	store.Repository
}

// WithinTx preserves the disabled-principal wrapper inside nested transaction callbacks.
func (repo disabledPrincipalRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return repo.Repository.WithinTx(ctx, func(txRepo store.Repository) error {
		return fn(disabledPrincipalRepository{Repository: txRepo})
	})
}

// GetPrincipal returns one disabled principal regardless of the stored principal status.
func (repo disabledPrincipalRepository) GetPrincipal(ctx context.Context, id string) (domain.Principal, error) {
	principal, err := repo.Repository.GetPrincipal(ctx, id)
	if err != nil {
		return domain.Principal{}, err
	}
	principal.Status = domain.StatusDisabled
	return principal, nil
}
