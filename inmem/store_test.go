package inmem

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/evanmschultz/autent/domain"
	"github.com/evanmschultz/autent/store"
)

// TestStorePrincipalLifecycle verifies basic principal persistence semantics.
func TestStorePrincipalLifecycle(t *testing.T) {
	t.Parallel()

	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	principal, err := domain.NewPrincipal(domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	if err := repo.CreatePrincipal(context.Background(), principal); err != nil {
		t.Fatalf("CreatePrincipal() error = %v", err)
	}
	if err := repo.CreatePrincipal(context.Background(), principal); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("CreatePrincipal(duplicate) error = %v, want ErrAlreadyExists", err)
	}
	loaded, err := repo.GetPrincipal(context.Background(), principal.ID)
	if err != nil {
		t.Fatalf("GetPrincipal() error = %v", err)
	}
	if loaded.DisplayName != principal.DisplayName {
		t.Fatalf("loaded.DisplayName = %q, want %q", loaded.DisplayName, principal.DisplayName)
	}
}

// TestStoreWithinTxRollback verifies in-memory transactions roll back on error.
func TestStoreWithinTxRollback(t *testing.T) {
	t.Parallel()

	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	principal, err := domain.NewPrincipal(domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}

	wantErr := errors.New("rollback")
	err = repo.WithinTx(context.Background(), func(txRepo store.Repository) error {
		if err := txRepo.CreatePrincipal(context.Background(), principal); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WithinTx() error = %v, want %v", err, wantErr)
	}
	if _, err := repo.GetPrincipal(context.Background(), principal.ID); !errors.Is(err, domain.ErrPrincipalNotFound) {
		t.Fatalf("GetPrincipal(after rollback) error = %v, want ErrPrincipalNotFound", err)
	}
}

// TestStoreWithinTxCommit verifies in-memory transactions persist on success.
func TestStoreWithinTxCommit(t *testing.T) {
	t.Parallel()

	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	principal, err := domain.NewPrincipal(domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}

	if err := repo.WithinTx(context.Background(), func(txRepo store.Repository) error {
		return txRepo.CreatePrincipal(context.Background(), principal)
	}); err != nil {
		t.Fatalf("WithinTx() error = %v", err)
	}
	if _, err := repo.GetPrincipal(context.Background(), principal.ID); err != nil {
		t.Fatalf("GetPrincipal(after commit) error = %v", err)
	}
}

// TestStoreRepositoryFlow verifies the full repository contract in memory.
func TestStoreRepositoryFlow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)

	principal, err := domain.NewPrincipal(domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	client, err := domain.NewClient(domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	}, now)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	session, err := domain.NewSession(domain.SessionInput{
		ID:          "session-1",
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	grant, err := domain.NewGrant(domain.GrantInput{
		ID:          "grant-1",
		SessionID:   session.ID,
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		Action:      "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := grant.Approve("approver-1", "approved", 1, now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Approve() error = %v", err)
	}
	rule, err := domain.ValidateAndNormalizeRule(domain.Rule{
		ID:     "rule-1",
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
	})
	if err != nil {
		t.Fatalf("ValidateAndNormalizeRule() error = %v", err)
	}
	event := domain.AuditEvent{
		ID:         "audit-1",
		Type:       domain.AuditEventAuthzAllowed,
		OccurredAt: now,
		SessionID:  session.ID,
	}

	if err := repo.CreatePrincipal(ctx, principal); err != nil {
		t.Fatalf("CreatePrincipal() error = %v", err)
	}
	if err := repo.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if loadedClient, err := repo.GetClient(ctx, client.ID); err != nil || loadedClient.ID != client.ID {
		t.Fatalf("GetClient() = %+v, %v, want client, nil", loadedClient, err)
	}
	if err := repo.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if loadedSession, err := repo.GetSession(ctx, session.ID); err != nil || loadedSession.ID != session.ID {
		t.Fatalf("GetSession() = %+v, %v, want session, nil", loadedSession, err)
	}
	session.Touch(now.Add(5 * time.Minute))
	if err := repo.UpdateSession(ctx, session); err != nil {
		t.Fatalf("UpdateSession() error = %v", err)
	}
	if err := repo.ReplaceRules(ctx, []domain.Rule{rule}); err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}
	if err := repo.CreateGrant(ctx, grant); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if loadedGrant, err := repo.GetGrant(ctx, grant.ID); err != nil || loadedGrant.ID != grant.ID {
		t.Fatalf("GetGrant() = %+v, %v, want grant, nil", loadedGrant, err)
	}
	grant.UsageCount = 1
	if err := repo.UpdateGrant(ctx, grant); err != nil {
		t.Fatalf("UpdateGrant() error = %v", err)
	}
	if err := repo.AppendAuditEvent(ctx, event); err != nil {
		t.Fatalf("AppendAuditEvent() error = %v", err)
	}

	if principals, err := repo.ListPrincipals(ctx); err != nil || len(principals) != 1 {
		t.Fatalf("ListPrincipals() = %d, %v, want 1, nil", len(principals), err)
	}
	if clients, err := repo.ListClients(ctx); err != nil || len(clients) != 1 {
		t.Fatalf("ListClients() = %d, %v, want 1, nil", len(clients), err)
	}
	if sessions, err := repo.ListSessions(ctx); err != nil || len(sessions) != 1 {
		t.Fatalf("ListSessions() = %d, %v, want 1, nil", len(sessions), err)
	}
	if rules, err := repo.ListRules(ctx); err != nil || len(rules) != 1 {
		t.Fatalf("ListRules() = %d, %v, want 1, nil", len(rules), err)
	}
	foundGrant, err := repo.FindGrant(ctx, domain.GrantQuery{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		Action:      grant.Action,
		Resource:    grant.Resource,
		Fingerprint: grant.Fingerprint,
		State:       domain.GrantStateApproved,
	})
	if err != nil {
		t.Fatalf("FindGrant() error = %v", err)
	}
	if foundGrant.UsageCount != 1 {
		t.Fatalf("foundGrant.UsageCount = %d, want 1", foundGrant.UsageCount)
	}
	if grants, err := repo.ListGrants(ctx); err != nil || len(grants) != 1 {
		t.Fatalf("ListGrants() = %d, %v, want 1, nil", len(grants), err)
	}
	if events, err := repo.ListAuditEvents(ctx, domain.AuditFilter{SessionID: session.ID}); err != nil || len(events) != 1 {
		t.Fatalf("ListAuditEvents() = %d, %v, want 1, nil", len(events), err)
	}
	if _, err := NewRepository().GetPrincipal(ctx, "missing"); !errors.Is(err, domain.ErrPrincipalNotFound) {
		t.Fatalf("NewRepository().GetPrincipal() error = %v, want ErrPrincipalNotFound", err)
	}
}

// TestStoreWithinTxCRUD verifies transaction-scoped repository methods.
func TestStoreWithinTxCRUD(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)

	principal, err := domain.NewPrincipal(domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	client, err := domain.NewClient(domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	}, now)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	session, err := domain.NewSession(domain.SessionInput{
		ID:          "session-1",
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	grant, err := domain.NewGrant(domain.GrantInput{
		ID:          "grant-1",
		SessionID:   session.ID,
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		Action:      "mutate",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := grant.Approve("approver-1", "approved", 0, now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Approve() error = %v", err)
	}

	err = repo.WithinTx(ctx, func(txRepo store.Repository) error {
		if err := txRepo.CreatePrincipal(ctx, principal); err != nil {
			return err
		}
		if err := txRepo.CreateClient(ctx, client); err != nil {
			return err
		}
		if err := txRepo.CreateSession(ctx, session); err != nil {
			return err
		}
		if err := txRepo.ReplaceRules(ctx, []domain.Rule{}); err != nil {
			return err
		}
		if err := txRepo.CreateGrant(ctx, grant); err != nil {
			return err
		}
		if err := txRepo.AppendAuditEvent(ctx, domain.AuditEvent{ID: "audit-1", Type: domain.AuditEventGrantApproved, OccurredAt: now}); err != nil {
			return err
		}
		if _, err := txRepo.GetPrincipal(ctx, principal.ID); err != nil {
			return err
		}
		if _, err := txRepo.GetClient(ctx, client.ID); err != nil {
			return err
		}
		if loaded, err := txRepo.GetSession(ctx, session.ID); err != nil {
			return err
		} else {
			loaded.Touch(now.Add(2 * time.Minute))
			if err := txRepo.UpdateSession(ctx, loaded); err != nil {
				return err
			}
		}
		if _, err := txRepo.GetGrant(ctx, grant.ID); err != nil {
			return err
		}
		if grants, err := txRepo.ListGrants(ctx); err != nil || len(grants) != 1 {
			t.Fatalf("txRepo.ListGrants() = %d, %v, want 1, nil", len(grants), err)
		}
		if _, err := txRepo.FindGrant(ctx, domain.GrantQuery{
			PrincipalID: principal.ID,
			ClientID:    client.ID,
			Action:      grant.Action,
			Resource:    grant.Resource,
			Fingerprint: grant.Fingerprint,
			State:       domain.GrantStateApproved,
		}); err != nil {
			return err
		}
		if events, err := txRepo.ListAuditEvents(ctx, domain.AuditFilter{Type: domain.AuditEventGrantApproved}); err != nil || len(events) != 1 {
			t.Fatalf("txRepo.ListAuditEvents() = %d, %v, want 1, nil", len(events), err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithinTx() error = %v", err)
	}
}

// TestStoreSessionGrantAndAuditFlows verifies the remaining store ports.
func TestStoreSessionGrantAndAuditFlows(t *testing.T) {
	t.Parallel()

	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)

	session, err := domain.NewSession(domain.SessionInput{
		ID:          "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	if err := repo.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	session.Touch(now.Add(5 * time.Minute))
	if err := repo.UpdateSession(context.Background(), session); err != nil {
		t.Fatalf("UpdateSession() error = %v", err)
	}
	sessions, err := repo.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions) != 1 || sessions[0].LastSeenAt != session.LastSeenAt {
		t.Fatalf("sessions = %+v, want updated session", sessions)
	}

	rule, err := domain.ValidateAndNormalizeRule(domain.Rule{
		ID:     "rule-1",
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
		t.Fatalf("ValidateAndNormalizeRule() error = %v", err)
	}
	if err := repo.ReplaceRules(context.Background(), []domain.Rule{rule}); err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}
	rules, err := repo.ListRules(context.Background())
	if err != nil {
		t.Fatalf("ListRules() error = %v", err)
	}
	if len(rules) != 1 || rules[0].ID != rule.ID {
		t.Fatalf("rules = %+v, want one rule", rules)
	}

	grant, err := domain.NewGrant(domain.GrantInput{
		ID:          "grant-1",
		SessionID:   session.ID,
		PrincipalID: session.PrincipalID,
		ClientID:    session.ClientID,
		Action:      "read",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := grant.Approve("approver-1", "approved", 1, now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Approve() error = %v", err)
	}
	if err := repo.CreateGrant(context.Background(), grant); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	found, err := repo.FindGrant(context.Background(), domain.GrantQuery{
		PrincipalID: grant.PrincipalID,
		ClientID:    grant.ClientID,
		Action:      grant.Action,
		Resource:    grant.Resource,
		Fingerprint: grant.Fingerprint,
		State:       domain.GrantStateApproved,
	})
	if err != nil {
		t.Fatalf("FindGrant() error = %v", err)
	}
	if found.ID != grant.ID {
		t.Fatalf("found.ID = %q, want %q", found.ID, grant.ID)
	}

	event := domain.AuditEvent{
		ID:          "audit-1",
		Type:        domain.AuditEventSessionIssued,
		OccurredAt:  now,
		PrincipalID: session.PrincipalID,
		ClientID:    session.ClientID,
		SessionID:   session.ID,
	}
	if err := repo.AppendAuditEvent(context.Background(), event); err != nil {
		t.Fatalf("AppendAuditEvent() error = %v", err)
	}
	events, err := repo.ListAuditEvents(context.Background(), domain.AuditFilter{
		SessionID: session.ID,
		Type:      domain.AuditEventSessionIssued,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events = %+v, want matching audit event", events)
	}
}

// TestStoreTransactionalPorts verifies every port remains usable inside WithinTx.
func TestStoreTransactionalPorts(t *testing.T) {
	t.Parallel()

	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	principal, err := domain.NewPrincipal(domain.PrincipalInput{
		ID:          "principal-1",
		Type:        domain.PrincipalTypeUser,
		DisplayName: "User One",
	}, now)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	client, err := domain.NewClient(domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	}, now)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	session, err := domain.NewSession(domain.SessionInput{
		ID:          "session-1",
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	rule, err := domain.ValidateAndNormalizeRule(domain.Rule{
		ID:     "rule-1",
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
		t.Fatalf("ValidateAndNormalizeRule() error = %v", err)
	}
	grant, err := domain.NewGrant(domain.GrantInput{
		ID:          "grant-1",
		SessionID:   session.ID,
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		Action:      "read",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := grant.Approve("approver-1", "approved", 0, now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Approve() error = %v", err)
	}

	err = repo.WithinTx(context.Background(), func(txRepo store.Repository) error {
		if err := txRepo.CreatePrincipal(context.Background(), principal); err != nil {
			return err
		}
		if err := txRepo.CreateClient(context.Background(), client); err != nil {
			return err
		}
		if _, err := txRepo.ListPrincipals(context.Background()); err != nil {
			return err
		}
		if _, err := txRepo.ListClients(context.Background()); err != nil {
			return err
		}
		if err := txRepo.CreateSession(context.Background(), session); err != nil {
			return err
		}
		loadedSession, err := txRepo.GetSession(context.Background(), session.ID)
		if err != nil {
			return err
		}
		loadedSession.Touch(now.Add(2 * time.Minute))
		if err := txRepo.UpdateSession(context.Background(), loadedSession); err != nil {
			return err
		}
		if _, err := txRepo.ListSessions(context.Background()); err != nil {
			return err
		}
		if err := txRepo.ReplaceRules(context.Background(), []domain.Rule{rule}); err != nil {
			return err
		}
		if _, err := txRepo.ListRules(context.Background()); err != nil {
			return err
		}
		if err := txRepo.CreateGrant(context.Background(), grant); err != nil {
			return err
		}
		loadedGrant, err := txRepo.GetGrant(context.Background(), grant.ID)
		if err != nil {
			return err
		}
		if err := loadedGrant.Redeem(now.Add(3 * time.Minute)); err != nil {
			return err
		}
		if err := txRepo.UpdateGrant(context.Background(), loadedGrant); err != nil {
			return err
		}
		if _, err := txRepo.FindGrant(context.Background(), domain.GrantQuery{
			PrincipalID: principal.ID,
			ClientID:    client.ID,
			Action:      grant.Action,
			Resource:    grant.Resource,
			Fingerprint: grant.Fingerprint,
			State:       domain.GrantStateApproved,
		}); err != nil {
			return err
		}
		if _, err := txRepo.ListGrants(context.Background()); err != nil {
			return err
		}
		if err := txRepo.AppendAuditEvent(context.Background(), domain.AuditEvent{
			ID:          "audit-1",
			Type:        domain.AuditEventGrantApproved,
			OccurredAt:  now,
			PrincipalID: principal.ID,
			ClientID:    client.ID,
			SessionID:   session.ID,
		}); err != nil {
			return err
		}
		if _, err := txRepo.ListAuditEvents(context.Background(), domain.AuditFilter{SessionID: session.ID}); err != nil {
			return err
		}
		return txRepo.WithinTx(context.Background(), func(store.Repository) error { return nil })
	})
	if err != nil {
		t.Fatalf("WithinTx() error = %v", err)
	}
}

// TestStoreErrorBranches verifies not-found and duplicate branches across the store.
func TestStoreErrorBranches(t *testing.T) {
	t.Parallel()

	repo := NewStore()
	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	client, err := domain.NewClient(domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	}, now)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	session, err := domain.NewSession(domain.SessionInput{
		ID:          "session-1",
		PrincipalID: "principal-1",
		ClientID:    client.ID,
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	grant, err := domain.NewGrant(domain.GrantInput{
		ID:          "grant-1",
		SessionID:   session.ID,
		PrincipalID: session.PrincipalID,
		ClientID:    session.ClientID,
		Action:      "read",
		Resource: domain.ResourceRef{
			Namespace: "project:demo",
			Type:      "task",
			ID:        "task-1",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}

	if _, err := repo.GetClient(context.Background(), client.ID); !errors.Is(err, domain.ErrClientNotFound) {
		t.Fatalf("GetClient(missing) error = %v, want ErrClientNotFound", err)
	}
	if err := repo.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if err := repo.CreateClient(context.Background(), client); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("CreateClient(duplicate) error = %v, want ErrAlreadyExists", err)
	}
	if _, err := repo.ListClients(context.Background()); err != nil {
		t.Fatalf("ListClients() error = %v", err)
	}

	if _, err := repo.GetSession(context.Background(), session.ID); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("GetSession(missing) error = %v, want ErrSessionNotFound", err)
	}
	if err := repo.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := repo.CreateSession(context.Background(), session); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("CreateSession(duplicate) error = %v, want ErrAlreadyExists", err)
	}
	missingSession := session
	missingSession.ID = "missing-session"
	if err := repo.UpdateSession(context.Background(), missingSession); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("UpdateSession(missing) error = %v, want ErrSessionNotFound", err)
	}

	if _, err := repo.GetGrant(context.Background(), grant.ID); !errors.Is(err, domain.ErrGrantNotFound) {
		t.Fatalf("GetGrant(missing) error = %v, want ErrGrantNotFound", err)
	}
	if _, err := repo.FindGrant(context.Background(), domain.GrantQuery{
		PrincipalID: grant.PrincipalID,
		ClientID:    grant.ClientID,
		Action:      grant.Action,
		Resource:    grant.Resource,
		Fingerprint: grant.Fingerprint,
		State:       domain.GrantStateApproved,
	}); !errors.Is(err, domain.ErrGrantNotFound) {
		t.Fatalf("FindGrant(missing) error = %v, want ErrGrantNotFound", err)
	}
	if err := repo.CreateGrant(context.Background(), grant); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if err := repo.CreateGrant(context.Background(), grant); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("CreateGrant(duplicate) error = %v, want ErrAlreadyExists", err)
	}
	missingGrant := grant
	missingGrant.ID = "missing-grant"
	if err := repo.UpdateGrant(context.Background(), missingGrant); !errors.Is(err, domain.ErrGrantNotFound) {
		t.Fatalf("UpdateGrant(missing) error = %v, want ErrGrantNotFound", err)
	}

	if err := repo.AppendAuditEvent(context.Background(), domain.AuditEvent{
		ID:         "audit-1",
		Type:       domain.AuditEventSessionIssued,
		OccurredAt: now,
		ClientID:   client.ID,
	}); err != nil {
		t.Fatalf("AppendAuditEvent() error = %v", err)
	}
	if err := repo.AppendAuditEvent(context.Background(), domain.AuditEvent{
		ID:         "audit-2",
		Type:       domain.AuditEventGrantApproved,
		OccurredAt: now.Add(time.Minute),
		ClientID:   client.ID,
	}); err != nil {
		t.Fatalf("AppendAuditEvent(second) error = %v", err)
	}
	events, err := repo.ListAuditEvents(context.Background(), domain.AuditFilter{
		ClientID: client.ID,
		Limit:    1,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(limit) error = %v", err)
	}
	if len(events) != 1 || events[0].ID != "audit-1" {
		t.Fatalf("events = %+v, want first limited event", events)
	}
}
