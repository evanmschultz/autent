package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/evanmschultz/autent/app"
	"github.com/evanmschultz/autent/domain"
	"github.com/evanmschultz/autent/store"
	"github.com/evanmschultz/autent/token"
)

// TestSQLiteServiceFlow verifies the core auth flow against the SQLite adapter.
func TestSQLiteServiceFlow(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "autent.db")
	repo, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close()
	})

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	nextID := 0
	service, err := app.NewService(app.Config{
		Repository: repo,
		Secrets:    token.OpaqueSecretManager{},
		Clock: func() time.Time {
			return now
		},
		IDGenerator: func() string {
			nextID++
			return fmt.Sprintf("sqlite-%d", nextID)
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

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
	if err := service.ReplaceRules(context.Background(), []domain.Rule{
		{
			ID: "rule-read",
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
			Effect:   domain.EffectAllow,
			Priority: 10,
		},
	}); err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	issued, err := service.IssueSession(context.Background(), app.IssueSessionInput{
		PrincipalID: principal.ID,
		ClientID:    client.ID,
	})
	if err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}
	decision, err := service.Authorize(context.Background(), app.AuthorizeInput{
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
	if decision.Code != domain.DecisionAllow {
		t.Fatalf("decision.Code = %q, want %q", decision.Code, domain.DecisionAllow)
	}

	events, err := service.ListAuditEvents(context.Background(), domain.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAuditEvents() error = %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events to be persisted")
	}
}

// TestSQLiteRepositoryCRUD verifies direct store persistence behavior.
func TestSQLiteRepositoryCRUD(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "crud.db")
	repo, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close()
	})

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
	principals, err := repo.ListPrincipals(context.Background())
	if err != nil {
		t.Fatalf("ListPrincipals() error = %v", err)
	}
	if len(principals) != 1 || principals[0].ID != principal.ID {
		t.Fatalf("principals = %+v, want one principal", principals)
	}
	if _, err := repo.GetPrincipal(context.Background(), principal.ID); err != nil {
		t.Fatalf("GetPrincipal() error = %v", err)
	}

	client, err := domain.NewClient(domain.ClientInput{
		ID:          "client-1",
		DisplayName: "CLI",
		Type:        "cli",
	}, now)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := repo.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	clients, err := repo.ListClients(context.Background())
	if err != nil {
		t.Fatalf("ListClients() error = %v", err)
	}
	if len(clients) != 1 || clients[0].ID != client.ID {
		t.Fatalf("clients = %+v, want one client", clients)
	}
	if _, err := repo.GetClient(context.Background(), client.ID); err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}

	session, err := domain.NewStoredSession(domain.StoredSessionInput{
		ID:          "session-1",
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewStoredSession() error = %v", err)
	}
	if err := repo.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if _, err := repo.GetSession(context.Background(), session.ID); err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	session.Touch(now.Add(5 * time.Minute))
	if err := repo.UpdateSession(context.Background(), session); err != nil {
		t.Fatalf("UpdateSession() error = %v", err)
	}
	sessions, err := repo.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != session.ID {
		t.Fatalf("sessions = %+v, want one session", sessions)
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
	if err := grant.Approve("approver-1", "approved", 1, now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Approve() error = %v", err)
	}
	if err := repo.CreateGrant(context.Background(), grant); err != nil {
		t.Fatalf("CreateGrant() error = %v", err)
	}
	if _, err := repo.GetGrant(context.Background(), grant.ID); err != nil {
		t.Fatalf("GetGrant() error = %v", err)
	}
	grant.UsageCount = 1
	if err := repo.UpdateGrant(context.Background(), grant); err != nil {
		t.Fatalf("UpdateGrant() error = %v", err)
	}
	found, err := repo.FindGrant(context.Background(), domain.GrantQuery{
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
	if found.ID != grant.ID {
		t.Fatalf("found.ID = %q, want %q", found.ID, grant.ID)
	}
	grants, err := repo.ListGrants(context.Background())
	if err != nil {
		t.Fatalf("ListGrants() error = %v", err)
	}
	if len(grants) != 1 || grants[0].UsageCount != 1 {
		t.Fatalf("grants = %+v, want one updated grant", grants)
	}

	event := domain.AuditEvent{
		ID:          "audit-1",
		Type:        domain.AuditEventGrantApproved,
		OccurredAt:  now,
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SessionID:   session.ID,
		Action:      "read",
		Resource:    grant.Resource,
	}
	if err := repo.AppendAuditEvent(context.Background(), event); err != nil {
		t.Fatalf("AppendAuditEvent() error = %v", err)
	}
	events, err := repo.ListAuditEvents(context.Background(), domain.AuditFilter{
		SessionID: session.ID,
		Type:      domain.AuditEventGrantApproved,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events = %+v, want one audit event", events)
	}
}

// TestSQLiteWithinTxRollback verifies transactional writes roll back on error.
func TestSQLiteWithinTxRollback(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "tx.db")
	repo, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close()
	})

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

// TestSQLiteOpenDBWithPrefix verifies the adapter can share one caller-owned database with prefixed tables.
func TestSQLiteOpenDBWithPrefix(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "shared.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	repo, err := OpenDB(db, Options{TablePrefix: "hostauth_"})
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
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
	if _, err := repo.GetPrincipal(context.Background(), principal.ID); err != nil {
		t.Fatalf("GetPrincipal() error = %v", err)
	}

	var count int
	row := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM hostauth_principals")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("Scan(prefixed principals count) error = %v", err)
	}
	if count != 1 {
		t.Fatalf("prefixed principals count = %d, want 1", count)
	}
}

// TestSQLiteOpenRejectsInvalidPrefix verifies shared-DB table prefixes are validated.
func TestSQLiteOpenRejectsInvalidPrefix(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "invalid-prefix.db")
	if _, err := OpenWithOptions(dbPath, Options{TablePrefix: "bad-prefix;"}); !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("OpenWithOptions() error = %v, want ErrInvalidConfig", err)
	}
	if _, err := OpenWithOptions(dbPath, Options{TablePrefix: "123_"}); !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("OpenWithOptions(numeric prefix) error = %v, want ErrInvalidConfig", err)
	}
}

// TestSQLiteOpenRecordsSchemaVersion verifies the adapter records its current schema version.
func TestSQLiteOpenRecordsSchemaVersion(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "schema-version.db")
	repo, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close()
	})

	var version int
	row := repo.db.QueryRowContext(context.Background(), "SELECT version FROM autent_schema_migrations LIMIT 1")
	if err := row.Scan(&version); err != nil {
		t.Fatalf("Scan(schema version) error = %v", err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
	}
}

// TestSQLiteWithinTxCRUD verifies transaction-scoped repository methods.
func TestSQLiteWithinTxCRUD(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "tx-crud.db")
	repo, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close()
	})

	ctx := context.Background()
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
	session, err := domain.NewStoredSession(domain.StoredSessionInput{
		ID:          "session-1",
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewStoredSession() error = %v", err)
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
		if _, err := txRepo.GetSession(ctx, session.ID); err != nil {
			return err
		}
		if _, err := txRepo.GetGrant(ctx, grant.ID); err != nil {
			return err
		}
		if principals, err := txRepo.ListPrincipals(ctx); err != nil || len(principals) != 1 {
			t.Fatalf("txRepo.ListPrincipals() = %d, %v, want 1, nil", len(principals), err)
		}
		if clients, err := txRepo.ListClients(ctx); err != nil || len(clients) != 1 {
			t.Fatalf("txRepo.ListClients() = %d, %v, want 1, nil", len(clients), err)
		}
		if sessions, err := txRepo.ListSessions(ctx); err != nil || len(sessions) != 1 {
			t.Fatalf("txRepo.ListSessions() = %d, %v, want 1, nil", len(sessions), err)
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

// TestSQLiteTransactionalPorts verifies every SQLite tx wrapper stays wired correctly.
func TestSQLiteTransactionalPorts(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "tx-ports.db")
	repo, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close()
	})

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
	session, err := domain.NewStoredSession(domain.StoredSessionInput{
		ID:          "session-1",
		PrincipalID: principal.ID,
		ClientID:    client.ID,
		SecretHash:  []byte("hash"),
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewStoredSession() error = %v", err)
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
