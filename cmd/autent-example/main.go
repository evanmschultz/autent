package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/evanmschultz/autent/app"
	"github.com/evanmschultz/autent/domain"
	"github.com/evanmschultz/autent/sqlite"
	"github.com/evanmschultz/autent/token"
)

// stdout and stderr are package-level writers so the entrypoint stays testable.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr

	// exitFunc terminates the process after entrypoint failures.
	exitFunc = os.Exit
	// osArgs provides a test seam for the process arguments.
	osArgs = os.Args
)

// sqliteFlags collects common SQLite CLI flag bindings.
type sqliteFlags struct {
	dbPath *string
	prefix *string
}

// sessionView redacts internal verifier material from operator-facing output.
type sessionView struct {
	ID               string            `json:"ID"`
	PrincipalID      string            `json:"PrincipalID"`
	ClientID         string            `json:"ClientID"`
	IssuedAt         time.Time         `json:"IssuedAt"`
	ExpiresAt        time.Time         `json:"ExpiresAt"`
	LastSeenAt       time.Time         `json:"LastSeenAt"`
	RevokedAt        *time.Time        `json:"RevokedAt"`
	RevocationReason string            `json:"RevocationReason"`
	Metadata         map[string]string `json:"Metadata"`
}

// main executes the example CLI and exits non-zero on failure.
func main() {
	if err := run(osArgs[1:], stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "autent-example: %v\n", err)
		exitFunc(1)
	}
}

// run dispatches one example CLI command.
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		printUsage(out)
		return nil
	}

	switch args[0] {
	case "help":
		printUsage(out)
		return nil
	case "principal":
		return runPrincipal(args[1:], out)
	case "client":
		return runClient(args[1:], out)
	case "policy":
		return runPolicy(args[1:], out)
	case "session":
		return runSession(args[1:], out)
	case "authz":
		return runAuthz(args[1:], out)
	case "grant":
		return runGrant(args[1:], out)
	case "audit":
		return runAudit(args[1:], out)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// runPrincipal handles principal subcommands.
func runPrincipal(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: principal create|enable|disable")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("principal create", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		id := fs.String("id", "", "principal id")
		principalType := fs.String("type", "user", "principal type")
		name := fs.String("name", "", "display name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		principal, err := service.RegisterPrincipal(context.Background(), domain.PrincipalInput{
			ID:          *id,
			Type:        domain.PrincipalType(*principalType),
			DisplayName: *name,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, principal)
	case "enable", "disable":
		fs := flag.NewFlagSet("principal status", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		id := fs.String("id", "", "principal id")
		actor := fs.String("actor", "operator", "operator id")
		reason := fs.String("reason", "", "status change reason")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		status := domain.StatusActive
		if args[0] == "disable" {
			status = domain.StatusDisabled
		}
		principal, err := service.UpdatePrincipalStatus(context.Background(), app.UpdatePrincipalStatusInput{
			PrincipalID: *id,
			Status:      status,
			Actor:       *actor,
			Reason:      *reason,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, principal)
	default:
		return errors.New("usage: principal create|enable|disable")
	}
}

// runClient handles client subcommands.
func runClient(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: client create|enable|disable")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("client create", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		id := fs.String("id", "", "client id")
		clientType := fs.String("type", "", "client type")
		name := fs.String("name", "", "display name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		client, err := service.RegisterClient(context.Background(), domain.ClientInput{
			ID:          *id,
			DisplayName: *name,
			Type:        *clientType,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, client)
	case "enable", "disable":
		fs := flag.NewFlagSet("client status", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		id := fs.String("id", "", "client id")
		actor := fs.String("actor", "operator", "operator id")
		reason := fs.String("reason", "", "status change reason")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		status := domain.StatusActive
		if args[0] == "disable" {
			status = domain.StatusDisabled
		}
		client, err := service.UpdateClientStatus(context.Background(), app.UpdateClientStatusInput{
			ClientID: *id,
			Status:   status,
			Actor:    *actor,
			Reason:   *reason,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, client)
	default:
		return errors.New("usage: client create|enable|disable")
	}
}

// runPolicy handles `policy load-demo`.
func runPolicy(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "load-demo" {
		return errors.New("usage: policy load-demo")
	}
	fs := flag.NewFlagSet("policy load-demo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sqliteConfig := bindSQLiteFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
	if err != nil {
		return err
	}
	defer cleanup()

	rules := demoRules()
	if err := service.ReplaceRules(context.Background(), rules); err != nil {
		return err
	}
	return writeJSON(out, map[string]any{
		"loaded_rules": len(rules),
		"rule_ids":     []string{"demo-read", "demo-mutate-with-grant"},
		"db_prefix":    *sqliteConfig.prefix,
	})
}

// runSession handles `session issue`, `session list`, and `session revoke`.
func runSession(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: session issue|list|revoke")
	}
	switch args[0] {
	case "issue":
		fs := flag.NewFlagSet("session issue", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		principalID := fs.String("principal", "", "principal id")
		clientID := fs.String("client", "", "client id")
		ttl := fs.Duration("ttl", 8*time.Hour, "session TTL")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		issued, err := service.IssueSession(context.Background(), app.IssueSessionInput{
			PrincipalID: *principalID,
			ClientID:    *clientID,
			TTL:         *ttl,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, map[string]any{
			"session_id":     issued.Session.ID,
			"session_secret": issued.Secret,
			"principal_id":   issued.Session.PrincipalID,
			"client_id":      issued.Session.ClientID,
			"issued_at":      issued.Session.IssuedAt,
			"expires_at":     issued.Session.ExpiresAt,
		})
	case "list":
		fs := flag.NewFlagSet("session list", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		sessionID := fs.String("session", "", "session id")
		principalID := fs.String("principal", "", "principal id")
		clientID := fs.String("client", "", "client id")
		state := fs.String("state", "", "session state filter: active, revoked, expired")
		limit := fs.Int("limit", 0, "max sessions to return")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		sessions, err := service.ListSessions(context.Background(), app.SessionFilter{
			SessionID:   *sessionID,
			PrincipalID: *principalID,
			ClientID:    *clientID,
			State:       app.SessionState(*state),
			Limit:       *limit,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, redactSessions(sessions))
	case "revoke":
		fs := flag.NewFlagSet("session revoke", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		sessionID := fs.String("session", "", "session id")
		reason := fs.String("reason", "revoked_by_operator", "revocation reason")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		session, err := service.RevokeSession(context.Background(), *sessionID, *reason)
		if err != nil {
			return err
		}
		return writeJSON(out, redactSession(session))
	default:
		return errors.New("usage: session issue|list|revoke")
	}
}

// runAuthz handles `authz check`.
func runAuthz(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: authz check")
	}
	fs := flag.NewFlagSet("authz check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sqliteConfig := bindSQLiteFlags(fs)
	sessionID := fs.String("session", "", "session id")
	secret := fs.String("secret", "", "session secret")
	action := fs.String("action", "", "action")
	namespace := fs.String("namespace", "", "resource namespace")
	resourceType := fs.String("resource-type", "", "resource type")
	resourceID := fs.String("resource-id", "", "resource id")
	contextValue := fs.String("context", "", "comma-separated key=value pairs")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
	if err != nil {
		return err
	}
	defer cleanup()

	contextMap, err := parseContext(*contextValue)
	if err != nil {
		return err
	}
	decision, err := service.Authorize(context.Background(), app.AuthorizeInput{
		SessionID:     *sessionID,
		SessionSecret: *secret,
		Action:        domain.Action(*action),
		Resource: domain.ResourceRef{
			Namespace: *namespace,
			Type:      *resourceType,
			ID:        *resourceID,
		},
		Context: contextMap,
	})
	if err != nil {
		return err
	}
	return writeJSON(out, decision)
}

// runGrant handles grant lifecycle subcommands.
func runGrant(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: grant request|approve|deny|cancel")
	}
	switch args[0] {
	case "request":
		fs := flag.NewFlagSet("grant request", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		sessionID := fs.String("session", "", "session id")
		secret := fs.String("secret", "", "session secret")
		action := fs.String("action", "", "action")
		namespace := fs.String("namespace", "", "resource namespace")
		resourceType := fs.String("resource-type", "", "resource type")
		resourceID := fs.String("resource-id", "", "resource id")
		contextValue := fs.String("context", "", "comma-separated key=value pairs")
		reason := fs.String("reason", "", "grant reason")
		ttl := fs.Duration("ttl", time.Hour, "grant TTL")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		contextMap, err := parseContext(*contextValue)
		if err != nil {
			return err
		}
		grant, err := service.RequestGrant(context.Background(), app.RequestGrantInput{
			SessionID:     *sessionID,
			SessionSecret: *secret,
			Action:        domain.Action(*action),
			Resource: domain.ResourceRef{
				Namespace: *namespace,
				Type:      *resourceType,
				ID:        *resourceID,
			},
			Context: contextMap,
			Reason:  *reason,
			TTL:     *ttl,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, grant)
	case "approve":
		fs := flag.NewFlagSet("grant approve", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		grantID := fs.String("grant-id", "", "grant id")
		actor := fs.String("actor", "", "approver id")
		note := fs.String("note", "", "approval note")
		usageLimit := fs.Int("usage-limit", 1, "grant usage limit; 0 means unbounded")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		grant, err := service.ResolveGrant(context.Background(), app.ResolveGrantInput{
			GrantID:    *grantID,
			Approve:    true,
			Actor:      *actor,
			Note:       *note,
			UsageLimit: *usageLimit,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, grant)
	case "deny":
		fs := flag.NewFlagSet("grant deny", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		grantID := fs.String("grant-id", "", "grant id")
		actor := fs.String("actor", "", "approver id")
		note := fs.String("note", "", "denial note")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		grant, err := service.ResolveGrant(context.Background(), app.ResolveGrantInput{
			GrantID: *grantID,
			Actor:   *actor,
			Note:    *note,
		})
		if err != nil {
			return err
		}
		return writeJSON(out, grant)
	case "cancel":
		fs := flag.NewFlagSet("grant cancel", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		sqliteConfig := bindSQLiteFlags(fs)
		grantID := fs.String("grant-id", "", "grant id")
		actor := fs.String("actor", "operator", "operator id")
		note := fs.String("note", "", "cancel note")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
		if err != nil {
			return err
		}
		defer cleanup()

		grant, err := service.CancelGrant(context.Background(), *grantID, *actor, *note)
		if err != nil {
			return err
		}
		return writeJSON(out, grant)
	default:
		return errors.New("usage: grant request|approve|deny|cancel")
	}
}

// runAudit handles `audit list`.
func runAudit(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "list" {
		return errors.New("usage: audit list")
	}
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sqliteConfig := bindSQLiteFlags(fs)
	principalID := fs.String("principal", "", "principal id")
	clientID := fs.String("client", "", "client id")
	sessionID := fs.String("session", "", "session id")
	eventType := fs.String("type", "", "event type")
	limit := fs.Int("limit", 0, "max events to return")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	service, cleanup, err := openService(*sqliteConfig.dbPath, *sqliteConfig.prefix)
	if err != nil {
		return err
	}
	defer cleanup()

	events, err := service.ListAuditEvents(context.Background(), domain.AuditFilter{
		PrincipalID: *principalID,
		ClientID:    *clientID,
		SessionID:   *sessionID,
		Type:        domain.AuditEventType(*eventType),
		Limit:       *limit,
	})
	if err != nil {
		return err
	}
	return writeJSON(out, events)
}

// openService opens the SQLite repository and constructs one app service.
func openService(dbPath, prefix string) (*app.Service, func(), error) {
	repo, err := sqlite.OpenWithOptions(dbPath, sqlite.Options{TablePrefix: prefix})
	if err != nil {
		return nil, nil, err
	}
	service, err := app.NewService(app.Config{
		Repository:  repo,
		Secrets:     token.OpaqueSecretManager{},
		IDGenerator: randomID,
	})
	if err != nil {
		_ = repo.Close()
		return nil, nil, err
	}
	return service, func() {
		_ = repo.Close()
	}, nil
}

// demoRules returns the built-in demo policy used for human testing.
func demoRules() []domain.Rule {
	return []domain.Rule{
		{
			ID:     "demo-read",
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
			Priority: 100,
		},
		{
			ID:     "demo-mutate-with-grant",
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
			Conditions: []domain.Condition{
				{Key: "scope", Operator: domain.ConditionEquals, Value: "current"},
			},
			Escalation: &domain.EscalationRequirement{Allowed: true},
			Priority:   90,
		},
	}
}

// bindSQLiteFlags binds common SQLite-related flags to one flag set.
func bindSQLiteFlags(fs *flag.FlagSet) sqliteFlags {
	return sqliteFlags{
		dbPath: fs.String("db", "autent.db", "SQLite database path"),
		prefix: fs.String("db-prefix", "autent_", "SQLite table prefix for embedding in an existing app database"),
	}
}

// parseContext parses one comma-separated `key=value` context string.
func parseContext(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid context pair %q", pair)
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out, nil
}

// printUsage writes the CLI usage summary.
func printUsage(out io.Writer) {
	_, _ = fmt.Fprintln(out, "autent-example commands:")
	_, _ = fmt.Fprintln(out, "  principal create --db <path> [--db-prefix autent_] --id <id> --type <user|agent|service> --name <name>")
	_, _ = fmt.Fprintln(out, "  principal enable|disable --db <path> [--db-prefix autent_] --id <id> [--actor <id>] [--reason <reason>]")
	_, _ = fmt.Fprintln(out, "  client create --db <path> [--db-prefix autent_] --id <id> --type <type> --name <name>")
	_, _ = fmt.Fprintln(out, "  client enable|disable --db <path> [--db-prefix autent_] --id <id> [--actor <id>] [--reason <reason>]")
	_, _ = fmt.Fprintln(out, "  policy load-demo --db <path> [--db-prefix autent_]")
	_, _ = fmt.Fprintln(out, "  session issue --db <path> [--db-prefix autent_] --principal <id> --client <id> [--ttl 8h]")
	_, _ = fmt.Fprintln(out, "  session list --db <path> [--db-prefix autent_] [--session <id>] [--principal <id>] [--client <id>] [--state <active|revoked|expired>] [--limit <n>]")
	_, _ = fmt.Fprintln(out, "  session revoke --db <path> [--db-prefix autent_] --session <id> [--reason <reason>]")
	_, _ = fmt.Fprintln(out, "  authz check --db <path> [--db-prefix autent_] --session <id> --secret <secret> --action <action> --namespace <ns> --resource-type <type> --resource-id <id> [--context key=value,...]")
	_, _ = fmt.Fprintln(out, "  grant request --db <path> [--db-prefix autent_] --session <id> --secret <secret> --action <action> --namespace <ns> --resource-type <type> --resource-id <id> [--context key=value,...] [--reason <reason>]")
	_, _ = fmt.Fprintln(out, "  grant approve --db <path> [--db-prefix autent_] --grant-id <id> --actor <actor> [--note <note>] [--usage-limit 1]")
	_, _ = fmt.Fprintln(out, "  grant deny --db <path> [--db-prefix autent_] --grant-id <id> --actor <actor> [--note <note>]")
	_, _ = fmt.Fprintln(out, "  grant cancel --db <path> [--db-prefix autent_] --grant-id <id> [--actor <id>] [--note <note>]")
	_, _ = fmt.Fprintln(out, "  audit list --db <path> [--db-prefix autent_] [--principal <id>] [--client <id>] [--session <id>] [--type <event>] [--limit <n>]")
}

// redactSessions converts caller-safe service session views into stable operator-facing JSON.
func redactSessions(sessions []app.SessionView) []sessionView {
	views := make([]sessionView, 0, len(sessions))
	for _, session := range sessions {
		views = append(views, redactSession(session))
	}
	return views
}

// writeJSON writes one value as indented JSON.
func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// randomID returns one opaque identifier for the example CLI.
func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("autent-%d", time.Now().UnixNano())
	}
	return "autent-" + hex.EncodeToString(buf)
}

// redactSession returns a session view safe for operator-facing output.
func redactSession(session app.SessionView) sessionView {
	return sessionView{
		ID:               session.ID,
		PrincipalID:      session.PrincipalID,
		ClientID:         session.ClientID,
		IssuedAt:         session.IssuedAt,
		ExpiresAt:        session.ExpiresAt,
		LastSeenAt:       session.LastSeenAt,
		RevokedAt:        session.RevokedAt,
		RevocationReason: session.RevocationReason,
		Metadata:         session.Metadata,
	}
}
