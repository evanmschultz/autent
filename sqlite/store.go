// Package sqlite contains SQLite-backed adapters for autent.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/evanmschultz/autent/domain"
	"github.com/evanmschultz/autent/store"
)

const defaultTablePrefix = "autent_"

// Options configures the SQLite adapter.
type Options struct {
	// TablePrefix scopes autent tables inside one SQLite database. Valid characters are ASCII letters,
	// digits, and underscores.
	TablePrefix string
}

type tableNames struct {
	principals  string
	clients     string
	sessions    string
	rules       string
	grants      string
	auditEvents string
}

// Store is a SQLite-backed autent repository.
type Store struct {
	db     *sql.DB
	tables tableNames
	ownDB  bool
}

// Open opens or creates a SQLite-backed autent repository and applies migrations.
func Open(path string) (*Store, error) {
	return OpenWithOptions(path, Options{})
}

// OpenWithOptions opens or creates a SQLite-backed autent repository with custom options and applies migrations.
func OpenWithOptions(path string, options Options) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}
	store, err := newStore(db, options, true)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// OpenDB wraps one caller-owned database handle, applies migrations, and returns a SQLite-backed repository.
func OpenDB(db *sql.DB, options Options) (*Store, error) {
	store, err := newStore(db, options, false)
	if err != nil {
		return nil, err
	}
	if err := store.migrate(context.Background()); err != nil {
		return nil, err
	}
	return store, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil || !s.ownDB {
		return nil
	}
	return s.db.Close()
}

func newStore(db *sql.DB, options Options, ownDB bool) (*Store, error) {
	tables, err := newTableNames(options.TablePrefix)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:     db,
		tables: tables,
		ownDB:  ownDB,
	}, nil
}

func newTableNames(prefix string) (tableNames, error) {
	normalized, err := normalizeTablePrefix(prefix)
	if err != nil {
		return tableNames{}, err
	}
	return tableNames{
		principals:  normalized + "principals",
		clients:     normalized + "clients",
		sessions:    normalized + "sessions",
		rules:       normalized + "rules",
		grants:      normalized + "grants",
		auditEvents: normalized + "audit_events",
	}, nil
}

func normalizeTablePrefix(prefix string) (string, error) {
	normalized := strings.TrimSpace(prefix)
	if normalized == "" {
		return defaultTablePrefix, nil
	}
	for _, r := range normalized {
		if r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		return "", fmt.Errorf("table prefix %q: %w", prefix, domain.ErrInvalidConfig)
	}
	return normalized, nil
}

// CreatePrincipal stores a principal.
func (s *Store) CreatePrincipal(ctx context.Context, principal domain.Principal) error {
	return createPrincipal(ctx, s.db, s.tables, principal)
}

// GetPrincipal loads a principal by id.
func (s *Store) GetPrincipal(ctx context.Context, id string) (domain.Principal, error) {
	return getPrincipal(ctx, s.db, s.tables, id)
}

// ListPrincipals returns all stored principals ordered by id.
func (s *Store) ListPrincipals(ctx context.Context) ([]domain.Principal, error) {
	return listPrincipals(ctx, s.db, s.tables)
}

// UpdatePrincipal updates a principal.
func (s *Store) UpdatePrincipal(ctx context.Context, principal domain.Principal) error {
	return updatePrincipal(ctx, s.db, s.tables, principal)
}

// CreateClient stores a client.
func (s *Store) CreateClient(ctx context.Context, client domain.Client) error {
	return createClient(ctx, s.db, s.tables, client)
}

// GetClient loads a client by id.
func (s *Store) GetClient(ctx context.Context, id string) (domain.Client, error) {
	return getClient(ctx, s.db, s.tables, id)
}

// ListClients returns all stored clients ordered by id.
func (s *Store) ListClients(ctx context.Context) ([]domain.Client, error) {
	return listClients(ctx, s.db, s.tables)
}

// UpdateClient updates a client.
func (s *Store) UpdateClient(ctx context.Context, client domain.Client) error {
	return updateClient(ctx, s.db, s.tables, client)
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, session domain.Session) error {
	return createSession(ctx, s.db, s.tables, session)
}

// GetSession loads a session by id.
func (s *Store) GetSession(ctx context.Context, id string) (domain.Session, error) {
	return getSession(ctx, s.db, s.tables, id)
}

// UpdateSession updates a session.
func (s *Store) UpdateSession(ctx context.Context, session domain.Session) error {
	return updateSession(ctx, s.db, s.tables, session)
}

// ListSessions returns all stored sessions ordered by id.
func (s *Store) ListSessions(ctx context.Context) ([]domain.Session, error) {
	return listSessions(ctx, s.db, s.tables)
}

// ReplaceRules replaces the persisted rule set.
func (s *Store) ReplaceRules(ctx context.Context, rules []domain.Rule) error {
	return replaceRules(ctx, s.db, s.tables, rules)
}

// ListRules returns the persisted rule set.
func (s *Store) ListRules(ctx context.Context) ([]domain.Rule, error) {
	return listRules(ctx, s.db, s.tables)
}

// CreateGrant stores a grant.
func (s *Store) CreateGrant(ctx context.Context, grant domain.Grant) error {
	return createGrant(ctx, s.db, s.tables, grant)
}

// GetGrant loads a grant by id.
func (s *Store) GetGrant(ctx context.Context, id string) (domain.Grant, error) {
	return getGrant(ctx, s.db, s.tables, id)
}

// UpdateGrant updates a grant.
func (s *Store) UpdateGrant(ctx context.Context, grant domain.Grant) error {
	return updateGrant(ctx, s.db, s.tables, grant)
}

// FindGrant returns the newest matching grant for a request fingerprint.
func (s *Store) FindGrant(ctx context.Context, query domain.GrantQuery) (domain.Grant, error) {
	return findGrant(ctx, s.db, s.tables, query)
}

// ListGrants returns all stored grants ordered by creation time.
func (s *Store) ListGrants(ctx context.Context) ([]domain.Grant, error) {
	return listGrants(ctx, s.db, s.tables)
}

// AppendAuditEvent appends an audit event.
func (s *Store) AppendAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return appendAuditEvent(ctx, s.db, s.tables, event)
}

// ListAuditEvents returns audit events filtered by the provided filter.
func (s *Store) ListAuditEvents(ctx context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	return listAuditEvents(ctx, s.db, s.tables, filter)
}

// WithinTx runs one function within a SQLite transaction.
func (s *Store) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite tx: %w", err)
	}
	repo := txStore{tx: tx, tables: s.tables}
	if err := fn(repo); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite tx: %w", err)
	}
	return nil
}

type txStore struct {
	tx     *sql.Tx
	tables tableNames
}

func (s txStore) CreatePrincipal(ctx context.Context, principal domain.Principal) error {
	return createPrincipal(ctx, s.tx, s.tables, principal)
}

func (s txStore) GetPrincipal(ctx context.Context, id string) (domain.Principal, error) {
	return getPrincipal(ctx, s.tx, s.tables, id)
}

func (s txStore) ListPrincipals(ctx context.Context) ([]domain.Principal, error) {
	return listPrincipals(ctx, s.tx, s.tables)
}

func (s txStore) UpdatePrincipal(ctx context.Context, principal domain.Principal) error {
	return updatePrincipal(ctx, s.tx, s.tables, principal)
}

func (s txStore) CreateClient(ctx context.Context, client domain.Client) error {
	return createClient(ctx, s.tx, s.tables, client)
}

func (s txStore) GetClient(ctx context.Context, id string) (domain.Client, error) {
	return getClient(ctx, s.tx, s.tables, id)
}

func (s txStore) ListClients(ctx context.Context) ([]domain.Client, error) {
	return listClients(ctx, s.tx, s.tables)
}

func (s txStore) UpdateClient(ctx context.Context, client domain.Client) error {
	return updateClient(ctx, s.tx, s.tables, client)
}

func (s txStore) CreateSession(ctx context.Context, session domain.Session) error {
	return createSession(ctx, s.tx, s.tables, session)
}

func (s txStore) GetSession(ctx context.Context, id string) (domain.Session, error) {
	return getSession(ctx, s.tx, s.tables, id)
}

func (s txStore) UpdateSession(ctx context.Context, session domain.Session) error {
	return updateSession(ctx, s.tx, s.tables, session)
}

func (s txStore) ListSessions(ctx context.Context) ([]domain.Session, error) {
	return listSessions(ctx, s.tx, s.tables)
}

func (s txStore) ReplaceRules(ctx context.Context, rules []domain.Rule) error {
	return replaceRules(ctx, s.tx, s.tables, rules)
}

func (s txStore) ListRules(ctx context.Context) ([]domain.Rule, error) {
	return listRules(ctx, s.tx, s.tables)
}

func (s txStore) CreateGrant(ctx context.Context, grant domain.Grant) error {
	return createGrant(ctx, s.tx, s.tables, grant)
}

func (s txStore) GetGrant(ctx context.Context, id string) (domain.Grant, error) {
	return getGrant(ctx, s.tx, s.tables, id)
}

func (s txStore) UpdateGrant(ctx context.Context, grant domain.Grant) error {
	return updateGrant(ctx, s.tx, s.tables, grant)
}

func (s txStore) FindGrant(ctx context.Context, query domain.GrantQuery) (domain.Grant, error) {
	return findGrant(ctx, s.tx, s.tables, query)
}

func (s txStore) ListGrants(ctx context.Context) ([]domain.Grant, error) {
	return listGrants(ctx, s.tx, s.tables)
}

func (s txStore) AppendAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return appendAuditEvent(ctx, s.tx, s.tables, event)
}

func (s txStore) ListAuditEvents(ctx context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	return listAuditEvents(ctx, s.tx, s.tables, filter)
}

func (s txStore) WithinTx(_ context.Context, fn func(store.Repository) error) error {
	return fn(s)
}

type execQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func createPrincipal(ctx context.Context, db execQuerier, tables tableNames, principal domain.Principal) error {
	payload, err := json.Marshal(principal)
	if err != nil {
		return fmt.Errorf("marshal principal: %w", err)
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, payload) VALUES (?, ?)`, tables.principals), principal.ID, payload)
	if isUniqueErr(err) {
		return fmt.Errorf("create principal %q: %w", principal.ID, domain.ErrAlreadyExists)
	}
	return err
}

func getPrincipal(ctx context.Context, db execQuerier, tables tableNames, id string) (domain.Principal, error) {
	var payload []byte
	err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT payload FROM %s WHERE id = ?`, tables.principals), strings.TrimSpace(id)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Principal{}, domain.ErrPrincipalNotFound
	}
	if err != nil {
		return domain.Principal{}, err
	}
	var principal domain.Principal
	if err := json.Unmarshal(payload, &principal); err != nil {
		return domain.Principal{}, fmt.Errorf("decode principal: %w", err)
	}
	return principal, nil
}

func updatePrincipal(ctx context.Context, db execQuerier, tables tableNames, principal domain.Principal) error {
	payload, err := json.Marshal(principal)
	if err != nil {
		return fmt.Errorf("marshal principal: %w", err)
	}
	result, err := db.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET payload = ? WHERE id = ?`, tables.principals), payload, principal.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrPrincipalNotFound
	}
	return nil
}

func listPrincipals(ctx context.Context, db execQuerier, tables tableNames) ([]domain.Principal, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT payload FROM %s ORDER BY id`, tables.principals))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []domain.Principal
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var principal domain.Principal
		if err := json.Unmarshal(payload, &principal); err != nil {
			return nil, err
		}
		out = append(out, principal)
	}
	return out, rows.Err()
}

func createClient(ctx context.Context, db execQuerier, tables tableNames, client domain.Client) error {
	payload, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("marshal client: %w", err)
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, payload) VALUES (?, ?)`, tables.clients), client.ID, payload)
	if isUniqueErr(err) {
		return fmt.Errorf("create client %q: %w", client.ID, domain.ErrAlreadyExists)
	}
	return err
}

func getClient(ctx context.Context, db execQuerier, tables tableNames, id string) (domain.Client, error) {
	var payload []byte
	err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT payload FROM %s WHERE id = ?`, tables.clients), strings.TrimSpace(id)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Client{}, domain.ErrClientNotFound
	}
	if err != nil {
		return domain.Client{}, err
	}
	var client domain.Client
	if err := json.Unmarshal(payload, &client); err != nil {
		return domain.Client{}, fmt.Errorf("decode client: %w", err)
	}
	return client, nil
}

func updateClient(ctx context.Context, db execQuerier, tables tableNames, client domain.Client) error {
	payload, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("marshal client: %w", err)
	}
	result, err := db.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET payload = ? WHERE id = ?`, tables.clients), payload, client.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrClientNotFound
	}
	return nil
}

func listClients(ctx context.Context, db execQuerier, tables tableNames) ([]domain.Client, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT payload FROM %s ORDER BY id`, tables.clients))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []domain.Client
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var client domain.Client
		if err := json.Unmarshal(payload, &client); err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, rows.Err()
}

func createSession(ctx context.Context, db execQuerier, tables tableNames, session domain.Session) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, principal_id, client_id, expires_at, payload) VALUES (?, ?, ?, ?, ?)`, tables.sessions), session.ID, session.PrincipalID, session.ClientID, session.ExpiresAt.UTC().Format(time.RFC3339Nano), payload)
	if isUniqueErr(err) {
		return fmt.Errorf("create session %q: %w", session.ID, domain.ErrAlreadyExists)
	}
	return err
}

func getSession(ctx context.Context, db execQuerier, tables tableNames, id string) (domain.Session, error) {
	var payload []byte
	err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT payload FROM %s WHERE id = ?`, tables.sessions), strings.TrimSpace(id)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Session{}, domain.ErrSessionNotFound
	}
	if err != nil {
		return domain.Session{}, err
	}
	var session domain.Session
	if err := json.Unmarshal(payload, &session); err != nil {
		return domain.Session{}, fmt.Errorf("decode session: %w", err)
	}
	return session, nil
}

func updateSession(ctx context.Context, db execQuerier, tables tableNames, session domain.Session) error {
	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	result, err := db.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET principal_id = ?, client_id = ?, expires_at = ?, payload = ? WHERE id = ?`, tables.sessions), session.PrincipalID, session.ClientID, session.ExpiresAt.UTC().Format(time.RFC3339Nano), payload, session.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrSessionNotFound
	}
	return nil
}

func listSessions(ctx context.Context, db execQuerier, tables tableNames) ([]domain.Session, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT payload FROM %s ORDER BY id`, tables.sessions))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []domain.Session
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var session domain.Session
		if err := json.Unmarshal(payload, &session); err != nil {
			return nil, err
		}
		out = append(out, session)
	}
	return out, rows.Err()
}

func replaceRules(ctx context.Context, db execQuerier, tables tableNames, rules []domain.Rule) error {
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s`, tables.rules)); err != nil {
		return err
	}
	for _, rule := range rules {
		payload, err := json.Marshal(rule)
		if err != nil {
			return fmt.Errorf("marshal rule: %w", err)
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, priority, payload) VALUES (?, ?, ?)`, tables.rules), rule.ID, rule.Priority, payload); err != nil {
			return err
		}
	}
	return nil
}

func listRules(ctx context.Context, db execQuerier, tables tableNames) ([]domain.Rule, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT payload FROM %s ORDER BY priority DESC, id ASC`, tables.rules))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []domain.Rule
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var rule domain.Rule
		if err := json.Unmarshal(payload, &rule); err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

func createGrant(ctx context.Context, db execQuerier, tables tableNames, grant domain.Grant) error {
	payload, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("marshal grant: %w", err)
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, principal_id, client_id, action, resource_namespace, resource_type, resource_id, fingerprint, state, created_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, tables.grants),
		grant.ID,
		grant.PrincipalID,
		grant.ClientID,
		string(grant.Action),
		grant.Resource.Namespace,
		grant.Resource.Type,
		grant.Resource.ID,
		grant.Fingerprint,
		string(grant.State),
		grant.CreatedAt.UTC().Format(time.RFC3339Nano),
		payload,
	)
	if isUniqueErr(err) {
		return fmt.Errorf("create grant %q: %w", grant.ID, domain.ErrAlreadyExists)
	}
	return err
}

func getGrant(ctx context.Context, db execQuerier, tables tableNames, id string) (domain.Grant, error) {
	var payload []byte
	err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT payload FROM %s WHERE id = ?`, tables.grants), strings.TrimSpace(id)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Grant{}, domain.ErrGrantNotFound
	}
	if err != nil {
		return domain.Grant{}, err
	}
	var grant domain.Grant
	if err := json.Unmarshal(payload, &grant); err != nil {
		return domain.Grant{}, fmt.Errorf("decode grant: %w", err)
	}
	return grant, nil
}

func updateGrant(ctx context.Context, db execQuerier, tables tableNames, grant domain.Grant) error {
	payload, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("marshal grant: %w", err)
	}
	result, err := db.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET state = ?, created_at = ?, payload = ? WHERE id = ?`, tables.grants), string(grant.State), grant.CreatedAt.UTC().Format(time.RFC3339Nano), payload, grant.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrGrantNotFound
	}
	return nil
}

func findGrant(ctx context.Context, db execQuerier, tables tableNames, query domain.GrantQuery) (domain.Grant, error) {
	row := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT payload FROM %s WHERE principal_id = ? AND client_id = ? AND action = ? AND resource_namespace = ? AND resource_type = ? AND resource_id = ? AND fingerprint = ? AND state = ? ORDER BY created_at DESC, id DESC LIMIT 1`, tables.grants),
		query.PrincipalID,
		query.ClientID,
		string(query.Action),
		query.Resource.Namespace,
		query.Resource.Type,
		query.Resource.ID,
		query.Fingerprint,
		string(query.State),
	)
	var payload []byte
	if err := row.Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.Grant{}, domain.ErrGrantNotFound
	} else if err != nil {
		return domain.Grant{}, err
	}
	var grant domain.Grant
	if err := json.Unmarshal(payload, &grant); err != nil {
		return domain.Grant{}, fmt.Errorf("decode grant: %w", err)
	}
	return grant, nil
}

func listGrants(ctx context.Context, db execQuerier, tables tableNames) ([]domain.Grant, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT payload FROM %s ORDER BY created_at ASC, id ASC`, tables.grants))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []domain.Grant
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var grant domain.Grant
		if err := json.Unmarshal(payload, &grant); err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}

func appendAuditEvent(ctx context.Context, db execQuerier, tables tableNames, event domain.AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, occurred_at, principal_id, client_id, session_id, event_type, payload) VALUES (?, ?, ?, ?, ?, ?, ?)`, tables.auditEvents),
		event.ID,
		event.OccurredAt.UTC().Format(time.RFC3339Nano),
		event.PrincipalID,
		event.ClientID,
		event.SessionID,
		string(event.Type),
		payload,
	)
	if isUniqueErr(err) {
		return fmt.Errorf("append audit event %q: %w", event.ID, domain.ErrAlreadyExists)
	}
	return err
}

func listAuditEvents(ctx context.Context, db execQuerier, tables tableNames, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	var (
		builder strings.Builder
		args    []any
	)
	_, _ = fmt.Fprintf(&builder, `SELECT payload FROM %s WHERE 1=1`, tables.auditEvents)
	if filter.PrincipalID != "" {
		builder.WriteString(` AND principal_id = ?`)
		args = append(args, filter.PrincipalID)
	}
	if filter.ClientID != "" {
		builder.WriteString(` AND client_id = ?`)
		args = append(args, filter.ClientID)
	}
	if filter.SessionID != "" {
		builder.WriteString(` AND session_id = ?`)
		args = append(args, filter.SessionID)
	}
	if filter.Type != "" {
		builder.WriteString(` AND event_type = ?`)
		args = append(args, string(filter.Type))
	}
	builder.WriteString(` ORDER BY occurred_at ASC, id ASC`)
	if filter.Limit > 0 {
		builder.WriteString(` LIMIT ?`)
		args = append(args, filter.Limit)
	}
	rows, err := db.QueryContext(ctx, builder.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var out []domain.AuditEvent
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event domain.AuditEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, payload BLOB NOT NULL)`, s.tables.principals),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, payload BLOB NOT NULL)`, s.tables.clients),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, client_id TEXT NOT NULL, expires_at TEXT NOT NULL, payload BLOB NOT NULL)`, s.tables.sessions),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, priority INTEGER NOT NULL, payload BLOB NOT NULL)`, s.tables.rules),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, client_id TEXT NOT NULL, action TEXT NOT NULL, resource_namespace TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, payload BLOB NOT NULL)`, s.tables.grants),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, principal_id TEXT, client_id TEXT, session_id TEXT, event_type TEXT NOT NULL, payload BLOB NOT NULL)`, s.tables.auditEvents),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_lookup_idx ON %s (principal_id, client_id, action, resource_namespace, resource_type, resource_id, fingerprint, state, created_at DESC)`, s.tables.grants, s.tables.grants),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_time_idx ON %s (occurred_at ASC, id ASC)`, s.tables.auditEvents, s.tables.auditEvents),
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply sqlite migration %q: %w", statement, err)
		}
	}
	return nil
}

func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique")
}
