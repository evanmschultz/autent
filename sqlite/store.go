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

// defaultTablePrefix scopes autent tables inside one SQLite database by default.
const defaultTablePrefix = "autent_"

// currentSchemaVersion is the latest SQLite schema version understood by this adapter.
const currentSchemaVersion = 1

// Options configures the SQLite adapter.
type Options struct {
	// TablePrefix scopes autent tables inside one SQLite database. Valid characters are ASCII letters,
	// digits, and underscores.
	TablePrefix string
}

// tableNames holds the concrete table names derived from one configured prefix.
type tableNames struct {
	schemaMigrations string
	principals       string
	clients          string
	sessions         string
	rules            string
	grants           string
	auditEvents      string
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

// newStore validates adapter options around one open database handle.
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

// newTableNames expands one configured prefix into the adapter's table set.
func newTableNames(prefix string) (tableNames, error) {
	normalized, err := normalizeTablePrefix(prefix)
	if err != nil {
		return tableNames{}, err
	}
	return tableNames{
		schemaMigrations: normalized + "schema_migrations",
		principals:       normalized + "principals",
		clients:          normalized + "clients",
		sessions:         normalized + "sessions",
		rules:            normalized + "rules",
		grants:           normalized + "grants",
		auditEvents:      normalized + "audit_events",
	}, nil
}

// normalizeTablePrefix validates and normalizes one configured table prefix.
func normalizeTablePrefix(prefix string) (string, error) {
	normalized := strings.TrimSpace(prefix)
	if normalized == "" {
		return defaultTablePrefix, nil
	}
	for idx, r := range normalized {
		if idx == 0 && (r != '_' && (r < 'A' || r > 'z' || (r > 'Z' && r < 'a'))) {
			return "", fmt.Errorf("table prefix %q: %w", prefix, domain.ErrInvalidConfig)
		}
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

// CreateSession stores one verifier-side session record.
func (s *Store) CreateSession(ctx context.Context, session domain.StoredSession) error {
	return createSession(ctx, s.db, s.tables, session)
}

// GetSession loads one verifier-side session record by id.
func (s *Store) GetSession(ctx context.Context, id string) (domain.StoredSession, error) {
	return getSession(ctx, s.db, s.tables, id)
}

// UpdateSession updates one verifier-side session record.
func (s *Store) UpdateSession(ctx context.Context, session domain.StoredSession) error {
	return updateSession(ctx, s.db, s.tables, session)
}

// ListSessions returns all caller-safe session metadata ordered by id.
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

// txStore routes repository calls through one SQLite transaction.
type txStore struct {
	tx     *sql.Tx
	tables tableNames
}

// CreatePrincipal stores one principal inside the transaction.
func (s txStore) CreatePrincipal(ctx context.Context, principal domain.Principal) error {
	return createPrincipal(ctx, s.tx, s.tables, principal)
}

// GetPrincipal loads one principal inside the transaction.
func (s txStore) GetPrincipal(ctx context.Context, id string) (domain.Principal, error) {
	return getPrincipal(ctx, s.tx, s.tables, id)
}

// ListPrincipals returns all principals inside the transaction.
func (s txStore) ListPrincipals(ctx context.Context) ([]domain.Principal, error) {
	return listPrincipals(ctx, s.tx, s.tables)
}

// UpdatePrincipal updates one principal inside the transaction.
func (s txStore) UpdatePrincipal(ctx context.Context, principal domain.Principal) error {
	return updatePrincipal(ctx, s.tx, s.tables, principal)
}

// CreateClient stores one client inside the transaction.
func (s txStore) CreateClient(ctx context.Context, client domain.Client) error {
	return createClient(ctx, s.tx, s.tables, client)
}

// GetClient loads one client inside the transaction.
func (s txStore) GetClient(ctx context.Context, id string) (domain.Client, error) {
	return getClient(ctx, s.tx, s.tables, id)
}

// ListClients returns all clients inside the transaction.
func (s txStore) ListClients(ctx context.Context) ([]domain.Client, error) {
	return listClients(ctx, s.tx, s.tables)
}

// UpdateClient updates one client inside the transaction.
func (s txStore) UpdateClient(ctx context.Context, client domain.Client) error {
	return updateClient(ctx, s.tx, s.tables, client)
}

// CreateSession stores one verifier-side session record inside the transaction.
func (s txStore) CreateSession(ctx context.Context, session domain.StoredSession) error {
	return createSession(ctx, s.tx, s.tables, session)
}

// GetSession loads one verifier-side session record inside the transaction.
func (s txStore) GetSession(ctx context.Context, id string) (domain.StoredSession, error) {
	return getSession(ctx, s.tx, s.tables, id)
}

// UpdateSession updates one verifier-side session record inside the transaction.
func (s txStore) UpdateSession(ctx context.Context, session domain.StoredSession) error {
	return updateSession(ctx, s.tx, s.tables, session)
}

// ListSessions returns all caller-safe session metadata inside the transaction.
func (s txStore) ListSessions(ctx context.Context) ([]domain.Session, error) {
	return listSessions(ctx, s.tx, s.tables)
}

// ReplaceRules replaces the persisted rule set inside the transaction.
func (s txStore) ReplaceRules(ctx context.Context, rules []domain.Rule) error {
	return replaceRules(ctx, s.tx, s.tables, rules)
}

// ListRules returns the persisted rule set inside the transaction.
func (s txStore) ListRules(ctx context.Context) ([]domain.Rule, error) {
	return listRules(ctx, s.tx, s.tables)
}

// CreateGrant stores one grant inside the transaction.
func (s txStore) CreateGrant(ctx context.Context, grant domain.Grant) error {
	return createGrant(ctx, s.tx, s.tables, grant)
}

// GetGrant loads one grant inside the transaction.
func (s txStore) GetGrant(ctx context.Context, id string) (domain.Grant, error) {
	return getGrant(ctx, s.tx, s.tables, id)
}

// UpdateGrant updates one grant inside the transaction.
func (s txStore) UpdateGrant(ctx context.Context, grant domain.Grant) error {
	return updateGrant(ctx, s.tx, s.tables, grant)
}

// FindGrant returns the newest matching grant inside the transaction.
func (s txStore) FindGrant(ctx context.Context, query domain.GrantQuery) (domain.Grant, error) {
	return findGrant(ctx, s.tx, s.tables, query)
}

// ListGrants returns all grants inside the transaction.
func (s txStore) ListGrants(ctx context.Context) ([]domain.Grant, error) {
	return listGrants(ctx, s.tx, s.tables)
}

// AppendAuditEvent appends one audit event inside the transaction.
func (s txStore) AppendAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return appendAuditEvent(ctx, s.tx, s.tables, event)
}

// ListAuditEvents returns filtered audit events inside the transaction.
func (s txStore) ListAuditEvents(ctx context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	return listAuditEvents(ctx, s.tx, s.tables, filter)
}

// WithinTx reuses the current transaction for nested transactional work.
func (s txStore) WithinTx(_ context.Context, fn func(store.Repository) error) error {
	return fn(s)
}

// execQuerier captures the sql.DB and sql.Tx methods used by the adapter helpers.
type execQuerier interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// createPrincipal stores one principal payload.
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

// getPrincipal loads one principal payload.
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

// updatePrincipal updates one principal payload.
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

// listPrincipals returns all principal payloads ordered by id.
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

// createClient stores one client payload.
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

// getClient loads one client payload.
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

// updateClient updates one client payload.
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

// listClients returns all client payloads ordered by id.
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

// createSession stores one verifier-side session payload.
func createSession(ctx context.Context, db execQuerier, tables tableNames, session domain.StoredSession) error {
	payload, err := encodeStoredSession(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	_, err = db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (id, principal_id, client_id, expires_at, payload) VALUES (?, ?, ?, ?, ?)`, tables.sessions), session.ID, session.PrincipalID, session.ClientID, session.ExpiresAt.UTC().Format(time.RFC3339Nano), payload)
	if isUniqueErr(err) {
		return fmt.Errorf("create session %q: %w", session.ID, domain.ErrAlreadyExists)
	}
	return err
}

// getSession loads one verifier-side session payload.
func getSession(ctx context.Context, db execQuerier, tables tableNames, id string) (domain.StoredSession, error) {
	var payload []byte
	err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT payload FROM %s WHERE id = ?`, tables.sessions), strings.TrimSpace(id)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.StoredSession{}, domain.ErrSessionNotFound
	}
	if err != nil {
		return domain.StoredSession{}, err
	}
	session, err := decodeStoredSession(payload)
	if err != nil {
		return domain.StoredSession{}, fmt.Errorf("decode session: %w", err)
	}
	return session, nil
}

// updateSession updates one verifier-side session payload.
func updateSession(ctx context.Context, db execQuerier, tables tableNames, session domain.StoredSession) error {
	payload, err := encodeStoredSession(session)
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

// listSessions returns all caller-safe session payloads ordered by id.
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
		session, err := decodeStoredSession(payload)
		if err != nil {
			return nil, err
		}
		out = append(out, session.View())
	}
	return out, rows.Err()
}

// encodeStoredSession serializes one verifier-side session record for SQLite persistence.
func encodeStoredSession(session domain.StoredSession) ([]byte, error) {
	type storedSessionJSON struct {
		ID               string            `json:"ID"`
		PrincipalID      string            `json:"PrincipalID"`
		ClientID         string            `json:"ClientID"`
		IssuedAt         time.Time         `json:"IssuedAt"`
		ExpiresAt        time.Time         `json:"ExpiresAt"`
		LastSeenAt       time.Time         `json:"LastSeenAt"`
		RevokedAt        *time.Time        `json:"RevokedAt"`
		RevocationReason string            `json:"RevocationReason"`
		Metadata         map[string]string `json:"Metadata"`
		SecretHash       []byte            `json:"SecretHash"`
	}
	return json.Marshal(storedSessionJSON{
		ID:               session.ID,
		PrincipalID:      session.PrincipalID,
		ClientID:         session.ClientID,
		IssuedAt:         session.IssuedAt,
		ExpiresAt:        session.ExpiresAt,
		LastSeenAt:       session.LastSeenAt,
		RevokedAt:        session.RevokedAt,
		RevocationReason: session.RevocationReason,
		Metadata:         session.Metadata,
		SecretHash:       session.SecretHash(),
	})
}

// decodeStoredSession restores one verifier-side session record from SQLite persistence.
func decodeStoredSession(payload []byte) (domain.StoredSession, error) {
	type storedSessionJSON struct {
		ID               string            `json:"ID"`
		PrincipalID      string            `json:"PrincipalID"`
		ClientID         string            `json:"ClientID"`
		IssuedAt         time.Time         `json:"IssuedAt"`
		ExpiresAt        time.Time         `json:"ExpiresAt"`
		LastSeenAt       time.Time         `json:"LastSeenAt"`
		RevokedAt        *time.Time        `json:"RevokedAt"`
		RevocationReason string            `json:"RevocationReason"`
		Metadata         map[string]string `json:"Metadata"`
		SecretHash       []byte            `json:"SecretHash"`
	}
	var decoded storedSessionJSON
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return domain.StoredSession{}, err
	}
	stored, err := domain.NewStoredSession(domain.StoredSessionInput{
		ID:          decoded.ID,
		PrincipalID: decoded.PrincipalID,
		ClientID:    decoded.ClientID,
		SecretHash:  decoded.SecretHash,
		ExpiresAt:   decoded.ExpiresAt,
		Metadata:    decoded.Metadata,
	}, decoded.IssuedAt)
	if err != nil {
		return domain.StoredSession{}, err
	}
	stored.IssuedAt = decoded.IssuedAt
	stored.LastSeenAt = decoded.LastSeenAt
	if decoded.RevokedAt != nil {
		ts := decoded.RevokedAt.UTC()
		stored.RevokedAt = &ts
	}
	stored.RevocationReason = decoded.RevocationReason
	return stored, nil
}

// replaceRules replaces the entire persisted rule set.
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

// listRules returns all persisted rules ordered by priority.
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

// createGrant stores one grant payload.
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

// getGrant loads one grant payload.
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

// updateGrant updates one grant payload.
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

// findGrant returns the newest matching persisted grant.
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

// listGrants returns all persisted grants ordered by creation time.
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

// appendAuditEvent stores one audit event payload.
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

// listAuditEvents returns persisted audit events that match one filter.
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

// migrate upgrades the SQLite schema to the current adapter version.
func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite migration tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (version INTEGER NOT NULL)`, s.tables.schemaMigrations)); err != nil {
		return fmt.Errorf("ensure sqlite schema table: %w", err)
	}

	version, err := currentVersion(ctx, tx, s.tables)
	if err != nil {
		return err
	}
	for version < currentSchemaVersion {
		version++
		if err := applyMigration(ctx, tx, s.tables, version); err != nil {
			return err
		}
		if err := setVersion(ctx, tx, s.tables, version); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite migration tx: %w", err)
	}
	return nil
}

// currentVersion returns the recorded schema version for one SQLite repository.
func currentVersion(ctx context.Context, db execQuerier, tables tableNames) (int, error) {
	row := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT version FROM %s LIMIT 1`, tables.schemaMigrations))
	var version int
	if err := row.Scan(&version); errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("load sqlite schema version: %w", err)
	}
	return version, nil
}

// applyMigration applies one numbered SQLite schema migration.
func applyMigration(ctx context.Context, db execQuerier, tables tableNames, version int) error {
	var statements []string
	switch version {
	case 1:
		statements = []string{
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, payload BLOB NOT NULL)`, tables.principals),
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, payload BLOB NOT NULL)`, tables.clients),
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, client_id TEXT NOT NULL, expires_at TEXT NOT NULL, payload BLOB NOT NULL)`, tables.sessions),
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, priority INTEGER NOT NULL, payload BLOB NOT NULL)`, tables.rules),
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, client_id TEXT NOT NULL, action TEXT NOT NULL, resource_namespace TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, payload BLOB NOT NULL)`, tables.grants),
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, principal_id TEXT, client_id TEXT, session_id TEXT, event_type TEXT NOT NULL, payload BLOB NOT NULL)`, tables.auditEvents),
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_lookup_idx ON %s (principal_id, client_id, action, resource_namespace, resource_type, resource_id, fingerprint, state, created_at DESC)`, tables.grants, tables.grants),
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s_time_idx ON %s (occurred_at ASC, id ASC)`, tables.auditEvents, tables.auditEvents),
		}
	default:
		return fmt.Errorf("apply sqlite migration version %d: %w", version, domain.ErrInvalidConfig)
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply sqlite migration version %d statement %q: %w", version, statement, err)
		}
	}
	return nil
}

// setVersion records one applied SQLite schema version.
func setVersion(ctx context.Context, db execQuerier, tables tableNames, version int) error {
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s`, tables.schemaMigrations)); err != nil {
		return fmt.Errorf("clear sqlite schema version: %w", err)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (version) VALUES (?)`, tables.schemaMigrations), version); err != nil {
		return fmt.Errorf("store sqlite schema version %d: %w", version, err)
	}
	return nil
}

// isUniqueErr reports whether one SQLite error represents a uniqueness violation.
func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique")
}
