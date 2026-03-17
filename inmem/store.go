package inmem

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/evanmschultz/autent/domain"
	"github.com/evanmschultz/autent/store"
)

// Store is an in-memory repository implementation for autent.
type Store struct {
	mu         sync.RWMutex
	principals map[string]domain.Principal
	clients    map[string]domain.Client
	sessions   map[string]domain.StoredSession
	rules      []domain.Rule
	grants     map[string]domain.Grant
	audit      []domain.AuditEvent
}

// NewStore constructs an empty in-memory repository.
func NewStore() *Store {
	return &Store{
		principals: make(map[string]domain.Principal),
		clients:    make(map[string]domain.Client),
		sessions:   make(map[string]domain.StoredSession),
		grants:     make(map[string]domain.Grant),
		audit:      make([]domain.AuditEvent, 0),
	}
}

// NewRepository constructs an empty in-memory repository.
func NewRepository() *Store {
	return NewStore()
}

// CreatePrincipal stores a principal.
func (s *Store) CreatePrincipal(_ context.Context, principal domain.Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.principals[principal.ID]; ok {
		return fmt.Errorf("create principal %q: %w", principal.ID, domain.ErrAlreadyExists)
	}
	s.principals[principal.ID] = clonePrincipal(principal)
	return nil
}

// GetPrincipal loads a principal by id.
func (s *Store) GetPrincipal(_ context.Context, id string) (domain.Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	principal, ok := s.principals[strings.TrimSpace(id)]
	if !ok {
		return domain.Principal{}, domain.ErrPrincipalNotFound
	}
	return clonePrincipal(principal), nil
}

// ListPrincipals returns all stored principals ordered by id.
func (s *Store) ListPrincipals(_ context.Context) ([]domain.Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Principal, 0, len(s.principals))
	for _, principal := range s.principals {
		out = append(out, clonePrincipal(principal))
	}
	slices.SortFunc(out, func(a, b domain.Principal) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdatePrincipal replaces a stored principal.
func (s *Store) UpdatePrincipal(_ context.Context, principal domain.Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.principals[principal.ID]; !ok {
		return domain.ErrPrincipalNotFound
	}
	s.principals[principal.ID] = clonePrincipal(principal)
	return nil
}

// CreateClient stores a client.
func (s *Store) CreateClient(_ context.Context, client domain.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[client.ID]; ok {
		return fmt.Errorf("create client %q: %w", client.ID, domain.ErrAlreadyExists)
	}
	s.clients[client.ID] = cloneClient(client)
	return nil
}

// GetClient loads a client by id.
func (s *Store) GetClient(_ context.Context, id string) (domain.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[strings.TrimSpace(id)]
	if !ok {
		return domain.Client{}, domain.ErrClientNotFound
	}
	return cloneClient(client), nil
}

// ListClients returns all stored clients ordered by id.
func (s *Store) ListClients(_ context.Context) ([]domain.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Client, 0, len(s.clients))
	for _, client := range s.clients {
		out = append(out, cloneClient(client))
	}
	slices.SortFunc(out, func(a, b domain.Client) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdateClient replaces a stored client.
func (s *Store) UpdateClient(_ context.Context, client domain.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[client.ID]; !ok {
		return domain.ErrClientNotFound
	}
	s.clients[client.ID] = cloneClient(client)
	return nil
}

// CreateSession stores one verifier-side session record.
func (s *Store) CreateSession(_ context.Context, session domain.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; ok {
		return fmt.Errorf("create session %q: %w", session.ID, domain.ErrAlreadyExists)
	}
	s.sessions[session.ID] = cloneSession(session)
	return nil
}

// GetSession loads one verifier-side session record by id.
func (s *Store) GetSession(_ context.Context, id string) (domain.StoredSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[strings.TrimSpace(id)]
	if !ok {
		return domain.StoredSession{}, domain.ErrSessionNotFound
	}
	return cloneSession(session), nil
}

// UpdateSession replaces one stored verifier-side session record.
func (s *Store) UpdateSession(_ context.Context, session domain.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; !ok {
		return domain.ErrSessionNotFound
	}
	s.sessions[session.ID] = cloneSession(session)
	return nil
}

// ListSessions returns all stored verifier-side session records ordered by id.
func (s *Store) ListSessions(_ context.Context) ([]domain.StoredSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.StoredSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		out = append(out, cloneSession(session))
	}
	slices.SortFunc(out, func(a, b domain.StoredSession) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// ReplaceRules replaces the persisted rule set.
func (s *Store) ReplaceRules(_ context.Context, rules []domain.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = cloneRules(rules)
	return nil
}

// ListRules returns the persisted rule set.
func (s *Store) ListRules(_ context.Context) ([]domain.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRules(s.rules), nil
}

// CreateGrant stores a grant.
func (s *Store) CreateGrant(_ context.Context, grant domain.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[grant.ID]; ok {
		return fmt.Errorf("create grant %q: %w", grant.ID, domain.ErrAlreadyExists)
	}
	s.grants[grant.ID] = cloneGrant(grant)
	return nil
}

// GetGrant loads a grant by id.
func (s *Store) GetGrant(_ context.Context, id string) (domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant, ok := s.grants[strings.TrimSpace(id)]
	if !ok {
		return domain.Grant{}, domain.ErrGrantNotFound
	}
	return cloneGrant(grant), nil
}

// UpdateGrant replaces a stored grant.
func (s *Store) UpdateGrant(_ context.Context, grant domain.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[grant.ID]; !ok {
		return domain.ErrGrantNotFound
	}
	s.grants[grant.ID] = cloneGrant(grant)
	return nil
}

// FindGrant returns the newest matching grant for a request fingerprint.
func (s *Store) FindGrant(_ context.Context, query domain.GrantQuery) (domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matches := make([]domain.Grant, 0)
	for _, grant := range s.grants {
		if strings.TrimSpace(query.PrincipalID) != "" && grant.PrincipalID != strings.TrimSpace(query.PrincipalID) {
			continue
		}
		if strings.TrimSpace(query.ClientID) != "" && grant.ClientID != strings.TrimSpace(query.ClientID) {
			continue
		}
		if domain.NormalizeAction(query.Action) != "" && grant.Action != domain.NormalizeAction(query.Action) {
			continue
		}
		if strings.TrimSpace(query.Fingerprint) != "" && grant.Fingerprint != strings.TrimSpace(query.Fingerprint) {
			continue
		}
		if query.State != "" && grant.State != query.State {
			continue
		}
		if grant.Resource.Namespace != query.Resource.Namespace || grant.Resource.Type != query.Resource.Type || grant.Resource.ID != query.Resource.ID {
			continue
		}
		matches = append(matches, cloneGrant(grant))
	}
	if len(matches) == 0 {
		return domain.Grant{}, domain.ErrGrantNotFound
	}
	slices.SortFunc(matches, func(a, b domain.Grant) int {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(a.ID, b.ID)
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return -1
		}
		return 1
	})
	return matches[0], nil
}

// ListGrants returns all stored grants ordered by creation time.
func (s *Store) ListGrants(_ context.Context) ([]domain.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		out = append(out, cloneGrant(grant))
	}
	slices.SortFunc(out, func(a, b domain.Grant) int {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(a.ID, b.ID)
		}
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		return 1
	})
	return out, nil
}

// AppendAuditEvent appends an audit event.
func (s *Store) AppendAuditEvent(_ context.Context, event domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, cloneAuditEvent(event))
	return nil
}

// ListAuditEvents returns audit events filtered by the provided filter.
func (s *Store) ListAuditEvents(_ context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.AuditEvent, 0, len(s.audit))
	for _, event := range s.audit {
		if filter.PrincipalID != "" && event.PrincipalID != filter.PrincipalID {
			continue
		}
		if filter.ClientID != "" && event.ClientID != filter.ClientID {
			continue
		}
		if filter.SessionID != "" && event.SessionID != filter.SessionID {
			continue
		}
		if filter.Type != "" && event.Type != filter.Type {
			continue
		}
		out = append(out, cloneAuditEvent(event))
	}
	slices.SortFunc(out, func(a, b domain.AuditEvent) int {
		if a.OccurredAt.Equal(b.OccurredAt) {
			return strings.Compare(a.ID, b.ID)
		}
		if a.OccurredAt.Before(b.OccurredAt) {
			return -1
		}
		return 1
	})
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

// WithinTx runs one function under the store write lock.
func (s *Store) WithinTx(_ context.Context, fn func(store.Repository) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	working := &Store{
		principals: clonePrincipalMap(s.principals),
		clients:    cloneClientMap(s.clients),
		sessions:   cloneSessionMap(s.sessions),
		rules:      cloneRules(s.rules),
		grants:     cloneGrantMap(s.grants),
		audit:      cloneAuditEvents(s.audit),
	}
	if err := fn(lockedStore{base: working}); err != nil {
		return err
	}
	s.principals = working.principals
	s.clients = working.clients
	s.sessions = working.sessions
	s.rules = working.rules
	s.grants = working.grants
	s.audit = working.audit
	return nil
}

// lockedStore provides transaction-local repository behavior over one cloned in-memory store.
type lockedStore struct {
	base *Store
}

// CreatePrincipal stores one principal in the transaction-local clone.
func (s lockedStore) CreatePrincipal(_ context.Context, principal domain.Principal) error {
	if _, ok := s.base.principals[principal.ID]; ok {
		return fmt.Errorf("create principal %q: %w", principal.ID, domain.ErrAlreadyExists)
	}
	s.base.principals[principal.ID] = clonePrincipal(principal)
	return nil
}

// GetPrincipal loads one principal from the transaction-local clone.
func (s lockedStore) GetPrincipal(_ context.Context, id string) (domain.Principal, error) {
	principal, ok := s.base.principals[strings.TrimSpace(id)]
	if !ok {
		return domain.Principal{}, domain.ErrPrincipalNotFound
	}
	return clonePrincipal(principal), nil
}

// ListPrincipals returns all principals from the transaction-local clone.
func (s lockedStore) ListPrincipals(_ context.Context) ([]domain.Principal, error) {
	out := make([]domain.Principal, 0, len(s.base.principals))
	for _, principal := range s.base.principals {
		out = append(out, clonePrincipal(principal))
	}
	slices.SortFunc(out, func(a, b domain.Principal) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdatePrincipal replaces one principal in the transaction-local clone.
func (s lockedStore) UpdatePrincipal(_ context.Context, principal domain.Principal) error {
	if _, ok := s.base.principals[principal.ID]; !ok {
		return domain.ErrPrincipalNotFound
	}
	s.base.principals[principal.ID] = clonePrincipal(principal)
	return nil
}

// CreateClient stores one client in the transaction-local clone.
func (s lockedStore) CreateClient(_ context.Context, client domain.Client) error {
	if _, ok := s.base.clients[client.ID]; ok {
		return fmt.Errorf("create client %q: %w", client.ID, domain.ErrAlreadyExists)
	}
	s.base.clients[client.ID] = cloneClient(client)
	return nil
}

// GetClient loads one client from the transaction-local clone.
func (s lockedStore) GetClient(_ context.Context, id string) (domain.Client, error) {
	client, ok := s.base.clients[strings.TrimSpace(id)]
	if !ok {
		return domain.Client{}, domain.ErrClientNotFound
	}
	return cloneClient(client), nil
}

// ListClients returns all clients from the transaction-local clone.
func (s lockedStore) ListClients(_ context.Context) ([]domain.Client, error) {
	out := make([]domain.Client, 0, len(s.base.clients))
	for _, client := range s.base.clients {
		out = append(out, cloneClient(client))
	}
	slices.SortFunc(out, func(a, b domain.Client) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// UpdateClient replaces one client in the transaction-local clone.
func (s lockedStore) UpdateClient(_ context.Context, client domain.Client) error {
	if _, ok := s.base.clients[client.ID]; !ok {
		return domain.ErrClientNotFound
	}
	s.base.clients[client.ID] = cloneClient(client)
	return nil
}

// CreateSession stores one verifier-side session record in the transaction-local clone.
func (s lockedStore) CreateSession(_ context.Context, session domain.StoredSession) error {
	if _, ok := s.base.sessions[session.ID]; ok {
		return fmt.Errorf("create session %q: %w", session.ID, domain.ErrAlreadyExists)
	}
	s.base.sessions[session.ID] = cloneSession(session)
	return nil
}

// GetSession loads one verifier-side session record from the transaction-local clone.
func (s lockedStore) GetSession(_ context.Context, id string) (domain.StoredSession, error) {
	session, ok := s.base.sessions[strings.TrimSpace(id)]
	if !ok {
		return domain.StoredSession{}, domain.ErrSessionNotFound
	}
	return cloneSession(session), nil
}

// UpdateSession replaces one verifier-side session record in the transaction-local clone.
func (s lockedStore) UpdateSession(_ context.Context, session domain.StoredSession) error {
	if _, ok := s.base.sessions[session.ID]; !ok {
		return domain.ErrSessionNotFound
	}
	s.base.sessions[session.ID] = cloneSession(session)
	return nil
}

// ListSessions returns all verifier-side session records from the transaction-local clone.
func (s lockedStore) ListSessions(_ context.Context) ([]domain.StoredSession, error) {
	out := make([]domain.StoredSession, 0, len(s.base.sessions))
	for _, session := range s.base.sessions {
		out = append(out, cloneSession(session))
	}
	slices.SortFunc(out, func(a, b domain.StoredSession) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// ReplaceRules replaces the transaction-local rule set.
func (s lockedStore) ReplaceRules(_ context.Context, rules []domain.Rule) error {
	s.base.rules = cloneRules(rules)
	return nil
}

// ListRules returns the transaction-local rule set.
func (s lockedStore) ListRules(_ context.Context) ([]domain.Rule, error) {
	return cloneRules(s.base.rules), nil
}

// CreateGrant stores one grant in the transaction-local clone.
func (s lockedStore) CreateGrant(_ context.Context, grant domain.Grant) error {
	if _, ok := s.base.grants[grant.ID]; ok {
		return fmt.Errorf("create grant %q: %w", grant.ID, domain.ErrAlreadyExists)
	}
	s.base.grants[grant.ID] = cloneGrant(grant)
	return nil
}

// GetGrant loads one grant from the transaction-local clone.
func (s lockedStore) GetGrant(_ context.Context, id string) (domain.Grant, error) {
	grant, ok := s.base.grants[strings.TrimSpace(id)]
	if !ok {
		return domain.Grant{}, domain.ErrGrantNotFound
	}
	return cloneGrant(grant), nil
}

// UpdateGrant replaces one grant in the transaction-local clone.
func (s lockedStore) UpdateGrant(_ context.Context, grant domain.Grant) error {
	if _, ok := s.base.grants[grant.ID]; !ok {
		return domain.ErrGrantNotFound
	}
	s.base.grants[grant.ID] = cloneGrant(grant)
	return nil
}

// FindGrant returns the newest matching grant from the transaction-local clone.
func (s lockedStore) FindGrant(ctx context.Context, query domain.GrantQuery) (domain.Grant, error) {
	_ = ctx
	matches := make([]domain.Grant, 0)
	for _, grant := range s.base.grants {
		if strings.TrimSpace(query.PrincipalID) != "" && grant.PrincipalID != strings.TrimSpace(query.PrincipalID) {
			continue
		}
		if strings.TrimSpace(query.ClientID) != "" && grant.ClientID != strings.TrimSpace(query.ClientID) {
			continue
		}
		if domain.NormalizeAction(query.Action) != "" && grant.Action != domain.NormalizeAction(query.Action) {
			continue
		}
		if strings.TrimSpace(query.Fingerprint) != "" && grant.Fingerprint != strings.TrimSpace(query.Fingerprint) {
			continue
		}
		if query.State != "" && grant.State != query.State {
			continue
		}
		if grant.Resource.Namespace != query.Resource.Namespace || grant.Resource.Type != query.Resource.Type || grant.Resource.ID != query.Resource.ID {
			continue
		}
		matches = append(matches, cloneGrant(grant))
	}
	if len(matches) == 0 {
		return domain.Grant{}, domain.ErrGrantNotFound
	}
	slices.SortFunc(matches, func(a, b domain.Grant) int {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(a.ID, b.ID)
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return -1
		}
		return 1
	})
	return matches[0], nil
}

// ListGrants returns all grants from the transaction-local clone.
func (s lockedStore) ListGrants(_ context.Context) ([]domain.Grant, error) {
	out := make([]domain.Grant, 0, len(s.base.grants))
	for _, grant := range s.base.grants {
		out = append(out, cloneGrant(grant))
	}
	slices.SortFunc(out, func(a, b domain.Grant) int {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(a.ID, b.ID)
		}
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		return 1
	})
	return out, nil
}

// AppendAuditEvent appends one audit event to the transaction-local clone.
func (s lockedStore) AppendAuditEvent(_ context.Context, event domain.AuditEvent) error {
	s.base.audit = append(s.base.audit, cloneAuditEvent(event))
	return nil
}

// ListAuditEvents returns filtered audit events from the transaction-local clone.
func (s lockedStore) ListAuditEvents(_ context.Context, filter domain.AuditFilter) ([]domain.AuditEvent, error) {
	out := make([]domain.AuditEvent, 0, len(s.base.audit))
	for _, event := range s.base.audit {
		if filter.PrincipalID != "" && event.PrincipalID != filter.PrincipalID {
			continue
		}
		if filter.ClientID != "" && event.ClientID != filter.ClientID {
			continue
		}
		if filter.SessionID != "" && event.SessionID != filter.SessionID {
			continue
		}
		if filter.Type != "" && event.Type != filter.Type {
			continue
		}
		out = append(out, cloneAuditEvent(event))
	}
	slices.SortFunc(out, func(a, b domain.AuditEvent) int {
		if a.OccurredAt.Equal(b.OccurredAt) {
			return strings.Compare(a.ID, b.ID)
		}
		if a.OccurredAt.Before(b.OccurredAt) {
			return -1
		}
		return 1
	})
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

// WithinTx reuses the transaction-local clone for nested transaction calls.
func (s lockedStore) WithinTx(_ context.Context, fn func(store.Repository) error) error { return fn(s) }

// clonePrincipal returns one deep-copied principal value.
func clonePrincipal(principal domain.Principal) domain.Principal {
	return domain.Principal{
		ID:          principal.ID,
		Type:        principal.Type,
		DisplayName: principal.DisplayName,
		Aliases:     slices.Clone(principal.Aliases),
		Status:      principal.Status,
		Metadata:    copyStringMap(principal.Metadata),
		CreatedAt:   principal.CreatedAt,
		UpdatedAt:   principal.UpdatedAt,
	}
}

// clonePrincipalMap returns one deep copy of a principal map.
func clonePrincipalMap(in map[string]domain.Principal) map[string]domain.Principal {
	if len(in) == 0 {
		return make(map[string]domain.Principal)
	}
	out := make(map[string]domain.Principal, len(in))
	for key, value := range in {
		out[key] = clonePrincipal(value)
	}
	return out
}

// cloneClient returns one deep-copied client value.
func cloneClient(client domain.Client) domain.Client {
	return domain.Client{
		ID:          client.ID,
		DisplayName: client.DisplayName,
		Type:        client.Type,
		Status:      client.Status,
		Metadata:    copyStringMap(client.Metadata),
		CreatedAt:   client.CreatedAt,
		UpdatedAt:   client.UpdatedAt,
	}
}

// cloneClientMap returns one deep copy of a client map.
func cloneClientMap(in map[string]domain.Client) map[string]domain.Client {
	if len(in) == 0 {
		return make(map[string]domain.Client)
	}
	out := make(map[string]domain.Client, len(in))
	for key, value := range in {
		out[key] = cloneClient(value)
	}
	return out
}

// cloneSession returns one deep-copied stored session value.
func cloneSession(session domain.StoredSession) domain.StoredSession {
	hash := make([]byte, len(session.SecretHash))
	copy(hash, session.SecretHash)
	return domain.StoredSession{
		Session: domain.Session{
			ID:               session.ID,
			PrincipalID:      session.PrincipalID,
			ClientID:         session.ClientID,
			IssuedAt:         session.IssuedAt,
			ExpiresAt:        session.ExpiresAt,
			LastSeenAt:       session.LastSeenAt,
			RevokedAt:        copyTime(session.RevokedAt),
			RevocationReason: session.RevocationReason,
			Metadata:         copyStringMap(session.Metadata),
		},
		SecretHash: hash,
	}
}

// cloneSessionMap returns one deep copy of a stored-session map.
func cloneSessionMap(in map[string]domain.StoredSession) map[string]domain.StoredSession {
	if len(in) == 0 {
		return make(map[string]domain.StoredSession)
	}
	out := make(map[string]domain.StoredSession, len(in))
	for key, value := range in {
		out[key] = cloneSession(value)
	}
	return out
}

// cloneGrant returns one deep-copied grant value.
func cloneGrant(grant domain.Grant) domain.Grant {
	return domain.Grant{
		ID:             grant.ID,
		SessionID:      grant.SessionID,
		PrincipalID:    grant.PrincipalID,
		ClientID:       grant.ClientID,
		Action:         grant.Action,
		Resource:       cloneResource(grant.Resource),
		Fingerprint:    grant.Fingerprint,
		RequestedScope: copyStringMap(grant.RequestedScope),
		Reason:         grant.Reason,
		State:          grant.State,
		UsageLimit:     grant.UsageLimit,
		UsageCount:     grant.UsageCount,
		CreatedAt:      grant.CreatedAt,
		ExpiresAt:      grant.ExpiresAt,
		ResolvedAt:     copyTime(grant.ResolvedAt),
		ResolvedBy:     grant.ResolvedBy,
		ResolutionNote: grant.ResolutionNote,
	}
}

// cloneGrantMap returns one deep copy of a grant map.
func cloneGrantMap(in map[string]domain.Grant) map[string]domain.Grant {
	if len(in) == 0 {
		return make(map[string]domain.Grant)
	}
	out := make(map[string]domain.Grant, len(in))
	for key, value := range in {
		out[key] = cloneGrant(value)
	}
	return out
}

// cloneRules returns one deep copy of a rule slice.
func cloneRules(rules []domain.Rule) []domain.Rule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]domain.Rule, len(rules))
	for i, rule := range rules {
		out[i] = domain.Rule{
			ID:             rule.ID,
			Effect:         rule.Effect,
			PrincipalIDs:   slices.Clone(rule.PrincipalIDs),
			PrincipalTypes: slices.Clone(rule.PrincipalTypes),
			ClientIDs:      slices.Clone(rule.ClientIDs),
			ClientTypes:    slices.Clone(rule.ClientTypes),
			Actions:        slices.Clone(rule.Actions),
			Resources:      cloneResourcePatterns(rule.Resources),
			Conditions:     slices.Clone(rule.Conditions),
			Priority:       rule.Priority,
		}
		if rule.Escalation != nil {
			out[i].Escalation = &domain.EscalationRequirement{
				Allowed: rule.Escalation.Allowed,
				Scope:   copyStringMap(rule.Escalation.Scope),
				Reason:  rule.Escalation.Reason,
			}
		}
	}
	return out
}

// cloneResourcePatterns returns one deep copy of resource patterns.
func cloneResourcePatterns(patterns []domain.ResourcePattern) []domain.ResourcePattern {
	if len(patterns) == 0 {
		return nil
	}
	out := make([]domain.ResourcePattern, len(patterns))
	for i, pattern := range patterns {
		out[i] = domain.ResourcePattern{
			Namespace:  pattern.Namespace,
			Type:       pattern.Type,
			ID:         pattern.ID,
			Attributes: copyStringMap(pattern.Attributes),
		}
	}
	return out
}

// cloneAuditEvent returns one deep-copied audit event.
func cloneAuditEvent(event domain.AuditEvent) domain.AuditEvent {
	return domain.AuditEvent{
		ID:           event.ID,
		Type:         event.Type,
		OccurredAt:   event.OccurredAt,
		PrincipalID:  event.PrincipalID,
		ClientID:     event.ClientID,
		SessionID:    event.SessionID,
		Action:       event.Action,
		Resource:     cloneResource(event.Resource),
		DecisionCode: event.DecisionCode,
		Reason:       event.Reason,
		Metadata:     copyStringMap(event.Metadata),
	}
}

// cloneAuditEvents returns one deep copy of audit events.
func cloneAuditEvents(events []domain.AuditEvent) []domain.AuditEvent {
	if len(events) == 0 {
		return nil
	}
	out := make([]domain.AuditEvent, len(events))
	for i, event := range events {
		out[i] = cloneAuditEvent(event)
	}
	return out
}

// cloneResource returns one deep-copied resource reference.
func cloneResource(resource domain.ResourceRef) domain.ResourceRef {
	return domain.ResourceRef{
		Namespace:  resource.Namespace,
		Type:       resource.Type,
		ID:         resource.ID,
		Attributes: copyStringMap(resource.Attributes),
	}
}

// copyStringMap returns one shallow-copied string map.
func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// copyTime returns one copied UTC timestamp pointer.
func copyTime(ts *time.Time) *time.Time {
	if ts == nil {
		return nil
	}
	out := ts.UTC()
	return &out
}
