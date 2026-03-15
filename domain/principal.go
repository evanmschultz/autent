package domain

import (
	"slices"
	"strings"
	"time"
)

// PrincipalType identifies the type of authenticated subject.
type PrincipalType string

const (
	// PrincipalTypeUser identifies a human user.
	PrincipalTypeUser PrincipalType = "user"
	// PrincipalTypeAgent identifies an LLM-driven agent or automation subject.
	PrincipalTypeAgent PrincipalType = "agent"
	// PrincipalTypeService identifies a service or daemon subject.
	PrincipalTypeService PrincipalType = "service"
)

// validPrincipalTypes stores supported principal types.
var validPrincipalTypes = []PrincipalType{
	PrincipalTypeUser,
	PrincipalTypeAgent,
	PrincipalTypeService,
}

// PrincipalInput carries fields used to construct a principal.
type PrincipalInput struct {
	ID          string
	Type        PrincipalType
	DisplayName string
	Aliases     []string
	Status      Status
	Metadata    map[string]string
}

// Principal stores an authenticated subject record.
type Principal struct {
	ID          string
	Type        PrincipalType
	DisplayName string
	Aliases     []string
	Status      Status
	Metadata    map[string]string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NormalizePrincipalType canonicalizes one principal type value.
func NormalizePrincipalType(principalType PrincipalType) PrincipalType {
	return PrincipalType(strings.TrimSpace(strings.ToLower(string(principalType))))
}

// IsValidPrincipalType reports whether a principal type is supported.
func IsValidPrincipalType(principalType PrincipalType) bool {
	return slices.Contains(validPrincipalTypes, NormalizePrincipalType(principalType))
}

// NewPrincipal validates and constructs a principal record.
func NewPrincipal(in PrincipalInput, now time.Time) (Principal, error) {
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return Principal{}, ErrInvalidID
	}
	principalType := NormalizePrincipalType(in.Type)
	if !IsValidPrincipalType(principalType) {
		return Principal{}, ErrInvalidPrincipalType
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		return Principal{}, ErrInvalidDisplayName
	}
	status := NormalizeStatus(in.Status)
	if status == "" {
		status = StatusActive
	}
	if !IsValidStatus(status) {
		return Principal{}, ErrInvalidStatus
	}

	aliases := normalizeStringSlice(in.Aliases)
	ts := now.UTC()
	return Principal{
		ID:          id,
		Type:        principalType,
		DisplayName: displayName,
		Aliases:     aliases,
		Status:      status,
		Metadata:    copyMap(in.Metadata),
		CreatedAt:   ts,
		UpdatedAt:   ts,
	}, nil
}

// IsActive reports whether the principal is active.
func (p Principal) IsActive() bool {
	return NormalizeStatus(p.Status) == StatusActive
}
