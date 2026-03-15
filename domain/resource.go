package domain

import (
	"path"
	"strings"
)

// Action identifies an authorization action.
type Action string

// ResourceRef identifies a generic authorization target.
type ResourceRef struct {
	Namespace  string
	Type       string
	ID         string
	Attributes map[string]string
}

// MatchOperator identifies how one string pattern should be evaluated.
type MatchOperator string

const (
	// MatchAny matches any non-empty or empty value.
	MatchAny MatchOperator = "any"
	// MatchExact matches one exact value.
	MatchExact MatchOperator = "exact"
	// MatchPrefix matches values by prefix.
	MatchPrefix MatchOperator = "prefix"
	// MatchGlob matches values using path.Match semantics.
	MatchGlob MatchOperator = "glob"
)

// StringPattern matches one string field.
type StringPattern struct {
	Operator MatchOperator
	Value    string
}

// ResourcePattern matches one resource reference.
type ResourcePattern struct {
	Namespace  StringPattern
	Type       StringPattern
	ID         StringPattern
	Attributes map[string]string
}

// NormalizeAction canonicalizes one action value.
func NormalizeAction(action Action) Action {
	return Action(strings.TrimSpace(strings.ToLower(string(action))))
}

// Validate reports whether the action is non-empty.
func (a Action) Validate() error {
	if NormalizeAction(a) == "" {
		return ErrInvalidAction
	}
	return nil
}

// Validate reports whether the resource reference is complete enough for authz.
func (r ResourceRef) Validate() error {
	if strings.TrimSpace(r.Type) == "" || strings.TrimSpace(r.ID) == "" {
		return ErrInvalidResource
	}
	return nil
}

// Matches reports whether the pattern matches the candidate string.
func (p StringPattern) Matches(candidate string) bool {
	operator := MatchOperator(strings.TrimSpace(strings.ToLower(string(p.Operator))))
	value := strings.TrimSpace(p.Value)
	switch operator {
	case "", MatchExact:
		return candidate == value
	case MatchAny:
		return true
	case MatchPrefix:
		return strings.HasPrefix(candidate, value)
	case MatchGlob:
		matched, err := path.Match(value, candidate)
		return err == nil && matched
	default:
		return false
	}
}

// Validate reports whether the string pattern is valid.
func (p StringPattern) Validate() error {
	operator := MatchOperator(strings.TrimSpace(strings.ToLower(string(p.Operator))))
	switch operator {
	case "", MatchExact, MatchAny, MatchPrefix, MatchGlob:
	default:
		return ErrInvalidPattern
	}
	if operator != MatchAny && strings.TrimSpace(p.Value) == "" {
		return ErrInvalidPattern
	}
	return nil
}

// Matches reports whether the resource pattern matches the resource reference.
func (p ResourcePattern) Matches(resource ResourceRef) bool {
	if !p.Namespace.Matches(strings.TrimSpace(resource.Namespace)) {
		return false
	}
	if !p.Type.Matches(strings.TrimSpace(resource.Type)) {
		return false
	}
	if !p.ID.Matches(strings.TrimSpace(resource.ID)) {
		return false
	}
	for key, want := range p.Attributes {
		if resource.Attributes[key] != want {
			return false
		}
	}
	return true
}

// Validate reports whether the resource pattern is valid.
func (p ResourcePattern) Validate() error {
	if err := p.Namespace.Validate(); err != nil {
		return err
	}
	if err := p.Type.Validate(); err != nil {
		return err
	}
	if err := p.ID.Validate(); err != nil {
		return err
	}
	return nil
}
