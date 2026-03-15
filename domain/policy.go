package domain

import (
	"maps"
	"slices"
	"strings"
)

// Effect identifies whether a rule allows or denies access.
type Effect string

const (
	// EffectAllow indicates a rule may allow or escalate a request.
	EffectAllow Effect = "allow"
	// EffectDeny indicates a rule denies a request.
	EffectDeny Effect = "deny"
)

// ConditionOperator identifies how one context condition should be evaluated.
type ConditionOperator string

const (
	// ConditionPresent requires a context key to exist.
	ConditionPresent ConditionOperator = "present"
	// ConditionEquals requires a context key to equal a value.
	ConditionEquals ConditionOperator = "equals"
)

// Condition matches one request context key.
type Condition struct {
	Key      string
	Operator ConditionOperator
	Value    string
}

// EscalationRequirement describes whether one matching rule may fall back to an approval grant.
type EscalationRequirement struct {
	Allowed bool
	Scope   map[string]string
	Reason  string
}

// Rule stores one authorization rule.
type Rule struct {
	ID             string
	Effect         Effect
	PrincipalIDs   []StringPattern
	PrincipalTypes []StringPattern
	ClientIDs      []StringPattern
	ClientTypes    []StringPattern
	Actions        []StringPattern
	Resources      []ResourcePattern
	Conditions     []Condition
	Escalation     *EscalationRequirement
	Priority       int
}

// AuthorizationRequest contains the normalized request evaluated by policy.
type AuthorizationRequest struct {
	SessionID string
	Principal Principal
	Client    Client
	Action    Action
	Resource  ResourceRef
	Context   map[string]string
}

// Validate reports whether the condition is well formed.
func (c Condition) Validate() error {
	if strings.TrimSpace(c.Key) == "" {
		return ErrInvalidCondition
	}
	switch ConditionOperator(strings.TrimSpace(strings.ToLower(string(c.Operator)))) {
	case ConditionPresent:
		return nil
	case ConditionEquals:
		if strings.TrimSpace(c.Value) == "" {
			return ErrInvalidCondition
		}
		return nil
	default:
		return ErrInvalidCondition
	}
}

// Matches reports whether the condition matches the provided request context.
func (c Condition) Matches(context map[string]string) bool {
	key := strings.TrimSpace(c.Key)
	operator := ConditionOperator(strings.TrimSpace(strings.ToLower(string(c.Operator))))
	switch operator {
	case ConditionPresent:
		_, ok := context[key]
		return ok
	case ConditionEquals:
		return context[key] == c.Value
	default:
		return false
	}
}

// Validate reports whether the rule is well formed.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return ErrInvalidRule
	}
	if r.Effect != EffectAllow && r.Effect != EffectDeny {
		return ErrInvalidRule
	}
	if len(r.Actions) == 0 || len(r.Resources) == 0 {
		return ErrInvalidRule
	}
	for _, pattern := range r.PrincipalIDs {
		if err := pattern.Validate(); err != nil {
			return err
		}
	}
	for _, pattern := range r.PrincipalTypes {
		if err := pattern.Validate(); err != nil {
			return err
		}
	}
	for _, pattern := range r.ClientIDs {
		if err := pattern.Validate(); err != nil {
			return err
		}
	}
	for _, pattern := range r.ClientTypes {
		if err := pattern.Validate(); err != nil {
			return err
		}
	}
	for _, pattern := range r.Actions {
		if err := pattern.Validate(); err != nil {
			return err
		}
	}
	for _, pattern := range r.Resources {
		if err := pattern.Validate(); err != nil {
			return err
		}
	}
	for _, condition := range r.Conditions {
		if err := condition.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Matches reports whether the rule matches the authorization request.
func (r Rule) Matches(req AuthorizationRequest) bool {
	if !matchesPatterns(r.PrincipalIDs, req.Principal.ID) {
		return false
	}
	if !matchesPatterns(r.PrincipalTypes, string(req.Principal.Type)) {
		return false
	}
	if !matchesPatterns(r.ClientIDs, req.Client.ID) {
		return false
	}
	if !matchesPatterns(r.ClientTypes, req.Client.Type) {
		return false
	}
	if !matchesPatterns(r.Actions, string(req.Action)) {
		return false
	}
	if !matchesResourcePatterns(r.Resources, req.Resource) {
		return false
	}
	for _, condition := range r.Conditions {
		if !condition.Matches(req.Context) {
			return false
		}
	}
	return true
}

func matchesPatterns(patterns []StringPattern, candidate string) bool {
	if len(patterns) == 0 {
		return true
	}
	return slices.ContainsFunc(patterns, func(pattern StringPattern) bool {
		return pattern.Matches(candidate)
	})
}

func matchesResourcePatterns(patterns []ResourcePattern, resource ResourceRef) bool {
	return slices.ContainsFunc(patterns, func(pattern ResourcePattern) bool {
		return pattern.Matches(resource)
	})
}

// ValidateAndNormalizeRule validates one rule and returns a normalized copy.
func ValidateAndNormalizeRule(rule Rule) (Rule, error) {
	normalized := Rule{
		ID:             strings.TrimSpace(rule.ID),
		Effect:         Effect(strings.TrimSpace(strings.ToLower(string(rule.Effect)))),
		PrincipalIDs:   normalizePatterns(rule.PrincipalIDs),
		PrincipalTypes: normalizePatterns(rule.PrincipalTypes),
		ClientIDs:      normalizePatterns(rule.ClientIDs),
		ClientTypes:    normalizePatterns(rule.ClientTypes),
		Actions:        normalizePatterns(rule.Actions),
		Resources:      normalizeResourcePatterns(rule.Resources),
		Conditions:     normalizeConditions(rule.Conditions),
		Priority:       rule.Priority,
	}
	if rule.Escalation != nil {
		normalized.Escalation = &EscalationRequirement{
			Allowed: rule.Escalation.Allowed,
			Scope:   copyMap(rule.Escalation.Scope),
			Reason:  strings.TrimSpace(rule.Escalation.Reason),
		}
	}
	if err := normalized.Validate(); err != nil {
		return Rule{}, err
	}
	return normalized, nil
}

func normalizePatterns(patterns []StringPattern) []StringPattern {
	if len(patterns) == 0 {
		return nil
	}
	out := make([]StringPattern, len(patterns))
	for i, pattern := range patterns {
		operator := MatchOperator(strings.TrimSpace(strings.ToLower(string(pattern.Operator))))
		if operator == "" {
			operator = MatchExact
		}
		out[i] = StringPattern{
			Operator: operator,
			Value:    strings.TrimSpace(pattern.Value),
		}
	}
	return out
}

func normalizeResourcePatterns(patterns []ResourcePattern) []ResourcePattern {
	if len(patterns) == 0 {
		return nil
	}
	out := make([]ResourcePattern, len(patterns))
	for i, pattern := range patterns {
		out[i] = ResourcePattern{
			Namespace: normalizePatterns([]StringPattern{pattern.Namespace})[0],
			Type:      normalizePatterns([]StringPattern{pattern.Type})[0],
			ID:        normalizePatterns([]StringPattern{pattern.ID})[0],
		}
		if len(pattern.Attributes) > 0 {
			out[i].Attributes = make(map[string]string, len(pattern.Attributes))
			maps.Copy(out[i].Attributes, pattern.Attributes)
		}
	}
	return out
}

func normalizeConditions(conditions []Condition) []Condition {
	if len(conditions) == 0 {
		return nil
	}
	out := make([]Condition, len(conditions))
	for i, condition := range conditions {
		out[i] = Condition{
			Key:      strings.TrimSpace(condition.Key),
			Operator: ConditionOperator(strings.TrimSpace(strings.ToLower(string(condition.Operator)))),
			Value:    strings.TrimSpace(condition.Value),
		}
	}
	return out
}
