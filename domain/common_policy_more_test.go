package domain

import (
	"errors"
	"testing"
	"time"
)

// TestStatusAndPrincipalTypeHelpers verifies the status and principal-type helpers.
func TestStatusAndPrincipalTypeHelpers(t *testing.T) {
	t.Parallel()

	if got := NormalizeStatus(" ACTIVE "); got != StatusActive {
		t.Fatalf("NormalizeStatus() = %q, want %q", got, StatusActive)
	}
	if !IsValidStatus(StatusDisabled) {
		t.Fatal("IsValidStatus() should accept disabled")
	}
	if IsValidStatus("bogus") {
		t.Fatal("IsValidStatus() should reject unknown values")
	}
	if got := NormalizePrincipalType(" AGENT "); got != PrincipalTypeAgent {
		t.Fatalf("NormalizePrincipalType() = %q, want %q", got, PrincipalTypeAgent)
	}
	if !IsValidPrincipalType(PrincipalTypeService) {
		t.Fatal("IsValidPrincipalType() should accept service")
	}
}

// TestActionAndResourceValidation verifies action and resource validation helpers.
func TestActionAndResourceValidation(t *testing.T) {
	t.Parallel()

	if got := NormalizeAction(" READ "); got != Action("read") {
		t.Fatalf("NormalizeAction() = %q, want read", got)
	}
	if err := Action("").Validate(); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("Action.Validate() error = %v, want ErrInvalidAction", err)
	}
	if err := (ResourceRef{Type: "task"}).Validate(); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("ResourceRef.Validate() error = %v, want ErrInvalidResource", err)
	}
	if err := (ResourceRef{Type: "task", ID: "task-1"}).Validate(); err != nil {
		t.Fatalf("ResourceRef.Validate() error = %v", err)
	}
}

// TestConditionValidationAndMatch verifies condition operators.
func TestConditionValidationAndMatch(t *testing.T) {
	t.Parallel()

	condition := Condition{Key: "scope", Operator: ConditionPresent}
	if err := condition.Validate(); err != nil {
		t.Fatalf("Condition.Validate() error = %v", err)
	}
	if !condition.Matches(map[string]string{"scope": "current"}) {
		t.Fatal("Condition.Matches() should match present keys")
	}
	if condition.Matches(map[string]string{}) {
		t.Fatal("Condition.Matches() should reject missing keys")
	}
	if err := (Condition{Key: "scope", Operator: ConditionEquals}).Validate(); !errors.Is(err, ErrInvalidCondition) {
		t.Fatalf("Condition.Validate() error = %v, want ErrInvalidCondition", err)
	}
}

// TestValidateAndNormalizeRule verifies normalized rule output and invalid cases.
func TestValidateAndNormalizeRule(t *testing.T) {
	t.Parallel()

	rule, err := ValidateAndNormalizeRule(Rule{
		ID:     " rule-1 ",
		Effect: " ALLOW ",
		Actions: []StringPattern{
			{Value: " READ "},
		},
		Resources: []ResourcePattern{
			{
				Namespace: StringPattern{Value: " project:* "},
				Type:      StringPattern{Value: " task "},
				ID:        StringPattern{Value: " task-1 "},
			},
		},
		Conditions: []Condition{
			{Key: " scope ", Operator: " EQUALS ", Value: " current "},
		},
		Escalation: &EscalationRequirement{
			Allowed: true,
			Scope:   map[string]string{"project": "demo"},
			Reason:  " once ",
		},
	})
	if err != nil {
		t.Fatalf("ValidateAndNormalizeRule() error = %v", err)
	}
	if rule.ID != "rule-1" {
		t.Fatalf("rule.ID = %q, want rule-1", rule.ID)
	}
	if rule.Effect != EffectAllow {
		t.Fatalf("rule.Effect = %q, want %q", rule.Effect, EffectAllow)
	}
	if rule.Actions[0].Operator != MatchExact {
		t.Fatalf("rule.Actions[0].Operator = %q, want %q", rule.Actions[0].Operator, MatchExact)
	}
	if rule.Conditions[0].Key != "scope" || rule.Conditions[0].Value != "current" {
		t.Fatalf("rule.Conditions[0] = %+v, want trimmed values", rule.Conditions[0])
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("rule.Validate() error = %v", err)
	}
	if _, err := ValidateAndNormalizeRule(Rule{ID: "rule-2"}); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("ValidateAndNormalizeRule(invalid) error = %v, want ErrInvalidRule", err)
	}
}

// TestGrantAdditionalTransitions verifies deny and cancel transitions.
func TestGrantAdditionalTransitions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 14, 12, 0, 0, 0, time.UTC)
	grant, err := NewGrant(GrantInput{
		ID:          "grant-1",
		SessionID:   "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		Action:      "mutate",
		Resource: ResourceRef{
			Type: "task",
			ID:   "task-1",
		},
		Fingerprint: "fp-1",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := grant.Deny("reviewer-1", "no", now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Deny() error = %v", err)
	}
	if grant.State != GrantStateDenied {
		t.Fatalf("grant.State = %q, want %q", grant.State, GrantStateDenied)
	}

	grant, err = NewGrant(GrantInput{
		ID:          "grant-2",
		SessionID:   "session-1",
		PrincipalID: "principal-1",
		ClientID:    "client-1",
		Action:      "mutate",
		Resource: ResourceRef{
			Type: "task",
			ID:   "task-1",
		},
		Fingerprint: "fp-2",
		ExpiresAt:   now.Add(time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	if err := grant.Cancel("reviewer-1", "later", now.Add(time.Minute)); err != nil {
		t.Fatalf("grant.Cancel() error = %v", err)
	}
	if grant.State != GrantStateCanceled {
		t.Fatalf("grant.State = %q, want %q", grant.State, GrantStateCanceled)
	}
}
