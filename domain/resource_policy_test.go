package domain

import (
	"testing"
)

// TestStringPatternMatches verifies exact, prefix, glob, and any matching modes.
func TestStringPatternMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern StringPattern
		value   string
		want    bool
	}{
		{name: "exact", pattern: StringPattern{Operator: MatchExact, Value: "tool"}, value: "tool", want: true},
		{name: "prefix", pattern: StringPattern{Operator: MatchPrefix, Value: "gopls."}, value: "gopls.rename", want: true},
		{name: "glob", pattern: StringPattern{Operator: MatchGlob, Value: "project:*"}, value: "project:demo", want: true},
		{name: "any", pattern: StringPattern{Operator: MatchAny}, value: "anything", want: true},
		{name: "miss", pattern: StringPattern{Operator: MatchExact, Value: "tool"}, value: "path", want: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.pattern.Matches(test.value); got != test.want {
				t.Fatalf("pattern.Matches(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

// TestResourcePatternMatches verifies resource envelope matching.
func TestResourcePatternMatches(t *testing.T) {
	t.Parallel()

	resource := ResourceRef{
		Namespace: "project:demo",
		Type:      "tool",
		ID:        "gopls.rename",
		Attributes: map[string]string{
			"scope": "write",
		},
	}
	pattern := ResourcePattern{
		Namespace: StringPattern{Operator: MatchGlob, Value: "project:*"},
		Type:      StringPattern{Operator: MatchExact, Value: "tool"},
		ID:        StringPattern{Operator: MatchGlob, Value: "gopls.*"},
		Attributes: map[string]string{
			"scope": "write",
		},
	}
	if !pattern.Matches(resource) {
		t.Fatal("pattern should match resource")
	}
}

// TestRuleMatches verifies selectors, actions, resources, and context conditions.
func TestRuleMatches(t *testing.T) {
	t.Parallel()

	req := AuthorizationRequest{
		Principal: Principal{ID: "principal-1", Type: PrincipalTypeUser},
		Client:    Client{ID: "client-1", Type: "mcp"},
		Action:    "mutate",
		Resource: ResourceRef{
			Namespace: "project:demo",
			Type:      "tool",
			ID:        "gopls.rename",
			Attributes: map[string]string{
				"scope": "write",
			},
		},
		Context: map[string]string{
			"project": "demo",
		},
	}
	rule := Rule{
		ID:     "rule-1",
		Effect: EffectAllow,
		PrincipalIDs: []StringPattern{
			{Operator: MatchExact, Value: "principal-1"},
		},
		ClientTypes: []StringPattern{
			{Operator: MatchExact, Value: "mcp"},
		},
		Actions: []StringPattern{
			{Operator: MatchExact, Value: "mutate"},
		},
		Resources: []ResourcePattern{
			{
				Namespace: StringPattern{Operator: MatchGlob, Value: "project:*"},
				Type:      StringPattern{Operator: MatchExact, Value: "tool"},
				ID:        StringPattern{Operator: MatchGlob, Value: "gopls.*"},
			},
		},
		Conditions: []Condition{
			{Key: "project", Operator: ConditionEquals, Value: "demo"},
		},
		Priority: 10,
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("rule.Validate() error = %v", err)
	}
	if !rule.Matches(req) {
		t.Fatal("rule should match request")
	}
}
