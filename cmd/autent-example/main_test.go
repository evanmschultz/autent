package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evanmschultz/autent/domain"
)

// TestRunUsage verifies the CLI prints usage when called without arguments.
func TestRunUsage(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if err := run(nil, &out); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(out.String(), "autent-example commands:") {
		t.Fatalf("run() output = %q, want usage text", out.String())
	}
}

// TestRunHumanFlow verifies the example CLI can drive the intended manual demo flow.
func TestRunHumanFlow(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "autent.db")

	runCommand := func(args ...string) []byte {
		t.Helper()

		var out bytes.Buffer
		if err := run(args, &out); err != nil {
			t.Fatalf("run(%v) error = %v", args, err)
		}
		return out.Bytes()
	}

	runCommand("principal", "create", "--db", dbPath, "--db-prefix", "demo_", "--id", "principal-1", "--type", "user", "--name", "User One")
	runCommand("client", "create", "--db", dbPath, "--db-prefix", "demo_", "--id", "client-1", "--type", "cli", "--name", "CLI")
	runCommand("policy", "load-demo", "--db", dbPath, "--db-prefix", "demo_")

	sessionPayload := runCommand("session", "issue", "--db", dbPath, "--db-prefix", "demo_", "--principal", "principal-1", "--client", "client-1")
	var issued struct {
		SessionID     string `json:"session_id"`
		SessionSecret string `json:"session_secret"`
	}
	if err := json.Unmarshal(sessionPayload, &issued); err != nil {
		t.Fatalf("json.Unmarshal(session issue) error = %v", err)
	}
	if issued.SessionID == "" || issued.SessionSecret == "" {
		t.Fatalf("issued session = %+v, want session id and secret", issued)
	}

	readDecisionPayload := runCommand(
		"authz", "check",
		"--db", dbPath,
		"--db-prefix", "demo_",
		"--session", issued.SessionID,
		"--secret", issued.SessionSecret,
		"--action", "read",
		"--namespace", "project:demo",
		"--resource-type", "task",
		"--resource-id", "task-1",
	)
	var readDecision domain.Decision
	if err := json.Unmarshal(readDecisionPayload, &readDecision); err != nil {
		t.Fatalf("json.Unmarshal(read decision) error = %v", err)
	}
	if readDecision.Code != domain.DecisionAllow {
		t.Fatalf("readDecision.Code = %q, want %q", readDecision.Code, domain.DecisionAllow)
	}

	grantRequiredPayload := runCommand(
		"authz", "check",
		"--db", dbPath,
		"--db-prefix", "demo_",
		"--session", issued.SessionID,
		"--secret", issued.SessionSecret,
		"--action", "mutate",
		"--namespace", "project:demo",
		"--resource-type", "task",
		"--resource-id", "task-1",
		"--context", "scope=current",
	)
	var grantRequired domain.Decision
	if err := json.Unmarshal(grantRequiredPayload, &grantRequired); err != nil {
		t.Fatalf("json.Unmarshal(grant required decision) error = %v", err)
	}
	if grantRequired.Code != domain.DecisionGrantRequired {
		t.Fatalf("grantRequired.Code = %q, want %q", grantRequired.Code, domain.DecisionGrantRequired)
	}

	grantPayload := runCommand(
		"grant", "request",
		"--db", dbPath,
		"--db-prefix", "demo_",
		"--session", issued.SessionID,
		"--secret", issued.SessionSecret,
		"--action", "mutate",
		"--namespace", "project:demo",
		"--resource-type", "task",
		"--resource-id", "task-1",
		"--context", "scope=current",
		"--reason", "need one mutation",
	)
	var grant struct {
		ID string
	}
	if err := json.Unmarshal(grantPayload, &grant); err != nil {
		t.Fatalf("json.Unmarshal(grant request) error = %v", err)
	}
	if grant.ID == "" {
		t.Fatal("grant.ID = empty, want generated id")
	}

	runCommand("grant", "approve", "--db", dbPath, "--db-prefix", "demo_", "--grant-id", grant.ID, "--actor", "reviewer-1", "--note", "approved", "--usage-limit", "1")

	approvedDecisionPayload := runCommand(
		"authz", "check",
		"--db", dbPath,
		"--db-prefix", "demo_",
		"--session", issued.SessionID,
		"--secret", issued.SessionSecret,
		"--action", "mutate",
		"--namespace", "project:demo",
		"--resource-type", "task",
		"--resource-id", "task-1",
		"--context", "scope=current",
	)
	var approvedDecision domain.Decision
	if err := json.Unmarshal(approvedDecisionPayload, &approvedDecision); err != nil {
		t.Fatalf("json.Unmarshal(approved decision) error = %v", err)
	}
	if approvedDecision.Code != domain.DecisionAllow || approvedDecision.GrantID == "" {
		t.Fatalf("approvedDecision = %+v, want allow with grant id", approvedDecision)
	}

	consumedDecisionPayload := runCommand(
		"authz", "check",
		"--db", dbPath,
		"--db-prefix", "demo_",
		"--session", issued.SessionID,
		"--secret", issued.SessionSecret,
		"--action", "mutate",
		"--namespace", "project:demo",
		"--resource-type", "task",
		"--resource-id", "task-1",
		"--context", "scope=current",
	)
	var consumedDecision domain.Decision
	if err := json.Unmarshal(consumedDecisionPayload, &consumedDecision); err != nil {
		t.Fatalf("json.Unmarshal(consumed decision) error = %v", err)
	}
	if consumedDecision.Code != domain.DecisionGrantRequired {
		t.Fatalf("consumedDecision.Code = %q, want %q", consumedDecision.Code, domain.DecisionGrantRequired)
	}

	revokedPayload := runCommand("session", "revoke", "--db", dbPath, "--db-prefix", "demo_", "--session", issued.SessionID, "--reason", "manual_revoke")
	if strings.Contains(string(revokedPayload), "\"SecretHash\"") {
		t.Fatalf("session revoke output leaked SecretHash: %s", revokedPayload)
	}
	var revoked sessionView
	if err := json.Unmarshal(revokedPayload, &revoked); err != nil {
		t.Fatalf("json.Unmarshal(session revoke) error = %v", err)
	}
	if revoked.ID != issued.SessionID {
		t.Fatalf("revoked.ID = %q, want %q", revoked.ID, issued.SessionID)
	}

	auditPayload := runCommand("audit", "list", "--db", dbPath, "--db-prefix", "demo_", "--session", issued.SessionID)
	var events []domain.AuditEvent
	if err := json.Unmarshal(auditPayload, &events); err != nil {
		t.Fatalf("json.Unmarshal(audit list) error = %v", err)
	}
	if len(events) == 0 {
		t.Fatal("len(events) = 0, want audit events")
	}
}

// TestRunGrantDenyAndCancel verifies the additional grant lifecycle commands work.
func TestRunGrantDenyAndCancel(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "autent.db")

	runCommand := func(args ...string) []byte {
		t.Helper()

		var out bytes.Buffer
		if err := run(args, &out); err != nil {
			t.Fatalf("run(%v) error = %v", args, err)
		}
		return out.Bytes()
	}

	runCommand("principal", "create", "--db", dbPath, "--id", "principal-1", "--type", "user", "--name", "User One")
	runCommand("client", "create", "--db", dbPath, "--id", "client-1", "--type", "cli", "--name", "CLI")
	runCommand("policy", "load-demo", "--db", dbPath)

	sessionPayload := runCommand("session", "issue", "--db", dbPath, "--principal", "principal-1", "--client", "client-1")
	var issued struct {
		SessionID     string `json:"session_id"`
		SessionSecret string `json:"session_secret"`
	}
	if err := json.Unmarshal(sessionPayload, &issued); err != nil {
		t.Fatalf("json.Unmarshal(session issue) error = %v", err)
	}

	requestGrant := func(reason string) domain.Grant {
		t.Helper()

		payload := runCommand(
			"grant", "request",
			"--db", dbPath,
			"--session", issued.SessionID,
			"--secret", issued.SessionSecret,
			"--action", "mutate",
			"--namespace", "project:demo",
			"--resource-type", "task",
			"--resource-id", "task-1",
			"--context", "scope=current",
			"--reason", reason,
		)
		var grant domain.Grant
		if err := json.Unmarshal(payload, &grant); err != nil {
			t.Fatalf("json.Unmarshal(grant request) error = %v", err)
		}
		return grant
	}

	deniedGrant := requestGrant("deny me")
	deniedPayload := runCommand("grant", "deny", "--db", dbPath, "--grant-id", deniedGrant.ID, "--actor", "reviewer-1", "--note", "rejected")
	var denied domain.Grant
	if err := json.Unmarshal(deniedPayload, &denied); err != nil {
		t.Fatalf("json.Unmarshal(grant deny) error = %v", err)
	}
	if denied.State != domain.GrantStateDenied {
		t.Fatalf("denied.State = %q, want denied", denied.State)
	}

	canceledGrant := requestGrant("cancel me")
	canceledPayload := runCommand("grant", "cancel", "--db", dbPath, "--grant-id", canceledGrant.ID, "--actor", "operator-1", "--note", "withdrawn")
	var canceled domain.Grant
	if err := json.Unmarshal(canceledPayload, &canceled); err != nil {
		t.Fatalf("json.Unmarshal(grant cancel) error = %v", err)
	}
	if canceled.State != domain.GrantStateCanceled {
		t.Fatalf("canceled.State = %q, want canceled", canceled.State)
	}
}

// TestMainFailure verifies the process entrypoint writes errors and exits non-zero.
func TestMainFailure(t *testing.T) {
	originalStdout := stdout
	originalStderr := stderr
	originalExitFunc := exitFunc
	originalArgs := osArgs
	t.Cleanup(func() {
		stdout = originalStdout
		stderr = originalStderr
		exitFunc = originalExitFunc
		osArgs = originalArgs
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	stdout = &out
	stderr = &errOut
	osArgs = []string{"autent-example", "bogus"}

	exitCode := 0
	exitFunc = func(code int) {
		exitCode = code
	}

	main()

	if exitCode != 1 {
		t.Fatalf("main() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("main() stderr = %q, want unknown command", errOut.String())
	}
}
