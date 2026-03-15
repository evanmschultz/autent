package main

import (
	"bytes"
	"encoding/json"
	"os"
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
	if !strings.Contains(out.String(), "authent-example commands:") {
		t.Fatalf("run() output = %q, want usage text", out.String())
	}
}

// TestRunHumanFlow verifies the example CLI can drive the intended manual demo flow.
func TestRunHumanFlow(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "authent.db")

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
	if issued.SessionID == "" || issued.SessionSecret == "" {
		t.Fatalf("issued session = %+v, want session id and secret", issued)
	}

	readDecisionPayload := runCommand(
		"authz", "check",
		"--db", dbPath,
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

	runCommand("grant", "approve", "--db", dbPath, "--grant-id", grant.ID, "--actor", "reviewer-1", "--note", "approved", "--usage-limit", "1")

	approvedDecisionPayload := runCommand(
		"authz", "check",
		"--db", dbPath,
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

	runCommand("session", "revoke", "--db", dbPath, "--session", issued.SessionID, "--reason", "manual_revoke")
	auditPayload := runCommand("audit", "list", "--db", dbPath, "--session", issued.SessionID)
	var events []domain.AuditEvent
	if err := json.Unmarshal(auditPayload, &events); err != nil {
		t.Fatalf("json.Unmarshal(audit list) error = %v", err)
	}
	if len(events) == 0 {
		t.Fatal("len(events) = 0, want audit events")
	}
}

// TestMainFailure verifies the process entrypoint writes errors and exits non-zero.
func TestMainFailure(t *testing.T) {
	originalStdout := stdout
	originalStderr := stderr
	originalExitFunc := exitFunc
	originalArgs := os.Args
	t.Cleanup(func() {
		stdout = originalStdout
		stderr = originalStderr
		exitFunc = originalExitFunc
		os.Args = originalArgs
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	stdout = &out
	stderr = &errOut
	os.Args = []string{"authent-example", "bogus"}

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
