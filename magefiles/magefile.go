// Package main defines Mage targets for autent repository automation.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/evanmschultz/laslig"
)

// Aliases preserves stable task names that previously used hyphenated just recipes.
var Aliases = map[string]any{
	"test-pkg": TestPkg,
}

// taskPrinter renders human-facing automation status output.
var taskPrinter = laslig.New(os.Stdout, laslig.Policy{
	Format: laslig.FormatAuto,
	Style:  laslig.StyleAuto,
})

// Fmt formats Go source files with gofumpt when the repository is initialized.
func Fmt() error {
	if err := renderSection("fmt"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return renderSkip("fmt", "go.mod not initialized yet")
	}
	if err := requireTool("gofumpt", "fmt failed: gofumpt is not installed", "brew install gofumpt"); err != nil {
		return err
	}

	goFiles, err := collectGoFiles(".")
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return renderSkip("fmt", "no Go files found")
	}

	if err := runCommand(nil, "gofumpt", append([]string{"-w"}, goFiles...)...); err != nil {
		return err
	}
	return renderSuccess("fmt", "formatted Go sources")
}

// Test runs the full Go test suite when Go sources are present.
func Test() error {
	if err := renderSection("test"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return renderSkip("test", "go.mod not initialized yet")
	}

	goFiles, err := collectGoFiles(".")
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return renderSkip("test", "no Go files found")
	}

	if err := runCommand(goCommandEnv(), "go", "test", "./..."); err != nil {
		return err
	}
	return renderSuccess("test", "all packages passed")
}

// Lint runs golangci-lint when the repository has Go sources and a valid git HEAD.
func Lint() error {
	if err := renderSection("lint"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return renderSkip("lint", "go.mod not initialized yet")
	}
	if err := requireTool("golangci-lint", "lint failed: golangci-lint is not installed", "brew install golangci-lint"); err != nil {
		return err
	}

	goFiles, err := collectGoFiles(".")
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return renderSkip("lint", "no Go files found")
	}
	if !gitHeadExists() {
		return renderSkip("lint", "git HEAD is missing")
	}
	targets, err := listLintTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return renderSkip("lint", "no Go packages found")
	}

	if err := runCommand(nil, "golangci-lint", append([]string{"run"}, targets...)...); err != nil {
		return err
	}
	return renderSuccess("lint", "lint passed")
}

// TestPkg runs package-scoped Go tests, matching the previous just recipe behavior.
func TestPkg(pkg string) error {
	if err := renderSection("test-pkg"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return renderSkip("test-pkg", "go.mod not initialized yet")
	}

	target := pkg
	if dirExists(pkg) {
		hasDirectGoFiles, err := directoryHasDirectGoFiles(pkg)
		if err != nil {
			return err
		}
		if !hasDirectGoFiles {
			target = filepath.ToSlash(filepath.Join(pkg, "..."))
		}
	}

	if err := runCommand(goCommandEnv(), "go", "test", target); err != nil {
		return err
	}
	return renderSuccess("test-pkg", fmt.Sprintf("package tests passed for %s", pkg))
}

// Build verifies that the example program still compiles when it is present.
func Build() error {
	if err := renderSection("build"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return renderSkip("build", "go.mod not initialized yet")
	}
	if !dirExists(filepath.Join("cmd", "autent-example")) {
		return renderSkip("build", "./cmd/autent-example not present")
	}

	tmpFile, err := os.CreateTemp("", "autent-example.*")
	if err != nil {
		return fmt.Errorf("create temporary build output: %w", err)
	}
	tmpPath := tmpFile.Name()
	if closeErr := tmpFile.Close(); closeErr != nil {
		return fmt.Errorf("close temporary build output: %w", closeErr)
	}
	defer os.Remove(tmpPath)

	if err := runCommand(goCommandEnv(), "go", "build", "-o", tmpPath, "./cmd/autent-example"); err != nil {
		return err
	}
	return renderSuccess("build", "example build succeeded")
}

// Run executes the example program for manual testing.
func Run() error {
	if err := renderSection("run"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return errors.New("run failed: go.mod not initialized yet")
	}
	if !dirExists(filepath.Join("cmd", "autent-example")) {
		return errors.New("run failed: expected ./cmd/autent-example to exist")
	}

	return runCommand(goCommandEnv(), "go", "run", "./cmd/autent-example")
}

// Check runs the fast cross-platform contributor gate.
func Check() error {
	if err := renderSection("check"); err != nil {
		return err
	}
	if err := verifyBootstrap(); err != nil {
		return err
	}
	if err := fmtCheck(); err != nil {
		return err
	}
	if err := Lint(); err != nil {
		return err
	}
	if err := Test(); err != nil {
		return err
	}
	if err := Build(); err != nil {
		return err
	}
	return renderSuccess("check", "canonical smoke gate passed")
}

// Ci runs the full repository gate, including coverage and release validation.
func Ci() error {
	if err := renderSection("ci"); err != nil {
		return err
	}
	if err := verifyBootstrap(); err != nil {
		return err
	}
	if err := fmtCheck(); err != nil {
		return err
	}
	if err := Lint(); err != nil {
		return err
	}
	if err := Test(); err != nil {
		return err
	}
	if err := coverage(); err != nil {
		return err
	}
	if err := Build(); err != nil {
		return err
	}
	if err := releaseCheck(); err != nil {
		return err
	}
	return renderSuccess("ci", "full gate passed")
}

// verifyBootstrap validates the repository files required by automation and CI.
func verifyBootstrap() error {
	if err := renderSection("verify-bootstrap"); err != nil {
		return err
	}

	for _, path := range bootstrapPaths() {
		if !fileExists(path) {
			return fmt.Errorf("verify-bootstrap failed: %s not found", path)
		}
	}
	return renderSuccess("verify-bootstrap", "required automation files are present")
}

// fmtCheck verifies that gofumpt would not rewrite any tracked Go sources.
func fmtCheck() error {
	if err := renderSection("fmt-check"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return renderSkip("fmt-check", "go.mod not initialized yet")
	}
	if err := requireTool("gofumpt", "fmt-check failed: gofumpt is not installed", "brew install gofumpt"); err != nil {
		return err
	}

	goFiles, err := collectGoFiles(".")
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return renderSkip("fmt-check", "no Go files found")
	}

	output, err := runCommandOutput(nil, "gofumpt", append([]string{"-l"}, goFiles...)...)
	if err != nil {
		return err
	}
	out := strings.TrimSpace(output)
	if out == "" {
		return renderSuccess("fmt-check", "formatting already clean")
	}
	return fmt.Errorf("gofumpt required for:\n%s", out)
}

// coverage enforces the repository's package coverage floor.
func coverage() error {
	if err := renderSection("coverage"); err != nil {
		return err
	}
	if !fileExists("go.mod") {
		return renderSkip("coverage", "go.mod not initialized yet")
	}

	goFiles, err := collectGoFiles(".")
	if err != nil {
		return err
	}
	if len(goFiles) == 0 {
		return renderSkip("coverage", "no Go files found")
	}

	output, err := runCommandTee(goCommandEnv(), "go", "test", "./...", "-cover")
	if err != nil {
		return err
	}

	belowFloor := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "ok") || !strings.Contains(line, "coverage:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		idx := strings.Index(line, "coverage:")
		if idx == -1 {
			continue
		}
		covText := strings.TrimSpace(strings.TrimPrefix(line[idx:], "coverage:"))
		percentIdx := strings.Index(covText, "%")
		if percentIdx == -1 {
			continue
		}

		valueText := strings.TrimSpace(covText[:percentIdx])
		cov, parseErr := strconv.ParseFloat(valueText, 64)
		if parseErr != nil {
			return fmt.Errorf("parse coverage %q: %w", valueText, parseErr)
		}
		if cov < 70 {
			belowFloor = append(belowFloor, fmt.Sprintf("%s %s%%", fields[1], valueText))
		}
	}

	if len(belowFloor) > 0 {
		return fmt.Errorf("coverage below 70%%:\n%s", strings.Join(belowFloor, "\n"))
	}
	return renderSuccess("coverage", "coverage floor satisfied")
}

// releaseCheck validates GoReleaser configuration and snapshot buildability.
func releaseCheck() error {
	if err := renderSection("release-check"); err != nil {
		return err
	}
	if !fileExists(".goreleaser.yml") {
		return errors.New("release-check failed: .goreleaser.yml not found")
	}
	if err := requireTool("goreleaser", "release-check failed: goreleaser is not installed", "brew install goreleaser"); err != nil {
		return err
	}

	defer os.RemoveAll("dist")
	if err := runCommand(nil, "goreleaser", "check"); err != nil {
		return err
	}
	if err := runCommand(nil, "goreleaser", "build", "--snapshot", "--clean", "--single-target"); err != nil {
		return err
	}
	return renderSuccess("release-check", "release configuration validated")
}

// bootstrapPaths returns the repository files required by the automation bootstrap.
func bootstrapPaths() []string {
	return []string{
		"AGENTS.md",
		"README.md",
		filepath.Join("magefiles", "go.mod"),
		filepath.Join("magefiles", "magefile.go"),
		".goreleaser.yml",
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "release.yml"),
	}
}

// renderSection prints a visual section header for one target.
func renderSection(title string) error {
	return taskPrinter.Section(title)
}

// renderSkip prints a warning-level skip message for a target.
func renderSkip(target string, reason string) error {
	return taskPrinter.StatusLine(laslig.StatusLine{
		Level:  laslig.NoticeWarningLevel,
		Label:  "skip",
		Text:   target,
		Detail: reason,
	})
}

// renderSuccess prints a success summary for a target.
func renderSuccess(target string, detail string) error {
	return taskPrinter.StatusLine(laslig.StatusLine{
		Level:  laslig.NoticeSuccessLevel,
		Label:  target,
		Text:   "ok",
		Detail: detail,
	})
}

// requireTool verifies that a binary exists on PATH before a target uses it.
func requireTool(name string, message string, installHint string) error {
	if _, err := exec.LookPath(name); err == nil {
		return nil
	}
	return errors.New(message + "\ninstall: " + installHint)
}

// fileExists reports whether a file or directory exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists reports whether a directory exists.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// collectGoFiles gathers Go sources while skipping local scratch and VCS directories.
func collectGoFiles(root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if shouldSkipDir(path, entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collect Go files: %w", err)
	}

	sort.Strings(files)
	return files, nil
}

// shouldSkipDir reports whether a directory should be excluded from repository scans.
func shouldSkipDir(path string, name string) bool {
	if path == "." {
		return false
	}
	switch name {
	case ".git", ".tmp", ".cache", ".resources":
		return true
	default:
		return false
	}
}

// directoryHasDirectGoFiles reports whether a directory contains Go files directly within it.
func directoryHasDirectGoFiles(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, fmt.Errorf("read directory %s: %w", path, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".go") {
			return true, nil
		}
	}
	return false, nil
}

// gitHeadExists reports whether the repository currently has a resolvable HEAD commit.
func gitHeadExists() bool {
	cmd := exec.Command("git", "rev-parse", "--verify", "HEAD")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// goCommandEnv returns the environment for Go-family tools that should suppress buildvcs metadata.
func goCommandEnv() []string {
	return append(os.Environ(), "GOFLAGS="+mergedGOFLAGS())
}

// listLintTargets returns repo-relative package directories for the root module only.
func listLintTargets() ([]string, error) {
	cmd := exec.Command("go", "list", "-f", "{{.Dir}}", "./...")
	cmd.Env = goCommandEnv()

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := taskPrinter.StatusLine(laslig.StatusLine{
		Level: laslig.NoticeInfoLevel,
		Label: "run",
		Text:  commandString("go", "list", "-f", "{{.Dir}}", "./..."),
	}); err != nil {
		return nil, err
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w", commandString("go", "list", "-f", "{{.Dir}}", "./..."), err)
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return nil, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}

	targets := make([]string, 0)
	seen := make(map[string]struct{})
	for _, dir := range strings.Fields(output) {
		rel, err := filepath.Rel(cwd, dir)
		if err != nil {
			return nil, fmt.Errorf("make %s relative to %s: %w", dir, cwd, err)
		}
		rel = filepath.ToSlash(rel)

		target := "."
		if rel != "." {
			target = "./" + rel
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}

	return targets, nil
}

// mergedGOFLAGS appends the repository's default buildvcs override to any existing GOFLAGS.
func mergedGOFLAGS() string {
	if current := strings.TrimSpace(os.Getenv("GOFLAGS")); current != "" {
		return current + " -buildvcs=false"
	}
	return "-buildvcs=false"
}

// runCommand executes a command while streaming output to the terminal.
func runCommand(env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := taskPrinter.StatusLine(laslig.StatusLine{
		Level: laslig.NoticeInfoLevel,
		Label: "run",
		Text:  commandString(name, args...),
	}); err != nil {
		return err
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", commandString(name, args...), err)
	}
	return nil
}

// runCommandOutput executes a command and returns its combined output.
func runCommandOutput(env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}
	if err := taskPrinter.StatusLine(laslig.StatusLine{
		Level: laslig.NoticeInfoLevel,
		Label: "run",
		Text:  commandString(name, args...),
	}); err != nil {
		return "", err
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w\n%s", commandString(name, args...), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

// runCommandTee executes a command, streams output, and also captures it for later parsing.
func runCommandTee(env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if env != nil {
		cmd.Env = env
	}

	var buffer bytes.Buffer
	stdout := io.MultiWriter(os.Stdout, &buffer)
	stderr := io.MultiWriter(os.Stderr, &buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := taskPrinter.StatusLine(laslig.StatusLine{
		Level: laslig.NoticeInfoLevel,
		Label: "run",
		Text:  commandString(name, args...),
	}); err != nil {
		return "", err
	}
	if err := cmd.Run(); err != nil {
		return buffer.String(), fmt.Errorf("%s: %w", commandString(name, args...), err)
	}
	return buffer.String(), nil
}

// commandString formats a command line for human-facing status output.
func commandString(name string, args ...string) string {
	parts := append([]string{name}, args...)
	return strings.Join(parts, " ")
}
