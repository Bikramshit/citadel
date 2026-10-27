package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"citadel/internal/catalog"
	"citadel/internal/handoff"
	"citadel/internal/harness"
	"citadel/internal/llm"
	"citadel/internal/policy"
	"citadel/internal/signed"
	"citadel/internal/tools"
	"citadel/internal/value"
)

// ClockConfig selects a process's time source.
type ClockConfig struct {
	Mode  string    `yaml:"mode"`  // system | fixture
	Epoch time.Time `yaml:"epoch"` // fixture mode: wall time at which the fixture's "now" begins
}

// ModelConfig selects the model implementation for an agent.
type ModelConfig struct {
	Impl string `yaml:"impl"` // scripted | model
	// Model-backed roles are configured here once the model-access gate is
	// passed (docs/GATE.md): endpoint, model ID, key file, timeouts.
	Planner   RoleModel `yaml:"planner"`
	Processor RoleModel `yaml:"processor"`
}

// RoleModel configures one model role.
type RoleModel struct {
	Endpoint string `yaml:"endpoint"`
	Model    string `yaml:"model"`
	KeyFile  string `yaml:"key_file"`
	Timeout  string `yaml:"timeout"`
}

// AgentFileConfig is an agent's configuration file.
type AgentFileConfig struct {
	Role          string            `yaml:"role"`
	Listen        string            `yaml:"listen"`
	Catalog       string            `yaml:"catalog"`
	Inventory     string            `yaml:"inventory"`
	Fixture       string            `yaml:"fixture"` // the mock environment's contents: builtin:M1 or a fixture file
	Registry      string            `yaml:"registry"`
	Key           string            `yaml:"key"`
	Thresholds    string            `yaml:"thresholds"`
	PolicyVersion string            `yaml:"policy_version"`
	HandoffMode   string            `yaml:"handoff_mode"`
	Evidence      string            `yaml:"evidence"` // on | off | legacy
	Peers         map[string]string `yaml:"peers"`
	Events        string            `yaml:"events"`
	Models        ModelConfig       `yaml:"models"`
	Clock         ClockConfig       `yaml:"clock"`
	ApprovalWait  string            `yaml:"approval_wait"`
}

// OrchestratorFileConfig is the orchestrator's configuration file.
type OrchestratorFileConfig struct {
	Listen        string      `yaml:"listen"`
	Catalog       string      `yaml:"catalog"`
	Inventory     string      `yaml:"inventory"`
	Fixture       string      `yaml:"fixture"`
	Key           string      `yaml:"key"`
	Thresholds    string      `yaml:"thresholds"`
	PolicyVersion string      `yaml:"policy_version"`
	Investigator  string      `yaml:"investigator"` // base URL of the investigator agent
	Clock         ClockConfig `yaml:"clock"`
}

func loadYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: %v", value.ErrConfig, err)
	}
	if err := value.DecodeYAMLStrict(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func resolve(base, p string) string {
	if p == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "builtin:") {
		return p
	}
	return filepath.Join(base, p)
}

// fixtureFor loads the fixture that defines the mock environment.
func fixtureFor(spec string) (*harness.Fixture, error) {
	if spec == "builtin:M1" {
		return harness.M1Fixture(), nil
	}
	if spec == "" {
		return nil, fmt.Errorf("%w: fixture is required: it defines the mock environment", value.ErrConfig)
	}
	return harness.LoadFixture(spec)
}

func clockFor(c ClockConfig, fx *harness.Fixture) (value.Clock, error) {
	switch c.Mode {
	case "", "system":
		return value.SystemClock{}, nil
	case "fixture":
		if c.Epoch.IsZero() {
			return nil, fmt.Errorf("%w: fixture clock needs an epoch", value.ErrConfig)
		}
		return value.OffsetClock{Base: fx.Now, Epoch: c.Epoch, Wall: time.Now}, nil
	}
	return nil, fmt.Errorf("%w: clock mode %q", value.ErrConfig, c.Mode)
}

func evidenceMode(s string) (policy.EvidenceMode, error) {
	switch s {
	case "", "on":
		return policy.EvidenceOn, nil
	case "off":
		return policy.EvidenceOff, nil
	case "legacy":
		return policy.EvidenceLegacy, nil
	}
	return 0, fmt.Errorf("%w: evidence mode %q", value.ErrConfig, s)
}

func handoffMode(s string) (string, error) {
	switch s {
	case "", handoff.ModeC2:
		return handoff.ModeC2, nil
	case handoff.ModeC1Instr, handoff.ModeC1Data:
		return s, nil
	}
	return "", fmt.Errorf("%w: handoff mode %q", value.ErrConfig, s)
}

// modelsFor returns the model roles. Model-backed roles need the provider
// client that the model-access gate unblocks; until then only the scripted
// stand-ins exist, and selecting "model" fails rather than guessing a
// provider.
func modelsFor(c ModelConfig, role, mode string) (llm.Set, error) {
	switch c.Impl {
	case "", llm.ImplScripted:
		return harness.Scripted(nil)(role, mode), nil
	case llm.ImplModel:
		return llm.Set{}, fmt.Errorf("%w: model-backed agents are blocked on the model-access gate: no Meta model ID, endpoint, or request format has been confirmed (docs/GATE.md)", value.ErrConfig)
	}
	return llm.Set{}, fmt.Errorf("%w: model implementation %q", value.ErrConfig, c.Impl)
}

func thresholdsFor(path string, ev policy.EvidenceMode) (harness.Thresholds, error) {
	if path == "" {
		if ev == policy.EvidenceOff {
			return harness.DefaultThresholds(), nil
		}
		return harness.Thresholds{}, fmt.Errorf("%w: thresholds file is required when evidence rules are on", value.ErrConfig)
	}
	f, err := harness.LoadThresholds(path)
	if err != nil {
		return harness.Thresholds{}, err
	}
	return f.Thresholds(), nil
}

func loadCatalogAndInventory(cat, inv string) (*catalog.Catalog, tools.InventoryData, error) {
	c, err := catalog.Load(cat)
	if err != nil {
		return nil, tools.InventoryData{}, err
	}
	d, err := harness.LoadBaseInventory(inv)
	if err != nil {
		return nil, tools.InventoryData{}, err
	}
	return c, d, nil
}

func cmdKeygen(_ context.Context, _ *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	agent := fs.String("agent", "", "agent ID: orchestrator, investigator, or responder")
	role := fs.String("role", "", "key role: orchestrator or agent (default: orchestrator for the orchestrator, agent otherwise)")
	dir := fs.String("dir", "keys", "directory for the private key file (mode 0600)")
	reg := fs.String("registry", "", "registry file to append to (default <dir>/registry.json)")
	kid := fs.String("kid", "", "key ID (generated when empty)")
	valid := fs.Duration("valid", 30*24*time.Hour, "validity window from now")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *agent == "" {
		fs.Usage()
		return errUsage
	}
	r := *role
	if r == "" {
		r = signed.RoleAgent
		if *agent == "orchestrator" {
			r = signed.RoleOrchestrator
		}
	}
	if *reg == "" {
		*reg = filepath.Join(*dir, "registry.json")
	}
	now := time.Now().UTC()
	id, err := signed.Keygen(signed.KeygenOptions{Dir: *dir, Registry: *reg, Agent: *agent, Role: r, KID: *kid,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(*valid), Rand: rand.Reader})
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", strings.TrimSpace(filepath.Join(*dir, id+".key")))
	return nil
}
