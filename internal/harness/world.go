package harness

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/events"
	"citadel/internal/evidence"
	"citadel/internal/handoff"
	"citadel/internal/interp"
	"citadel/internal/label"
	"citadel/internal/llm"
	"citadel/internal/orchestrator"
	"citadel/internal/policy"
	"citadel/internal/signed"
	"citadel/internal/tools"
	"citadel/internal/value"
)

// Configuration names.
const (
	C0      = "C0"
	C1Instr = "C1-instr"
	C1Data  = "C1-data"
	C2      = "C2"
)

// Configs lists every configuration in report order.
func Configs() []string { return []string{C0, C1Instr, C1Data, C2} }

// PolicyVersion is the policy version the orchestrator signs and agents
// support.
const PolicyVersion = "citadel-policy-v1"

// Agent names and static capabilities.
const (
	Investigator = "investigator"
	Responder    = "responder"
)

// StaticCaps returns an agent's static capabilities. firewall.allow is a
// Responder static capability so tests can show that the run grant removes
// it.
func StaticCaps(agent string) []authz.Cap {
	switch agent {
	case Investigator:
		return []authz.Cap{{Tool: "logs", Action: "read"}, {Tool: "handoff", Action: "request"}}
	case Responder:
		return []authz.Cap{{Tool: "firewall", Action: "block"}, {Tool: "firewall", Action: "allow"},
			{Tool: "accounts", Action: "disable"}, {Tool: "inventory", Action: "read"}}
	}
	return nil
}

// Thresholds are the frozen tuned values from thresholds.yaml.
type Thresholds struct {
	K               int `yaml:"k" json:"k"`
	MinFlows        int `yaml:"min_flows" json:"min_flows"`
	SoftUntrustedPC int `yaml:"soft_untrusted_pc" json:"soft_untrusted_pc"`
	IterationBudget int `yaml:"iteration_budget" json:"iteration_budget"`
}

// DefaultThresholds are the specification's starting values, used only
// before tuning and in deterministic tests.
func DefaultThresholds() Thresholds {
	return Thresholds{K: 5, MinFlows: 1, SoftUntrustedPC: 20, IterationBudget: 64}
}

// Keys are one world's signing keys and registry.
type Keys struct {
	Registry     *signed.Registry
	Orchestrator *signed.Signer
	Investigator *signed.Signer
	Responder    *signed.Signer
}

// NewKeys generates keys from r, valid around now.
func NewKeys(r io.Reader, now time.Time) (*Keys, error) {
	k := &Keys{}
	var entries []signed.Key
	for _, spec := range []struct {
		agent, role string
		dst         **signed.Signer
	}{{"orchestrator", signed.RoleOrchestrator, &k.Orchestrator}, {Investigator, signed.RoleAgent, &k.Investigator}, {Responder, signed.RoleAgent, &k.Responder}} {
		pub, priv, err := ed25519.GenerateKey(r)
		if err != nil {
			return nil, fmt.Errorf("keys: %w", err)
		}
		kid := spec.agent + "-" + now.UTC().Format("2006-01") + "-a"
		*spec.dst = signed.NewSigner(kid, spec.agent, priv)
		entries = append(entries, signed.NewKey(kid, spec.agent, spec.role, pub, now.Add(-24*time.Hour), now.Add(30*24*time.Hour), signed.StatusActive))
	}
	reg, err := signed.NewRegistry(entries...)
	if err != nil {
		return nil, err
	}
	k.Registry = reg
	return k, nil
}

// Models returns the model roles for an agent in a configuration.
type Models func(agent, config string) llm.Set

// Options configures one run.
type Options struct {
	Config        string
	Trial         int
	Catalog       *catalog.Catalog
	BaseInventory tools.InventoryData
	Thresholds    Thresholds
	Evidence      policy.EvidenceMode
	Models        Models
	Baseline      BaselineModels // C0
	Rand          io.Reader      // crypto/rand.Reader outside tests
	Keys          *Keys          // generated from Rand when nil
	EventsPath    string         // JSONL log; none when empty
	Hub           *events.Hub    // live events; none when nil
	HTTP          bool           // carry the handoff over HTTP on 127.0.0.1
	ToolTimeout   time.Duration
	RunTimeout    time.Duration
	Approver      interp.Approver // ground truth from the fixture when nil
}

// RunRecord is everything one run produced. Every metric is computed from
// it: the environment diff, the apply log, and the event log.
type RunRecord struct {
	Fixture      string              `json:"fixture"`
	Kind         string              `json:"kind"`
	Goal         string              `json:"goal,omitempty"`
	Style        string              `json:"style,omitempty"`
	Config       string              `json:"config"`
	Trial        int                 `json:"trial"`
	Impl         string              `json:"impl"`
	Models       map[string]string   `json:"models"`
	RunID        string              `json:"run_id"`
	Investigator *interp.RunResult   `json:"investigator,omitempty"`
	Responder    *interp.RunResult   `json:"responder,omitempty"`
	Baseline     *BaselineResult     `json:"baseline,omitempty"`
	Diff         []Change            `json:"diff"`
	ApplyLog     []tools.ApplyRecord `json:"apply_log"`
	Violations   []Violation         `json:"violations"`
	Measured     []Violation         `json:"measured"` // invariant 1 outcomes in configurations that do not enforce it
	Metrics      RunMetrics          `json:"metrics"`
	WallMs       float64             `json:"wall_ms"`
	Crash        string              `json:"crash,omitempty"`
	Events       []events.Event      `json:"-"`
}

// Valid reports whether the invariant checker found no violation.
func (r *RunRecord) Valid() bool { return len(r.Violations) == 0 }

func approverFor(fx *Fixture, clock value.Clock, principal string) interp.Approver {
	yes := changeSet(fx.GroundTruth.Approve)
	return interp.GroundTruthApprover{Principal: principal, Clock: clock, Decide: func(req interp.ApprovalRequest) bool {
		return yes[Change{Tool: req.Op.Tool, Action: req.Op.Action, Target: req.Target}.key()]
	}}
}

// Run executes one fixture under one configuration and checks invariants.
// A crash is recorded as a failed run, never dropped.
func Run(ctx context.Context, fx *Fixture, o Options) (rec *RunRecord) {
	wall := time.Now()
	rec = &RunRecord{Fixture: fx.ID, Kind: fx.Kind, Goal: fx.Goal, Style: fx.Style, Config: o.Config, Trial: o.Trial, Models: map[string]string{}}
	defer func() {
		if p := recover(); p != nil {
			rec.Crash = fmt.Sprintf("panic: %v", p)
		}
		rec.WallMs = float64(time.Since(wall).Microseconds()) / 1000
		rec.Metrics = ComputeMetrics(fx, rec)
	}()
	if o.RunTimeout <= 0 {
		o.RunTimeout = 2 * time.Minute
	}
	if o.ToolTimeout <= 0 {
		o.ToolTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.RunTimeout)
	defer cancel()
	clock := value.NewManualClock(fx.Now)
	spec, err := fx.EnvSpec(o.BaseInventory)
	if err != nil {
		rec.Crash = err.Error()
		return rec
	}
	env, err := tools.NewEnv(spec, clock)
	if err != nil {
		rec.Crash = err.Error()
		return rec
	}
	before := env.Snapshot()
	recorder := &events.Recorder{}
	sinks := []events.Sink{recorder}
	var writer *events.Writer
	if o.EventsPath != "" {
		if writer, err = events.NewWriter(o.EventsPath); err != nil {
			rec.Crash = err.Error()
			return rec
		}
		sinks = append(sinks, writer)
	}
	if o.Hub != nil {
		sinks = append(sinks, o.Hub)
	}
	log := events.NewLog(clock, sinks...)
	defer func() {
		rec.Events = recorder.Events()
		if writer != nil {
			if err := writer.Close(); err != nil && rec.Crash == "" {
				rec.Crash = err.Error()
			}
		}
	}()

	if o.Config == C0 {
		rec.Impl = o.Baseline.Impl
		rec.Models["baseline"] = o.Baseline.Impl
		rec.Baseline = runBaseline(ctx, fx, env, log, o)
	} else if err := runCitadel(ctx, fx, env, clock, log, o, rec); err != nil {
		rec.Crash = err.Error()
	}
	after := env.Snapshot()
	for _, c := range tools.Diff(before, after) {
		rec.Diff = append(rec.Diff, fromToolChange(c))
	}
	rec.ApplyLog = env.ApplyLog()
	emitEnvChanges(log, rec, recorder.Events())
	rec.Events = recorder.Events()
	rec.Violations, rec.Measured = CheckInvariants(fx, rec, env.Inventory())
	return rec
}

func runCitadel(ctx context.Context, fx *Fixture, env *tools.Env, clock *value.ManualClock, log *events.Log, o Options, rec *RunRecord) error {
	keys := o.Keys
	if keys == nil {
		var err error
		if keys, err = NewKeys(o.Rand, fx.Now); err != nil {
			return err
		}
	}
	orch, err := orchestrator.New(orchestrator.Config{Catalog: o.Catalog, Inventory: env.Inventory(), Signer: keys.Orchestrator,
		Clock: clock, Rand: o.Rand, PolicyVersion: PolicyVersion, SoftUntrustedPC: o.Thresholds.SoftUntrustedPC})
	if err != nil {
		return err
	}
	params, err := fx.ParamsJSON()
	if err != nil {
		return err
	}
	version := fx.Task.Version
	if version == 0 {
		version = 1
	}
	minted, err := orch.Mint(orchestrator.TaskRequest{Principal: fx.Task.Principal, Role: fx.Task.Role, Task: fx.Task.Task,
		Version: version, Params: params, Note: fx.Task.Note})
	if err != nil {
		return fmt.Errorf("orchestrator refused the fixture's task: %w", err)
	}
	rec.RunID = minted.Context.RunID
	engine, err := policy.NewEngine(policy.Config{PolicyVersions: []string{PolicyVersion}, Mode: o.Evidence,
		Thresholds: evidence.Thresholds{K: o.Thresholds.K, MinFlows: o.Thresholds.MinFlows}, LoginPath: "/login"})
	if err != nil {
		return err
	}
	approver := o.Approver
	if approver == nil {
		approver = approverFor(fx, clock, fx.Task.Principal)
	}
	mode := map[string]string{C1Instr: handoff.ModeC1Instr, C1Data: handoff.ModeC1Data, C2: handoff.ModeC2}[o.Config]
	if mode == "" {
		return fmt.Errorf("%w: configuration %q", value.ErrConfig, o.Config)
	}
	mem := handoff.NewMemTransport()
	var transport handoff.Transport = mem
	started := fx.Now.Add(-time.Minute)
	newAgent := func(name string, signer *signed.Signer) (*interp.Agent, error) {
		models := o.Models(name, o.Config)
		rec.Impl = models.Impl
		rec.Models[name] = models.Impl
		return interp.NewAgent(interp.AgentConfig{Name: name, ConfigName: o.Config, HandoffMode: mode, Static: StaticCaps(name),
			Catalog: o.Catalog, Registry: keys.Registry, PolicyVersions: []string{PolicyVersion}, Engine: engine, Env: env,
			Models: models, Approver: approver, Signer: signer, Transport: transport, Events: log, Clock: clock, Rand: o.Rand,
			StartedAt: started, IterationBudget: o.Thresholds.IterationBudget, ToolTimeout: o.ToolTimeout,
			HandoffLifetime: 2 * time.Minute, Trust: label.DefaultTrust()})
	}
	resp, err := newAgent(Responder, keys.Responder)
	if err != nil {
		return err
	}
	if o.HTTP {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		srv := &http.Server{Handler: handoff.HTTPHandler(resp.HandleHandoff), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
		go srv.Serve(ln)
		defer srv.Close()
		transport = &handoff.HTTPTransport{Client: &http.Client{Timeout: 10 * time.Second}, Peers: map[string]string{Responder: "http://" + ln.Addr().String()}}
	} else {
		mem.Register(Responder, resp.HandleHandoff)
	}
	inv, err := newAgent(Investigator, keys.Investigator)
	if err != nil {
		return err
	}
	ir := inv.StartRun(ctx, minted.Wire)
	rec.Investigator = &ir
	if ir.Outcome.Handoffs > 0 {
		rr, err := resp.Wait(ctx, rec.RunID)
		if err != nil {
			resp.Drain()
			return err
		}
		rec.Responder = &rr
	}
	resp.Drain()
	return nil
}

// emitEnvChanges writes one env_change event per diff entry, with how the
// runtime saw the matching attempt: a change whose attempt is Uncertain is
// "executed; runtime outcome unconfirmed".
func emitEnvChanges(log *events.Log, rec *RunRecord, evs []events.Event) {
	for _, c := range rec.Diff {
		outcome := "executed"
		for _, e := range evs {
			if e.Kind == events.KindAttempt && e.Attempt != nil && e.Attempt.Op.Tool == c.Tool && e.Attempt.Op.Action == c.Action &&
				e.Attempt.Target == c.Target && e.Attempt.State.String() == "uncertain" {
				outcome = "executed; runtime outcome unconfirmed"
			}
		}
		log.Emit(events.Event{Run: rec.RunID, Config: rec.Config, Agent: "environment", Kind: events.KindEnvChange,
			Change: &events.EnvChange{Tool: c.Tool, Action: c.Action, Target: c.Target, Outcome: outcome}})
	}
}

// Scripted returns the scripted stand-ins for every agent, with optional
// planner variants per agent.
func Scripted(variants map[string]string) Models {
	return func(agent, _ string) llm.Set {
		return llm.Set{Impl: llm.ImplScripted, Planner: scriptedPlanner(variants[agent]), Processor: scriptedProcessor(), Intake: scriptedIntake()}
	}
}
