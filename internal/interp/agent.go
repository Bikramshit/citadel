package interp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/events"
	"citadel/internal/handoff"
	"citadel/internal/label"
	"citadel/internal/llm"
	"citadel/internal/plan"
	"citadel/internal/policy"
	"citadel/internal/runstate"
	"citadel/internal/signed"
	"citadel/internal/tools"
	"citadel/internal/value"
)

// AgentConfig configures one agent process: the Investigator or the
// Responder.
type AgentConfig struct {
	Name            string
	ConfigName      string // the evaluation configuration, for events
	HandoffMode     string // C2, C1-instr, or C1-data
	Static          []authz.Cap
	Catalog         *catalog.Catalog
	Registry        *signed.Registry
	PolicyVersions  []string
	Engine          *policy.Engine
	Env             *tools.Env
	Models          llm.Set
	Approver        Approver
	Signer          *signed.Signer // signs this agent's handoffs; nil if it sends none
	Transport       handoff.Transport
	Events          events.Sink
	Clock           value.Clock
	Rand            io.Reader
	StartedAt       time.Time // the restart watermark
	IterationBudget int
	ToolTimeout     time.Duration
	HandoffLifetime time.Duration
	Trust           label.TrustTable
}

// RunResult is one agent's view of a finished run.
type RunResult struct {
	RunID    string       `json:"run_id"`
	Agent    string       `json:"agent"`
	Outcome  Outcome      `json:"outcome"`
	Planner  llm.CallInfo `json:"planner"`
	Intake   llm.CallInfo `json:"intake,omitempty"`
	Started  time.Time    `json:"started"`
	Finished time.Time    `json:"finished"`
	Stats    RunStats     `json:"stats"`
	Eff      []authz.Cap  `json:"effective"`
}

// RunStats are the run-state counters at the end of a run.
type RunStats struct {
	MaxSensitive  int `json:"max_sensitive"`
	Sensitive     int `json:"sensitive"`
	Handoffs      int `json:"handoffs"`
	UsedApprovals int `json:"used_approvals"`
	Attempts      int `json:"attempts"`
}

// Agent is one agent's runtime: its run table, replay table, receiver,
// sender, and interpreter.
type Agent struct {
	cfg      AgentConfig
	runs     *runstate.Runs
	receiver *handoff.Receiver
	interp   *Interp

	mu      sync.Mutex
	done    map[string]chan struct{}
	results map[string]RunResult
	pending sync.WaitGroup
}

// NewAgent validates cfg and builds the runtime.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.Name == "" || cfg.Catalog == nil || cfg.Registry == nil || cfg.Engine == nil || cfg.Env == nil ||
		cfg.Models.Planner == nil || cfg.Models.Processor == nil || cfg.Approver == nil || cfg.Events == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("%w: agent %q configuration incomplete", value.ErrConfig, cfg.Name)
	}
	if cfg.HandoffMode == handoff.ModeC1Instr && cfg.Models.Intake == nil {
		return nil, fmt.Errorf("%w: C1-instr needs an intake", value.ErrConfig)
	}
	a := &Agent{cfg: cfg, runs: runstate.NewRuns(cfg.Name, cfg.StartedAt), done: map[string]chan struct{}{}, results: map[string]RunResult{}}
	rcv, err := handoff.NewReceiver(handoff.ReceiverConfig{Self: cfg.Name, Static: cfg.Static, Registry: cfg.Registry, Runs: a.runs,
		Replay: runstate.NewReplayTable(), Catalog: cfg.Catalog, Hosts: cfg.Env.Inventory(), PolicyVersions: cfg.PolicyVersions,
		Mode: cfg.HandoffMode, Events: cfg.Events, Clock: cfg.Clock})
	if err != nil {
		return nil, err
	}
	a.receiver = rcv
	var sender HandoffSender
	if cfg.Signer != nil {
		s, err := handoff.NewSender(handoff.SenderConfig{Self: cfg.Name, Signer: cfg.Signer, Clock: cfg.Clock, Rand: cfg.Rand,
			Transport: cfg.Transport, Lifetime: cfg.HandoffLifetime, Retransmits: 2, Events: cfg.Events, ConfigName: cfg.ConfigName,
			ReceiverOps: func(to, task string, version int, params map[string]json.RawMessage) ([]authz.Cap, error) {
				t, ok := cfg.Catalog.Lookup(task, version)
				if !ok {
					return nil, fmt.Errorf("%w: %s", value.ErrUnknownTask, task)
				}
				return t.Ops(to, params)
			}})
		if err != nil {
			return nil, err
		}
		sender = s
	}
	in, err := New(Config{Agent: cfg.Name, ConfigName: cfg.ConfigName, HandoffMode: cfg.HandoffMode, IterationBudget: cfg.IterationBudget,
		ToolTimeout: cfg.ToolTimeout, Trust: cfg.Trust},
		Deps{Engine: cfg.Engine, Tools: cfg.Env.ToolFor, Inv: cfg.Env.Inventory(), Evidence: cfg.Env.Evidence(),
			Processor: cfg.Models.Processor, Approver: cfg.Approver, Sender: sender, Events: cfg.Events, Clock: cfg.Clock})
	if err != nil {
		return nil, err
	}
	a.interp = in
	return a, nil
}

// Name returns the agent's ID.
func (a *Agent) Name() string { return a.cfg.Name }

// Runs returns the agent's run table, for tests and the invariant checker.
func (a *Agent) Runs() *runstate.Runs { return a.runs }

func (a *Agent) channel(runID string) chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, ok := a.done[runID]
	if !ok {
		ch = make(chan struct{})
		a.done[runID] = ch
	}
	return ch
}

// Wait returns the result of runID once the run has finished in this agent.
func (a *Agent) Wait(ctx context.Context, runID string) (RunResult, error) {
	select {
	case <-a.channel(runID):
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.results[runID], nil
	case <-ctx.Done():
		return RunResult{}, fmt.Errorf("agent %s: run %s did not finish: %w", a.cfg.Name, runID, ctx.Err())
	}
}

// Drain waits for every run this agent started in the background.
func (a *Agent) Drain() { a.pending.Wait() }

func (a *Agent) finish(r RunResult, rs *runstate.RunState) RunResult {
	r.Finished = a.cfg.Clock.Now()
	if rs != nil {
		st := rs.Stats()
		r.Stats = RunStats{MaxSensitive: st.MaxSensitive, Sensitive: st.Sensitive, UsedApprovals: st.UsedApprovals, Attempts: len(st.Attempts) + len(st.Reads)}
		for _, n := range st.Handoffs {
			r.Stats.Handoffs += n
		}
	}
	a.cfg.Events.Emit(events.Event{Run: r.RunID, Config: a.cfg.ConfigName, Agent: a.cfg.Name, Kind: events.KindRunEnd,
		Code: r.Outcome.AbortCode, Detail: fmt.Sprintf("completed=%t calls=%d executed=%d denied=%d escalated=%d",
			r.Outcome.Completed, r.Outcome.Calls, r.Outcome.Executed, r.Outcome.Denied, r.Outcome.Escalated),
		Extra: map[string]float64{"duration_ms": float64(r.Finished.Sub(r.Started).Microseconds()) / 1000}})
	ch := a.channel(r.RunID)
	a.mu.Lock()
	if _, seen := a.results[r.RunID]; !seen {
		a.results[r.RunID] = r
		close(ch)
	}
	a.mu.Unlock()
	return r
}

func (a *Agent) abortRun(runID string, started time.Time, code value.Code, err error) RunResult {
	a.cfg.Events.Emit(events.Event{Run: runID, Config: a.cfg.ConfigName, Agent: a.cfg.Name, Kind: events.KindRunAbort,
		Code: string(code), Detail: value.Truncate(err.Error())})
	return a.finish(RunResult{RunID: runID, Agent: a.cfg.Name, Started: started,
		Outcome: Outcome{AbortCode: string(code), AbortDetail: err.Error()}}, nil)
}

// StartRun is the first agent's entry point: it verifies the
// orchestrator-signed context, binds it to local run state, computes the
// effective capabilities, asks the planner for a plan, and executes it.
func (a *Agent) StartRun(ctx context.Context, w signed.Wire) RunResult {
	started := a.cfg.Clock.Now()
	ac, h, err := handoff.VerifyAuthCtx(a.cfg.Registry, w, a.cfg.PolicyVersions, started)
	if err != nil {
		return a.abortRun("", started, value.ErrAuthCtx, err)
	}
	rs, err := a.runs.Activate(ac, h, started)
	if err != nil {
		code := value.Code(value.CodeOf(err))
		return a.abortRun(ac.RunID, started, code, err)
	}
	task, ok := a.cfg.Catalog.Lookup(ac.Task, ac.TaskVersion)
	if !ok {
		rs.Close()
		return a.abortRun(ac.RunID, started, value.ErrUnknownTask, fmt.Errorf("task %s v%d", ac.Task, ac.TaskVersion))
	}
	ops, err := task.Ops(a.cfg.Name, ac.Params)
	if err != nil {
		rs.Close()
		return a.abortRun(ac.RunID, started, value.ErrAuthCtx, err)
	}
	eff := authz.Effective(a.cfg.Static, ac.Grants[a.cfg.Name], ops, nil)
	return a.execute(ctx, RunInput{RS: rs, Ctx: ac, CtxHash: h, CtxWire: w, Task: task, Eff: eff}, started, llm.CallInfo{})
}

// HandleHandoff is the receiving agent's entry point. A verified, committed
// envelope starts the agent's run in the background; the response goes back
// to the sender at once.
func (a *Agent) HandleHandoff(ctx context.Context, body []byte) handoff.Response {
	var installed map[string]value.Value
	resp, st := a.receiver.Accept(ctx, body, func(s *handoff.Staged) { installed = s.Values })
	if st == nil {
		return resp
	}
	a.channel(st.Ctx.RunID)
	a.pending.Add(1)
	go func() {
		defer a.pending.Done()
		a.received(context.WithoutCancel(ctx), st, installed)
	}()
	return resp
}

func (a *Agent) received(ctx context.Context, st *handoff.Staged, values map[string]value.Value) RunResult {
	started := a.cfg.Clock.Now()
	input := RunInput{RS: st.Run, Ctx: st.Ctx, CtxHash: st.CtxHash, CtxWire: st.CtxWire, Task: st.Task, Eff: st.Eff, Data: values}
	var intake llm.CallInfo
	if a.cfg.HandoffMode == handoff.ModeC1Instr {
		// The comparison configuration that launders on purpose: the
		// runtime accepts a peer's message as the analyst's request and
		// labels what its intake reads from it TaskParam.
		report, _ := values[handoff.ReportData].AsString()
		raw, info, err := a.cfg.Models.Intake.Intake(ctx, llm.IntakeRequest{Report: report, Data: []llm.DataDecl{
			{Name: "ips", Type: "list<ipv4>"}, {Name: "accounts", Type: "list<account_id>"}}})
		intake = info
		if err != nil {
			st.Run.Close()
			return a.abortRun(st.Ctx.RunID, started, value.ErrProcessor, err)
		}
		v, err := llm.DecodeOutput(llm.SchemaIOCList, raw, label.New(label.TaskParam("c1_intake")))
		if err != nil {
			st.Run.Close()
			return a.abortRun(st.Ctx.RunID, started, value.ErrDecode, err)
		}
		ips, _ := v.FieldValue("ips")
		accts, _ := v.FieldValue("accounts")
		input.Data = map[string]value.Value{"ips": ips, "accounts": accts}
	}
	r := a.execute(ctx, input, started, intake)
	return r
}

func (a *Agent) execute(ctx context.Context, input RunInput, started time.Time, intake llm.CallInfo) RunResult {
	a.cfg.Events.Emit(events.Event{Run: input.Ctx.RunID, Config: a.cfg.ConfigName, Agent: a.cfg.Name, Kind: events.KindRunStart,
		Detail: capsString(input.Eff)})
	pin := PlannerInput(a.cfg.Name, input.Ctx, input.Task, input.Eff, input.Data, a.cfg.HandoffMode)
	p, info, err := a.cfg.Models.Planner.Plan(ctx, pin)
	info.PromptHash = llm.BuildPlannerPrompt(pin).Hash()
	if err != nil {
		input.RS.Close()
		r := a.abortRun(input.Ctx.RunID, started, value.ErrPlanInvalid, err)
		return r
	}
	out := a.interp.Run(ctx, input, p)
	return a.finish(RunResult{RunID: input.Ctx.RunID, Agent: a.cfg.Name, Outcome: out, Planner: info, Intake: intake, Started: started, Eff: input.Eff}, input.RS)
}

// Plan returns the plan the configured planner would write for a run, for
// tests that check planner input.
func (a *Agent) Plan(ctx context.Context, in llm.PlannerInput) (plan.Plan, llm.CallInfo, error) {
	return a.cfg.Models.Planner.Plan(ctx, in)
}

func capsString(caps []authz.Cap) string {
	s := ""
	for i, c := range caps {
		if i > 0 {
			s += " "
		}
		s += c.String()
	}
	return s
}
