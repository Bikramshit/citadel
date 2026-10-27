// Package interp is Citadel's labeling interpreter and agent runtime. It
// executes plans in the restricted plan language with nine semantics: the
// static check first; aborts on branches over untrusted values; loops longer
// than the iteration budget abort before the first iteration; every
// state-changing call goes Decide, then Admit under the run lock, then the
// tool with its idempotency key; Deny skips the call; Escalate pauses for
// approval, and a timeout is a Deny; errors abort; processor output is decoded
// strictly and labeled QLLM plus its inputs' sources; values leave a process
// only through a handoff or the event log. The executor here is the only
// caller of tools.
package interp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/events"
	"citadel/internal/evidence"
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

// ApprovalRequest describes an escalated call for the approver: the bound
// call, every argument's sources, the evidence counts, and the rule that
// escalated.
type ApprovalRequest struct {
	RunID    string
	Agent    string
	Key      policy.ApprovalKey
	Op       authz.Op
	Target   string
	Args     map[string]string
	Sources  map[string][]string
	Evidence *evidence.Counts
	Decision policy.Decision
	// RequestedAt and ExpiresAt are on the run's clock.
	RequestedAt time.Time
	ExpiresAt   time.Time
}

// Approver obtains the principal's answer. It returns once it has called
// rs.Approve or given up; the interpreter then re-runs Admit, which consumes
// a granted approval or denies.
type Approver interface {
	Await(ctx context.Context, rs *runstate.RunState, req ApprovalRequest) error
}

// HandoffSender sends handoffs for the interpreter.
type HandoffSender interface {
	Send(ctx context.Context, req handoff.Request) (handoff.Sent, error)
}

// Config configures an Interp.
type Config struct {
	Agent           string
	ConfigName      string // C1-instr | C1-data | C2, for events
	HandoffMode     string
	IterationBudget int
	ToolTimeout     time.Duration
	Trust           label.TrustTable
}

// Deps are an Interp's collaborators.
type Deps struct {
	Engine    *policy.Engine
	Tools     func(authz.Op) (tools.Tool, bool)
	Inv       policy.Inventory
	Evidence  *evidence.Store
	Processor llm.Processor
	Approver  Approver
	Sender    HandoffSender // nil for an agent that makes no handoffs
	Events    events.Sink
	Clock     value.Clock
}

// Interp executes plans for one agent.
type Interp struct {
	cfg  Config
	deps Deps
}

// New validates the configuration.
func New(cfg Config, deps Deps) (*Interp, error) {
	if cfg.Agent == "" || cfg.IterationBudget < 1 || cfg.ToolTimeout <= 0 {
		return nil, fmt.Errorf("%w: interpreter needs an agent, an iteration budget, and a tool timeout", value.ErrConfig)
	}
	if deps.Engine == nil || deps.Tools == nil || deps.Inv == nil || deps.Processor == nil || deps.Approver == nil || deps.Events == nil || deps.Clock == nil {
		return nil, fmt.Errorf("%w: interpreter dependencies missing", value.ErrConfig)
	}
	return &Interp{cfg: cfg, deps: deps}, nil
}

// RunInput is one run's verified context and imported data.
type RunInput struct {
	RS      *runstate.RunState
	Ctx     *authz.AuthContext
	CtxHash [32]byte
	CtxWire signed.Wire
	Task    *catalog.Task
	Eff     []authz.Cap
	Data    map[string]value.Value // handles imported from a handoff
}

// Outcome summarizes a run.
type Outcome struct {
	Completed   bool           `json:"completed"`
	AbortCode   string         `json:"abort_code,omitempty"`
	AbortDetail string         `json:"abort_detail,omitempty"`
	Calls       int            `json:"calls"`
	Denied      int            `json:"denied"`
	Escalated   int            `json:"escalated"`
	Executed    int            `json:"executed"`
	Handoffs    int            `json:"handoffs"`
	Processor   []llm.CallInfo `json:"processor,omitempty"`
}

type abortError struct {
	code   string
	detail string
}

// Error returns the abort's code and detail.
func (e *abortError) Error() string { return e.code + ": " + e.detail }

func abort(code value.Code, format string, args ...any) error {
	return &abortError{code: string(code), detail: fmt.Sprintf(format, args...)}
}

func abortFrom(err error, fallback value.Code) error {
	var ae *abortError
	if errors.As(err, &ae) {
		return ae
	}
	code := value.CodeOf(err)
	if code == "" {
		code = string(fallback)
	}
	return &abortError{code: code, detail: value.Truncate(err.Error())}
}

type slot struct {
	v      value.Value
	denied bool // bound by a call that was denied: any use aborts
}

type exec struct {
	in      *Interp
	ctx     context.Context
	input   RunInput
	params  map[string]value.Value
	scopes  []map[string]slot
	pc      []label.Label
	ids     int
	deps    []string
	out     *Outcome
	baseLbl label.Label
}

// StaticEnv builds the static checker's environment for a run.
func (in *Interp) StaticEnv(input RunInput) plan.Env {
	data := map[string]plan.DataBinding{}
	for name, v := range input.Data {
		data[name] = plan.DataBinding{Type: v.Type(), Untrusted: !v.Label().Trusted(in.cfg.Trust)}
	}
	return plan.Env{Agent: in.cfg.Agent, Eff: input.Eff, Task: input.Task, Ctx: input.Ctx, Data: data,
		Schemas: llm.Schemas(), HandoffSchema: handoff.DataSchema(input.Task, in.cfg.HandoffMode), Hosts: in.deps.Inv}
}

func (in *Interp) emit(input RunInput, e events.Event) {
	e.Run, e.Config, e.Agent = input.Ctx.RunID, in.cfg.ConfigName, in.cfg.Agent
	in.deps.Events.Emit(e)
}

// Run statically checks p, then executes it. The run is closed when the plan
// finishes or aborts. Effects already executed stay and are recorded.
func (in *Interp) Run(ctx context.Context, input RunInput, p plan.Plan) Outcome {
	out := &Outcome{}
	defer input.RS.Close()
	if err := plan.StaticCheck(p, in.StaticEnv(input)); err != nil {
		var rej *plan.RejectError
		var ds []policy.Decision
		if errors.As(err, &rej) {
			for _, v := range rej.Violations {
				ds = append(ds, policy.Decision{Verdict: policy.Deny, Rule: v.Rule, Group: ruleGroup(v.Rule), Reason: v.Path + ": " + v.Reason})
			}
		}
		in.emit(input, events.Event{Kind: events.KindPlanRejected, Code: string(value.ErrPlanRejected),
			Detail: value.Truncate(err.Error()), Decisions: ds})
		out.AbortCode, out.AbortDetail = string(value.ErrPlanRejected), err.Error()
		return *out
	}
	params, err := input.Task.ParamValues(input.Ctx.Params, in.deps.Inv)
	if err != nil {
		in.emit(input, events.Event{Kind: events.KindRunAbort, Code: string(value.ErrAuthCtx), Detail: err.Error()})
		out.AbortCode, out.AbortDetail = string(value.ErrAuthCtx), err.Error()
		return *out
	}
	x := &exec{in: in, ctx: ctx, input: input, params: params, scopes: []map[string]slot{{}}, out: out,
		baseLbl: label.New(label.Runtime())}
	for _, name := range slices.Sorted(maps.Keys(input.Data)) {
		v := x.bind(input.Data[name], nil)
		x.scopes[0][name] = slot{v: v}
	}
	if err := x.stmts(p.Steps); err != nil {
		ae := abortFrom(err, value.ErrPlanInvalid).(*abortError)
		in.emit(input, events.Event{Kind: events.KindRunAbort, Code: ae.code, Detail: ae.detail})
		out.AbortCode, out.AbortDetail = ae.code, ae.detail
		return *out
	}
	out.Completed = true
	return *out
}

func (x *exec) pcLabel() label.Label { return label.Join(append([]label.Label{x.baseLbl}, x.pc...)...) }

// bind assigns a value ID and records it.
func (x *exec) bind(v value.Value, deps []string) value.Value {
	x.ids++
	v = v.WithID(fmt.Sprintf("%s/v%d", x.in.cfg.Agent, x.ids))
	x.in.emit(x.input, events.Event{Kind: events.KindValue, ValueID: v.ID(), ValueType: v.Type().String(), Deps: deps,
		Sources: v.Label().Strings(), Trusted: v.Label().Trusted(x.in.cfg.Trust), PCTrusted: x.pcLabel().Trusted(x.in.cfg.Trust)})
	return v
}

func (x *exec) lookup(name string) (slot, bool) {
	for i := len(x.scopes) - 1; i >= 0; i-- {
		if s, ok := x.scopes[i][name]; ok {
			return s, true
		}
	}
	return slot{}, false
}

func (x *exec) stmts(ss []plan.Stmt) error {
	for i := range ss {
		if err := x.ctx.Err(); err != nil {
			return abort(value.ErrProcessor, "run cancelled: %v", err)
		}
		if err := x.stmt(&ss[i]); err != nil {
			return err
		}
	}
	return nil
}

func (x *exec) scoped(f func() error) error {
	x.scopes = append(x.scopes, map[string]slot{})
	defer func() { x.scopes = x.scopes[:len(x.scopes)-1] }()
	return f()
}

func (x *exec) stmt(s *plan.Stmt) error {
	switch s.Op {
	case "let":
		x.deps = nil
		v, denied, err := x.expr(s.Expr, nil)
		if err != nil {
			return err
		}
		if denied {
			x.scopes[len(x.scopes)-1][s.Var] = slot{denied: true}
			return nil
		}
		x.scopes[len(x.scopes)-1][s.Var] = slot{v: x.bind(v, x.deps)}
	case "call":
		x.deps = nil
		_, _, err := x.expr(s.Expr, nil)
		return err
	case "for_each":
		x.deps = nil
		over, denied, err := x.expr(s.Over, nil)
		if err != nil {
			return err
		}
		if denied {
			return abort(value.ErrUndefinedValue, "loop over the result of a denied call")
		}
		if over.Kind() != value.KindList {
			return abort(value.ErrType, "for_each over %s", over.Type())
		}
		if over.Count() > x.in.cfg.IterationBudget {
			return abort(value.ErrIterationBudget, "list of %d values exceeds the iteration budget %d", over.Count(), x.in.cfg.IterationBudget)
		}
		x.pc = append(x.pc, over.Label())
		defer func() { x.pc = x.pc[:len(x.pc)-1] }()
		for _, e := range over.Elems() {
			if err := x.scoped(func() error {
				x.scopes[len(x.scopes)-1][s.Var] = slot{v: e}
				return x.stmts(s.Body)
			}); err != nil {
				return err
			}
		}
	case "if":
		ok, l, err := x.cond(s.Cond)
		if err != nil {
			return err
		}
		if !label.Join(l, x.pcLabel()).Trusted(x.in.cfg.Trust) {
			return abort(value.ErrUntrustedBranch, "condition depends on %s", strings.Join(l.Strings(), ","))
		}
		x.pc = append(x.pc, l)
		defer func() { x.pc = x.pc[:len(x.pc)-1] }()
		body := s.Body
		if !ok {
			body = s.Else
		}
		return x.scoped(func() error { return x.stmts(body) })
	case "handoff":
		return x.handoff(s.Handoff)
	default:
		return abort(value.ErrPlanRejected, "unknown statement %q", value.Truncate(s.Op))
	}
	return nil
}

func (x *exec) cond(c *plan.Cond) (bool, label.Label, error) {
	left, denied, err := x.expr(&c.Left, nil)
	if err != nil {
		return false, label.Label{}, err
	}
	if denied {
		return false, label.Label{}, abort(value.ErrUndefinedValue, "condition on the result of a denied call")
	}
	switch c.Op {
	case "not_empty":
		return left.Count() > 0, left.Label(), nil
	case "eq", "in":
		want := left.Type()
		if c.Op == "in" {
			want = value.ListOf(left.Type())
		}
		right, denied, err := x.expr(c.Right, &want)
		if err != nil {
			return false, label.Label{}, err
		}
		if denied {
			return false, label.Label{}, abort(value.ErrUndefinedValue, "condition on the result of a denied call")
		}
		l := label.Join(left.Label(), right.Label())
		if c.Op == "eq" {
			return left.Equal(right), l, nil
		}
		return slices.ContainsFunc(right.Elems(), func(e value.Value) bool { return e.Equal(left) }), l, nil
	}
	return false, label.Label{}, abort(value.ErrPlanRejected, "unknown condition %q", value.Truncate(c.Op))
}

// expr evaluates an expression. denied is true when the expression is a call
// that policy denied: it has no value.
func (x *exec) expr(e *plan.Expr, expected *value.Type) (value.Value, bool, error) {
	switch e.Op {
	case "lit":
		if expected == nil {
			return value.Value{}, false, abort(value.ErrType, "literal with no type")
		}
		v, err := value.FromJSON(e.Lit, *expected, x.in.deps.Inv, label.New(label.PlannerLiteral(x.in.cfg.Agent)))
		if err != nil {
			return value.Value{}, false, abortFrom(err, value.ErrType)
		}
		return v, false, nil
	case "ref":
		s, ok := x.lookup(e.Ref)
		if !ok || s.denied {
			return value.Value{}, false, abort(value.ErrUndefinedValue, "%q has no value", value.Truncate(e.Ref))
		}
		if s.v.ID() != "" {
			x.deps = append(x.deps, s.v.ID())
		}
		return s.v, false, nil
	case "param":
		v, ok := x.params[e.Param]
		if !ok {
			return value.Value{}, false, abort(value.ErrUndefinedValue, "parameter %q", value.Truncate(e.Param))
		}
		return v, false, nil
	case "field":
		of, denied, err := x.expr(e.Of, nil)
		if err != nil || denied {
			return value.Value{}, denied, err
		}
		f, ok := of.FieldValue(e.Field)
		if !ok {
			return value.Value{}, false, abort(value.ErrType, "%s has no field %q", of.Type(), value.Truncate(e.Field))
		}
		return f, false, nil
	case "call":
		return x.call(e)
	case "extract":
		return x.extract(e)
	}
	return value.Value{}, false, abort(value.ErrPlanRejected, "unknown expression %q", value.Truncate(e.Op))
}

func (x *exec) extract(e *plan.Expr) (value.Value, bool, error) {
	var inputs []string
	labels := []label.Label{label.New(label.QLLM(x.in.cfg.Agent)), x.pcLabel()}
	for i := range e.Inputs {
		v, denied, err := x.expr(&e.Inputs[i], nil)
		if err != nil {
			return value.Value{}, false, err
		}
		if denied {
			return value.Value{}, false, abort(value.ErrUndefinedValue, "extract input from a denied call")
		}
		inputs = append(inputs, render(v))
		labels = append(labels, v.Label())
	}
	raw, info, err := x.in.deps.Processor.Extract(x.ctx, llm.ExtractRequest{Agent: x.in.cfg.Agent, Schema: e.Schema, Ask: e.Ask, Inputs: inputs})
	x.out.Processor = append(x.out.Processor, info)
	if err != nil {
		return value.Value{}, false, abortFrom(err, value.ErrProcessor)
	}
	// Processor output is never trusted, whatever its inputs were.
	v, err := llm.DecodeOutput(e.Schema, raw, label.Join(labels...))
	if err != nil {
		return value.Value{}, false, abortFrom(err, value.ErrDecode)
	}
	return v, false, nil
}

// render turns a value into the text a processor reads.
func render(v value.Value) string {
	switch v.Kind() {
	case value.KindList:
		lines := make([]string, 0, v.Count())
		for _, e := range v.Elems() {
			lines = append(lines, render(e))
		}
		return strings.Join(lines, "\n")
	case value.KindText:
		s, _ := v.AsString()
		return s
	}
	return v.Canonical()
}

func (x *exec) evalArgs(spec authz.ToolSpec, e *plan.Expr) (map[string]value.Value, error) {
	args := map[string]value.Value{}
	for _, a := range spec.Args {
		ae, ok := e.Args[a.Name]
		if !ok {
			return nil, abort(value.ErrType, "%s needs %q", spec.Op, a.Name)
		}
		var v value.Value
		var err error
		var denied bool
		if ae.Op == "lit" {
			err = abort(value.ErrType, "literal %s is not a valid %s", value.Truncate(string(ae.Lit)), a.Types[0])
			for _, t := range a.Types {
				if v, denied, err = x.expr(&ae, &t); err == nil {
					break
				}
			}
		} else {
			v, denied, err = x.expr(&ae, nil)
		}
		if err != nil {
			return nil, err
		}
		if denied {
			return nil, abort(value.ErrUndefinedValue, "argument %q from a denied call", a.Name)
		}
		if !a.Accepts(v.Type()) {
			return nil, abort(value.ErrType, "%s.%s takes %s, got %s", spec.Op, a.Name, a.Types[0], v.Type())
		}
		args[a.Name] = v
	}
	if len(e.Args) != len(spec.Args) {
		return nil, abort(value.ErrType, "%s takes %d arguments", spec.Op, len(spec.Args))
	}
	return args, nil
}

func sourcesOf(args map[string]value.Value) map[string][]string {
	out := map[string][]string{}
	for k, v := range args {
		out[k] = v.Label().Strings()
	}
	return out
}

func canonicalArgs(args map[string]value.Value) map[string]string {
	out := map[string]string{}
	for k, v := range args {
		out[k] = v.Canonical()
	}
	return out
}

// call runs one tool call through Decide, Admit, and the executor.
func (x *exec) call(e *plan.Expr) (value.Value, bool, error) {
	op := authz.Op{Tool: e.Tool, Action: e.Action}
	spec, ok := authz.Spec(op)
	if !ok {
		return value.Value{}, false, abort(value.ErrPlanRejected, "%s is not a tool", value.Truncate(op.String()))
	}
	args, err := x.evalArgs(spec, e)
	if err != nil {
		return value.Value{}, false, err
	}
	pc := x.pcLabel()
	in := x.input
	c := &policy.CallCtx{RunID: in.Ctx.RunID, Agent: x.in.cfg.Agent, Op: op, Args: args, PC: pc, Eff: in.Eff,
		Ctx: in.Ctx, CtxHash: in.CtxHash, CtxVerified: true, Task: in.Task, Inv: x.in.deps.Inv,
		Evidence: x.in.deps.Evidence, Trust: x.in.cfg.Trust, Now: x.in.deps.Clock.Now()}
	target, tsrc := "", []string(nil)
	if ta := spec.TargetArg(); ta != "" {
		t := args[ta]
		c.TargetArg, c.Target = ta, &t
		target, tsrc = t.Canonical(), t.Label().Strings()
	} else if h, ok := args["host"]; ok {
		target, tsrc = h.Canonical(), h.Label().Strings()
	}
	x.out.Calls++
	ev := events.Event{Op: &op, Target: target, Sources: tsrc, PCTrusted: pc.Trusted(x.in.cfg.Trust), Deps: slices.Clone(x.deps)}
	if c.Target != nil {
		ev.Trusted = c.Target.Label().Trusted(x.in.cfg.Trust)
	}
	call := ev
	call.Kind = events.KindCall
	x.in.emit(in, call)

	final, all := x.in.deps.Engine.Decide(c)
	evid := final.Evidence
	for _, d := range all {
		if d.Evidence != nil {
			evid = d.Evidence
		}
	}
	a, d := in.RS.Admit(c, final, x.in.deps.Clock.Now())
	if d.Rule != final.Rule || d.Verdict != final.Verdict {
		all = append(all, d)
	}
	if a == nil && d.Verdict == policy.Escalate {
		x.out.Escalated++
		a, d, all = x.escalate(c, final, d, all, args, evid)
	}
	decision := ev
	decision.Kind, decision.Evidence = events.KindDecision, evid
	decision.Decisions = append(all, d)
	x.in.emit(in, decision)
	if a == nil {
		x.out.Denied++
		return value.Value{}, true, nil
	}
	return x.run(c, spec, a, args)
}

// escalate requests approval, waits for the approver, and re-runs Admit,
// which consumes a granted approval. Anything short of a granted approval
// ends in Deny.
func (x *exec) escalate(c *policy.CallCtx, final, d policy.Decision, all []policy.Decision, args map[string]value.Value, evid *evidence.Counts) (*runstate.Attempt, policy.Decision, []policy.Decision) {
	in := x.input
	k := policy.KeyFor(c)
	requested := x.in.deps.Clock.Now()
	ap := in.RS.RequestApproval(k, requested)
	info := &events.Approval{Key: k, State: ap.State.String(), ExpiresAt: ap.ExpiresAt, Args: canonicalArgs(args),
		Sources: sourcesOf(args), Rule: d.Rule, Reason: d.Reason}
	target, tsrc := "", []string(nil)
	if c.Target != nil {
		target, tsrc = c.Target.Canonical(), c.Target.Label().Strings()
	}
	x.in.emit(in, events.Event{Kind: events.KindApprovalRequest, Op: &c.Op, Target: target, Sources: tsrc, Approval: info, Evidence: evid})
	actx, cancel := context.WithCancel(x.ctx)
	err := x.in.deps.Approver.Await(actx, in.RS, ApprovalRequest{RunID: in.Ctx.RunID, Agent: x.in.cfg.Agent, Key: k, Op: c.Op,
		Target: target, Args: canonicalArgs(args), Sources: sourcesOf(args), Evidence: evid, Decision: d, RequestedAt: requested, ExpiresAt: ap.ExpiresAt})
	cancel()
	got, _ := in.RS.Approval(k)
	answer := *info
	answer.State, answer.Approver = got.State.String(), got.Approver
	if err != nil {
		answer.Reason = value.Truncate(err.Error())
	}
	x.in.emit(in, events.Event{Kind: events.KindApproval, Op: &c.Op, Target: target, Approval: &answer})
	a, d2 := in.RS.Admit(c, final, x.in.deps.Clock.Now())
	if a != nil {
		return a, d2, append(all, d2)
	}
	if d2.Verdict == policy.Escalate {
		d2 = policy.Decision{Verdict: policy.Deny, Rule: d.Rule, Group: d.Group, Reason: "escalation not approved (" + got.State.String() + "): a timeout or refusal is a Deny"}
	}
	return nil, d2, append(all, d2)
}

// run executes an admitted call with its idempotency key and turns the result
// into a labeled value.
func (x *exec) run(c *policy.CallCtx, spec authz.ToolSpec, a *runstate.Attempt, args map[string]value.Value) (value.Value, bool, error) {
	in := x.input
	t, ok := x.in.deps.Tools(c.Op)
	if !ok {
		in.RS.Settle(a, runstate.Failed, false, "no such tool", x.in.deps.Clock.Now())
		x.emitAttempt(in.RS, a)
		return value.Value{}, false, abort(value.ErrToolFailed, "no tool for %s", c.Op)
	}
	x.emitAttempt(in.RS, a)
	res, err := x.execute(in.RS, a, t, tools.Args(args))
	x.emitAttempt(in.RS, a)
	if err != nil {
		return value.Value{}, false, err
	}
	x.out.Executed++
	labels := []label.Label{label.New(label.Tool(c.Op.String())), c.PC}
	for _, v := range args {
		labels = append(labels, v.Label())
	}
	l := label.Join(labels...)
	switch {
	case spec.StateChanging:
		return value.Unit(l), false, nil
	case c.Op == authz.Op{Tool: "logs", Action: "read"}:
		recs := make([]value.Value, 0, len(res.Records))
		for _, r := range res.Records {
			recs = append(recs, value.Record(r, l))
		}
		v, err := value.List(value.Scalar(value.KindRecord), recs, l)
		return v, false, abortFromOrNil(err)
	default:
		key, _ := args["key"].AsString()
		t := spec.OutputByKey[key]
		elems := make([]value.Value, 0, len(res.Items))
		for _, s := range res.Items {
			e, err := value.FromString(s, *t.Elem, nil, l)
			if err != nil {
				return value.Value{}, false, abortFrom(err, value.ErrType)
			}
			elems = append(elems, e)
		}
		v, err := value.List(*t.Elem, elems, l)
		return v, false, abortFromOrNil(err)
	}
}

func abortFromOrNil(err error) error {
	if err == nil {
		return nil
	}
	return abortFrom(err, value.ErrType)
}

// execute calls the tool once. A definite rejection settles Failed. A
// timeout or lost response is reconciled by the read-only Lookup and is never
// re-applied: Succeeded if the key was applied, Failed if it was never seen,
// Uncertain if the lookup also fails. Only Succeeded continues the run.
func (x *exec) execute(rs *runstate.RunState, a *runstate.Attempt, t tools.Tool, args tools.Args) (tools.Result, error) {
	ctx, cancel := context.WithTimeout(x.ctx, x.in.cfg.ToolTimeout)
	defer cancel()
	now := x.in.deps.Clock.Now
	res, err := t.Apply(ctx, a, args)
	switch {
	case err == nil:
		rs.Settle(a, runstate.Succeeded, false, "", now())
		return res, nil
	case errors.Is(err, tools.ErrRejected): // rejected before any state change
		rs.Settle(a, runstate.Failed, false, value.Truncate(err.Error()), now())
		return tools.Result{}, abort(value.ErrToolFailed, "%s rejected: %v", a.Op, err)
	}
	// Timeout or lost response: outcome unknown. Never call Apply again.
	applied, known, lerr := t.Lookup(x.ctx, a.Key)
	switch {
	case lerr == nil && known && applied:
		rs.Settle(a, runstate.Succeeded, true, "confirmed after lost response", now())
		return res, nil
	case lerr == nil && !known:
		rs.Settle(a, runstate.Failed, true, "never reached the tool", now())
		return tools.Result{}, abort(value.ErrToolFailed, "%s never reached the tool", a.Op)
	default:
		rs.Settle(a, runstate.Uncertain, false, "lost response; lookup unavailable", now())
		return tools.Result{}, abort(value.ErrToolUncertain, "%s outcome unknown: lost response and lookup unavailable", a.Op)
	}
}

func (x *exec) emitAttempt(rs *runstate.RunState, a *runstate.Attempt) {
	snap := rs.Snapshot(a)
	op := snap.Op
	x.in.emit(x.input, events.Event{Kind: events.KindAttempt, Op: &op, Target: snap.Target, Attempt: &snap, Detail: snap.Detail})
}

// handoff evaluates the data expressions and asks the runtime to send.
func (x *exec) handoff(h *plan.HandoffStmt) error {
	in := x.input
	op := authz.Op{Tool: "handoff", Action: "request"}
	data := map[string]value.Value{}
	var srcs []string
	for _, name := range slices.Sorted(maps.Keys(h.Data)) {
		e := h.Data[name]
		v, denied, err := x.expr(&e, nil)
		if err != nil {
			return err
		}
		if denied {
			return abort(value.ErrUndefinedValue, "handoff data %q from a denied call", name)
		}
		data[name] = v
		srcs = append(srcs, v.Label().Strings()...)
	}
	pc := x.pcLabel()
	if x.in.deps.Sender == nil {
		return abort(value.ErrNoHandoffCap, "agent %s cannot send handoffs", x.in.cfg.Agent)
	}
	sent, err := x.in.deps.Sender.Send(x.ctx, handoff.Request{Run: in.RS, Ctx: in.Ctx, CtxWire: in.CtxWire, Eff: in.Eff, PC: pc,
		Trust: x.in.cfg.Trust, To: h.To, Task: h.Task, RequestedOps: h.RequestedOps, Data: data})
	ev := events.Event{Kind: events.KindDecision, Op: &op, Target: h.To + "/" + h.Task, Sources: dedupe(srcs), PCTrusted: pc.Trusted(x.in.cfg.Trust)}
	if err != nil && sent.Bytes == nil {
		// Refused before anything was sent (H1, H2, H3, or the allowance).
		rule := map[string]string{string(value.ErrNoHandoffCap): "H1", string(value.ErrExcessGrant): "H2", string(value.ErrUntrustedPC): "H3", string(value.ErrWorkflow): "H5"}[value.CodeOf(err)]
		if rule == "" {
			rule = "H1"
		}
		d := policy.Decision{Verdict: policy.Deny, Rule: rule, Group: "H", Reason: value.Truncate(err.Error())}
		ev.Decisions, ev.Code = []policy.Decision{d, d}, value.CodeOf(err)
		x.in.emit(in, ev)
		x.out.Denied++
		return nil // Deny skips the statement; nothing was sent
	}
	pass := []policy.Decision{
		{Verdict: policy.Allow, Rule: "H1", Group: "H", Reason: "handoff capability and workflow entry"},
		{Verdict: policy.Allow, Rule: "H2", Group: "H", Reason: "requested operations within the receiver's grant"},
		{Verdict: policy.Allow, Rule: "H3", Group: "H", Reason: "trusted pc; literal instruction fields"},
	}
	ev.Decisions = append(pass, pass[2])
	x.in.emit(in, ev)
	if err != nil {
		return abortFrom(err, value.ErrWorkflow)
	}
	x.out.Handoffs++
	if !sent.Response.Accepted() {
		return abort(value.Code(sent.Response.Code), "receiver rejected the handoff")
	}
	return nil
}

func ruleGroup(rule string) string {
	if rule == "schema" {
		return "S"
	}
	return rule[:1]
}

func dedupe(ss []string) []string {
	slices.Sort(ss)
	return slices.Compact(ss)
}

// PlannerInput builds a planner's input from trusted values only: the task,
// the analyst's parameters and note, effective capabilities, and data names
// and types. Data values and list lengths never enter it.
func PlannerInput(agent string, ac *authz.AuthContext, task *catalog.Task, eff []authz.Cap, data map[string]value.Value, mode string) llm.PlannerInput {
	in := llm.PlannerInput{Agent: agent, Task: task.Name, TaskVersion: task.Version, Note: ac.UserNote,
		Effective: slices.Clone(eff), Schemas: llm.SchemaDecls()}
	for _, name := range task.ParamNames() {
		t, _ := task.ParamType(name)
		in.Params = append(in.Params, llm.Param{Name: name, Type: t.String(), Value: json.RawMessage(ac.Params[name])})
	}
	for _, c := range eff {
		if c.Tool == "handoff" && c.Action == "request" {
			in.Handoffs = append(in.Handoffs, llm.HandoffTo{To: c.Scope.HandoffTo, Task: c.Scope.HandoffTask})
		}
	}
	if len(in.Handoffs) > 0 {
		schema := handoff.DataSchema(task, mode)
		for _, n := range slices.Sorted(maps.Keys(schema)) {
			in.HandoffData = append(in.HandoffData, llm.DataDecl{Name: n, Type: schema[n].String()})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(data)) {
		in.Data = append(in.Data, llm.DataDecl{Name: name, Type: data[name].Type().String()})
	}
	return in
}
