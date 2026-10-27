package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"citadel/internal/authz"
	"citadel/internal/evidence"
	"citadel/internal/runstate"
	"citadel/internal/value"
)

// ErrRejected marks a definite tool rejection: the tool refused before
// changing any state, so the attempt settles as Failed.
var ErrRejected = errors.New("tool rejected the call before any state change")

// ErrLostResponse marks a transport failure: the outcome is unknown until a
// read-only Lookup reconciles it. A state-changing call is never retried.
var ErrLostResponse = errors.New("tool response lost")

// ErrLookupUnavailable is returned by Lookup when the lookup_down fault is
// active.
var ErrLookupUnavailable = errors.New("tool lookup unavailable")

// Fault modes for the mock tools. They exist only in the mock environment.
const (
	FaultNone            = "none"
	FaultDropBeforeApply = "drop_before_apply" // times out, state unchanged
	FaultDropAfterApply  = "drop_after_apply"  // state changes, then times out
	FaultLookupDown      = "lookup_down"       // lookup returns an error
)

// Fault injects one failure into a tool. Target, when set, limits it to calls
// on that canonical target.
type Fault struct {
	Mode   string `yaml:"mode" json:"mode"`
	Target string `yaml:"target" json:"target"`
}

// Spec is everything a fixture says about the environment before a run.
type Spec struct {
	Inventory InventoryData           `yaml:"inventory" json:"inventory"`
	Access    []evidence.AccessRecord `yaml:"access" json:"access"`
	Flows     []evidence.FlowRecord   `yaml:"flows" json:"flows"`
	Blocked   []string                `yaml:"blocked" json:"blocked"`   // firewall rules present before the run
	Disabled  []string                `yaml:"disabled" json:"disabled"` // accounts disabled before the run
	Faults    map[string][]Fault      `yaml:"faults" json:"faults"`     // per tool: "firewall", "accounts"
}

// Args are a tool call's typed arguments.
type Args map[string]value.Value

// Result is a tool's raw output. The runtime, not the tool, labels it.
type Result struct {
	Records []map[string]string // logs.read: every field, trusted and attacker-written
	Items   []string            // inventory.read: canonical strings
	Changed bool                // a state-changing call changed state
}

// Tool is what the interpreter's executor calls. Apply requires an attempt
// issued by runstate.Admit and still unsettled; Lookup never changes state.
type Tool interface {
	Apply(ctx context.Context, a *runstate.Attempt, args Args) (Result, error)
	Lookup(ctx context.Context, key runstate.IdemKey) (applied, known bool, err error)
}

// ApplyRecord is one entry of a state-changing tool's own apply log.
type ApplyRecord struct {
	Key     runstate.IdemKey `json:"key"`
	Op      authz.Op         `json:"op"`
	Target  string           `json:"target"`
	Applies int              `json:"applies"` // times the state change was applied for this key
	Calls   int              `json:"calls"`   // times Apply was called with this key
	Changed bool             `json:"changed"`
}

// State is a snapshot of the environment's mutable state.
type State struct {
	Blocked  []string `json:"blocked"`  // firewall block rules
	Allowed  []string `json:"allowed"`  // firewall allow rules
	Disabled []string `json:"disabled"` // disabled accounts
}

// Change is one difference between two snapshots.
type Change struct {
	Tool   string `json:"tool"`
	Action string `json:"action"`
	Target string `json:"target"`
}

// String renders the change as "firewall.block 203.0.113.7".
func (c Change) String() string { return c.Tool + "." + c.Action + " " + c.Target }

// Env is the mock environment for one run.
type Env struct {
	mu       sync.Mutex
	clock    value.Clock
	inv      *Inventory
	store    *evidence.Store
	blocked  map[netip.Addr]bool
	allowed  map[netip.Addr]bool
	disabled map[string]bool
	log      map[runstate.IdemKey]*ApplyRecord
	faults   map[string][]Fault
}

// NewEnv builds an environment from a fixture spec. Every run starts from
// such a reset.
func NewEnv(s Spec, clock value.Clock) (*Env, error) {
	inv, err := NewInventory(s.Inventory)
	if err != nil {
		return nil, err
	}
	store, err := evidence.NewStore(inv, s.Access, s.Flows)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", value.ErrConfig, err)
	}
	e := &Env{clock: clock, inv: inv, store: store, blocked: map[netip.Addr]bool{}, allowed: map[netip.Addr]bool{},
		disabled: map[string]bool{}, log: map[runstate.IdemKey]*ApplyRecord{}, faults: map[string][]Fault{}}
	for _, b := range s.Blocked {
		a, err := value.ParseIPv4(b)
		if err != nil {
			return nil, fmt.Errorf("%w: pre-existing block: %v", value.ErrConfig, err)
		}
		e.blocked[a] = true
	}
	for _, d := range s.Disabled {
		if _, ok := inv.AccountKind(d); !ok {
			return nil, fmt.Errorf("%w: pre-disabled account %s not in directory", value.ErrConfig, d)
		}
		e.disabled[d] = true
	}
	for tool, fs := range s.Faults {
		if tool != "firewall" && tool != "accounts" {
			return nil, fmt.Errorf("%w: faults apply to firewall or accounts, not %q", value.ErrConfig, tool)
		}
		for _, f := range fs {
			switch f.Mode {
			case FaultNone, FaultDropBeforeApply, FaultDropAfterApply, FaultLookupDown:
			default:
				return nil, fmt.Errorf("%w: fault mode %q", value.ErrConfig, f.Mode)
			}
		}
		e.faults[tool] = slices.Clone(fs)
	}
	return e, nil
}

// Inventory returns the environment's inventory.
func (e *Env) Inventory() *Inventory { return e.inv }

// Evidence returns the evidence store over the environment's records.
func (e *Env) Evidence() *evidence.Store { return e.store }

func (e *Env) faultActive(tool, mode, target string) bool {
	for _, f := range e.faults[tool] {
		if f.Mode == mode && (f.Target == "" || f.Target == target) {
			return true
		}
	}
	return false
}

// Snapshot returns the current mutable state, sorted.
func (e *Env) Snapshot() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	var s State
	for a := range e.blocked {
		s.Blocked = append(s.Blocked, a.String())
	}
	for a := range e.allowed {
		s.Allowed = append(s.Allowed, a.String())
	}
	s.Disabled = slices.Sorted(maps.Keys(e.disabled))
	sortIPs(s.Blocked)
	sortIPs(s.Allowed)
	return s
}

func sortIPs(ss []string) {
	slices.SortFunc(ss, func(a, b string) int {
		return netip.MustParseAddr(a).Compare(netip.MustParseAddr(b))
	})
}

// Diff lists what changed from before to after.
func Diff(before, after State) []Change {
	var out []Change
	add := func(tool, action string, b, a []string) {
		for _, x := range a {
			if !slices.Contains(b, x) {
				out = append(out, Change{Tool: tool, Action: action, Target: x})
			}
		}
		for _, x := range b {
			if !slices.Contains(a, x) {
				out = append(out, Change{Tool: tool, Action: "un" + action, Target: x})
			}
		}
	}
	add("firewall", "block", before.Blocked, after.Blocked)
	add("firewall", "allow", before.Allowed, after.Allowed)
	add("accounts", "disable", before.Disabled, after.Disabled)
	return out
}

// ApplyLog returns the state-changing tools' own apply log, sorted by key.
func (e *Env) ApplyLog() []ApplyRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ApplyRecord, 0, len(e.log))
	for _, r := range e.log {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b ApplyRecord) int { return slices.Compare(a.Key[:], b.Key[:]) })
	return out
}

func requireAdmitted(a *runstate.Attempt, op authz.Op) error {
	if !a.Admitted() {
		return fmt.Errorf("%w: %w: %s needs an unsettled attempt from Admit", ErrRejected, value.ErrNotAdmitted, op)
	}
	if a.Op != op {
		return fmt.Errorf("%w: %w: attempt is for %s, not %s", ErrRejected, value.ErrNotAdmitted, a.Op, op)
	}
	return nil
}

// apply runs a state change idempotently by key. The change function is
// called only for a key never applied before.
func (e *Env) apply(tool string, op authz.Op, key runstate.IdemKey, target string, change func() bool) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, seen := e.log[key]
	if seen {
		rec.Calls++
		return Result{Changed: rec.Changed}, nil // a known key returns the recorded result
	}
	if e.faultActive(tool, FaultDropBeforeApply, target) {
		return Result{}, fmt.Errorf("%w: %s %s dropped before apply", ErrLostResponse, op, target)
	}
	changed := change()
	e.log[key] = &ApplyRecord{Key: key, Op: op, Target: target, Applies: 1, Calls: 1, Changed: changed}
	if e.faultActive(tool, FaultDropAfterApply, target) {
		return Result{}, fmt.Errorf("%w: %s %s applied, response dropped", ErrLostResponse, op, target)
	}
	return Result{Changed: changed}, nil
}

func (e *Env) lookup(tool string, key runstate.IdemKey) (bool, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, seen := e.log[key]
	target := ""
	if seen {
		target = rec.Target
	}
	if e.faultActive(tool, FaultLookupDown, target) {
		return false, false, ErrLookupUnavailable
	}
	if !seen {
		return false, false, nil
	}
	return rec.Applies > 0, true, nil
}

// Firewall is the mock firewall: firewall.block and firewall.allow.
type Firewall struct {
	env    *Env
	action string
}

// Accounts is the mock account directory: accounts.disable.
type Accounts struct{ env *Env }

// Logs is the mock log store: logs.read. It never changes state.
type Logs struct{ env *Env }

// InventoryTool answers inventory.read. It never changes state.
type InventoryTool struct{ env *Env }

// ToolFor returns the tool implementing op.
func (e *Env) ToolFor(op authz.Op) (Tool, bool) {
	switch op {
	case authz.Op{Tool: "firewall", Action: "block"}, authz.Op{Tool: "firewall", Action: "allow"}:
		return &Firewall{env: e, action: op.Action}, true
	case authz.Op{Tool: "accounts", Action: "disable"}:
		return &Accounts{env: e}, true
	case authz.Op{Tool: "logs", Action: "read"}:
		return &Logs{env: e}, true
	case authz.Op{Tool: "inventory", Action: "read"}:
		return &InventoryTool{env: e}, true
	}
	return nil, false
}

// Apply blocks or allows an address.
func (f *Firewall) Apply(_ context.Context, a *runstate.Attempt, args Args) (Result, error) {
	op := authz.Op{Tool: "firewall", Action: f.action}
	if err := requireAdmitted(a, op); err != nil {
		return Result{}, err
	}
	return f.env.firewallChange(op, a.Key, args)
}

func (e *Env) firewallChange(op authz.Op, key runstate.IdemKey, args Args) (Result, error) {
	ip, ok := args["ip"].AsIPv4()
	if !ok || len(args) != 1 {
		return Result{}, fmt.Errorf("%w: %s takes one ipv4 argument", ErrRejected, op)
	}
	set := e.blocked
	if op.Action == "allow" {
		set = e.allowed
	}
	return e.apply("firewall", op, key, ip.String(), func() bool {
		if set[ip] {
			return false
		}
		set[ip] = true
		return true
	})
}

// Lookup reports whether key was applied. It never changes state.
func (f *Firewall) Lookup(_ context.Context, key runstate.IdemKey) (bool, bool, error) {
	return f.env.lookup("firewall", key)
}

// Apply disables an account in the directory.
func (t *Accounts) Apply(_ context.Context, a *runstate.Attempt, args Args) (Result, error) {
	op := authz.Op{Tool: "accounts", Action: "disable"}
	if err := requireAdmitted(a, op); err != nil {
		return Result{}, err
	}
	return t.env.accountChange(op, a.Key, args)
}

func (e *Env) accountChange(op authz.Op, key runstate.IdemKey, args Args) (Result, error) {
	name, ok := args["account"].AsString()
	if !ok || args["account"].Kind() != value.KindAccountID || len(args) != 1 {
		return Result{}, fmt.Errorf("%w: %s takes one account_id argument", ErrRejected, op)
	}
	if _, exists := e.inv.AccountKind(name); !exists {
		return Result{}, fmt.Errorf("%w: account %s does not exist", ErrRejected, name)
	}
	return e.apply("accounts", op, key, name, func() bool {
		if e.disabled[name] {
			return false
		}
		e.disabled[name] = true
		return true
	})
}

// Lookup reports whether key was applied. It never changes state.
func (t *Accounts) Lookup(_ context.Context, key runstate.IdemKey) (bool, bool, error) {
	return t.env.lookup("accounts", key)
}

// Apply reads access records for the named hosts within the window ending
// now. Every field is returned; the runtime labels the result untrusted.
func (l *Logs) Apply(_ context.Context, a *runstate.Attempt, args Args) (Result, error) {
	if err := requireAdmitted(a, authz.Op{Tool: "logs", Action: "read"}); err != nil {
		return Result{}, err
	}
	hostArg, okH := args["host"]
	window, okW := args["window"].AsDuration()
	if !okH || !okW || len(args) != 2 {
		return Result{}, fmt.Errorf("%w: logs.read takes host and window", ErrRejected)
	}
	hosts := []value.Value{hostArg}
	if hostArg.Kind() == value.KindList {
		hosts = hostArg.Elems()
	}
	sc := evidence.TaskScope{To: l.env.clock.Now()}
	sc.From = sc.To.Add(-window)
	for _, h := range hosts {
		name, ok := h.AsString()
		if !ok || h.Kind() != value.KindHostname || !l.env.inv.HostExists(name) {
			return Result{}, fmt.Errorf("%w: logs.read host %q", ErrRejected, value.Truncate(h.Canonical()))
		}
		sc.Hosts = append(sc.Hosts, name)
	}
	var res Result
	for _, r := range l.env.store.Access(sc) {
		res.Records = append(res.Records, recordFields(r))
	}
	return res, nil
}

func recordFields(r evidence.AccessRecord) map[string]string {
	return map[string]string{
		"event_id": r.EventID, "ts": r.TS.UTC().Format(time.RFC3339), "host": r.Host,
		"client_ip": r.ClientIP.String(), "status": fmt.Sprint(r.Status), "auth_result": r.AuthResult,
		"auth_principal": r.AuthPrincipal, "sensor_id": r.SensorID, "pipeline_id": r.PipelineID,
		"path": r.Path, "user_agent": r.UserAgent, "x_forwarded_for": r.XForwardedFor, "attempted_user": r.AttemptedUser,
	}
}

// Lookup on a read-only tool reports nothing applied.
func (l *Logs) Lookup(context.Context, runstate.IdemKey) (bool, bool, error) {
	return false, false, nil
}

// Apply answers inventory.read.
func (t *InventoryTool) Apply(_ context.Context, a *runstate.Attempt, args Args) (Result, error) {
	if err := requireAdmitted(a, authz.Op{Tool: "inventory", Action: "read"}); err != nil {
		return Result{}, err
	}
	key, ok := args["key"].AsString()
	if !ok || len(args) != 1 {
		return Result{}, fmt.Errorf("%w: inventory.read takes key", ErrRejected)
	}
	items, err := t.env.inv.Read(key)
	if err != nil {
		return Result{}, err
	}
	return Result{Items: items}, nil
}

// Lookup on a read-only tool reports nothing applied.
func (t *InventoryTool) Lookup(context.Context, runstate.IdemKey) (bool, bool, error) {
	return false, false, nil
}

// BaselineCall is the C0 configuration's tool path. C0 is, by definition,
// ordinary tool calling with no Citadel runtime, so its calls do not go
// through Admit. The same idempotent apply log and fault injection apply.
// Only the harness's C0 driver may call it; a test checks that no other
// package does.
func (e *Env) BaselineCall(key runstate.IdemKey, op authz.Op, args Args) (Result, error) {
	switch op {
	case authz.Op{Tool: "firewall", Action: "block"}, authz.Op{Tool: "firewall", Action: "allow"}:
		return e.firewallChange(op, key, args)
	case authz.Op{Tool: "accounts", Action: "disable"}:
		return e.accountChange(op, key, args)
	}
	return Result{}, fmt.Errorf("%w: baseline call to %s", ErrRejected, op)
}

// BaselineRead answers the C0 baseline's read-only calls.
func (e *Env) BaselineRead(op authz.Op, args Args) (Result, error) {
	switch op {
	case authz.Op{Tool: "inventory", Action: "read"}:
		key, ok := args["key"].AsString()
		if !ok {
			return Result{}, fmt.Errorf("%w: inventory.read takes key", ErrRejected)
		}
		items, err := e.inv.Read(key)
		return Result{Items: items}, err
	case authz.Op{Tool: "logs", Action: "read"}:
		sc := evidence.TaskScope{To: e.clock.Now()}
		w, ok := args["window"].AsDuration()
		if !ok {
			return Result{}, fmt.Errorf("%w: logs.read takes window", ErrRejected)
		}
		sc.From = sc.To.Add(-w)
		hosts := []value.Value{args["host"]}
		if args["host"].Kind() == value.KindList {
			hosts = args["host"].Elems()
		}
		for _, h := range hosts {
			name, _ := h.AsString()
			sc.Hosts = append(sc.Hosts, name)
		}
		var res Result
		for _, r := range e.store.Access(sc) {
			res.Records = append(res.Records, recordFields(r))
		}
		return res, nil
	}
	return Result{}, fmt.Errorf("%w: baseline read of %s", ErrRejected, op)
}
