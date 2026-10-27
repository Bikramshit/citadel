// Package runstate holds every counted or one-time permission of a run (call
// budgets, the handoff allowance, approvals, attempt records) in one per-run
// object guarded by one mutex. Every state-changing call, handoff
// acceptance, and approval passes through it. A valid signature proves who
// issued a context; whether any budget remains is decided only here.
//
// Lock order: Runs.mu before RunState.mu; the replay table's mutex is never
// held with either. No tool call runs while any lock is held.
package runstate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"citadel/internal/authz"
	"citadel/internal/policy"
	"citadel/internal/value"
)

// IdemKey is a state-changing call's idempotency key.
type IdemKey [32]byte

// String renders the key in hex.
func (k IdemKey) String() string { return hex.EncodeToString(k[:]) }

// MarshalText writes the key in hex.
func (k IdemKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText parses a hex key, for replaying event logs.
func (k *IdemKey) UnmarshalText(b []byte) error {
	if len(b) != 64 {
		return fmt.Errorf("idempotency key: want 64 hex characters")
	}
	_, err := hex.Decode(k[:], b)
	return err
}

// IdemPrefix is the domain prefix of idempotency keys.
const IdemPrefix = "citadel-idem-v1\x00"

// IdemFields are the inputs an idempotency key binds.
type IdemFields struct {
	RunID        string
	CtxHash      [32]byte
	Agent        string
	Tool, Action string
	Args         map[string]string // name -> canonical value
}

// EncodeIdem is the encoding IdemKeyFor hashes: the prefix, then
// length-prefixed (uint32 big-endian) run ID, context hash (raw), agent,
// tool, action, then each argument sorted by name as length-prefixed name
// and canonical value.
func EncodeIdem(f IdemFields) []byte {
	b := []byte(IdemPrefix)
	lp := func(s string) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	for _, s := range []string{f.RunID, string(f.CtxHash[:]), f.Agent, f.Tool, f.Action} {
		lp(s)
	}
	for _, name := range slices.Sorted(maps.Keys(f.Args)) {
		lp(name)
		lp(f.Args[name])
	}
	return b
}

// IdemKeyOf hashes idempotency fields.
func IdemKeyOf(f IdemFields) IdemKey { return sha256.Sum256(EncodeIdem(f)) }

// IdemKeyFor returns the idempotency key of a call: run, context hash,
// agent, tool, action, normalized arguments.
func IdemKeyFor(c *policy.CallCtx) IdemKey {
	f := IdemFields{RunID: c.RunID, CtxHash: c.CtxHash, Agent: c.Agent, Tool: c.Op.Tool, Action: c.Op.Action, Args: map[string]string{}}
	for name, v := range c.Args {
		f.Args[name] = v.Canonical()
	}
	return IdemKeyOf(f)
}

// AttemptState is an admitted call's outcome.
type AttemptState uint8

// Attempt states. Denied is not an attempt state: a denied call never reaches
// a tool.
const (
	Attempted AttemptState = iota
	Succeeded
	Failed
	Uncertain
)

// String names the state.
func (s AttemptState) String() string {
	switch s {
	case Attempted:
		return "attempted"
	case Succeeded:
		return "succeeded"
	case Failed:
		return "failed"
	case Uncertain:
		return "uncertain"
	}
	return "invalid"
}

// MarshalText writes the state's name.
func (s AttemptState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a state name, for replaying event logs.
func (s *AttemptState) UnmarshalText(b []byte) error {
	for _, c := range []AttemptState{Attempted, Succeeded, Failed, Uncertain} {
		if c.String() == string(b) {
			*s = c
			return nil
		}
	}
	return fmt.Errorf("unknown attempt state %q", value.Truncate(string(b)))
}

// Attempt records one admitted tool call. Only Admit creates attempts that
// tools accept: the issuer field is unexported and set nowhere else.
type Attempt struct {
	Key        IdemKey      `json:"key"`
	RunID      string       `json:"run_id"`
	Op         authz.Op     `json:"op"`
	Target     string       `json:"target"`
	Sensitive  bool         `json:"sensitive"`
	State      AttemptState `json:"state"`
	Reconciled bool         `json:"reconciled"`
	Started    time.Time    `json:"started"`
	Settled    time.Time    `json:"settled"`
	Detail     string       `json:"detail"`

	issuer *RunState
}

// Admitted reports whether a came from Admit and is still unsettled, which
// is what a tool requires before it acts.
func (a *Attempt) Admitted() bool {
	if a == nil || a.issuer == nil {
		return false
	}
	a.issuer.mu.Lock()
	defer a.issuer.mu.Unlock()
	return a.State == Attempted
}

// HandoffKey identifies a handoff allowance.
type HandoffKey struct{ From, To, Task string }

// RunState is one run's local state.
type RunState struct {
	mu sync.Mutex

	runID     string
	ctxHash   [32]byte
	principal string
	task      string
	agents    []string
	policyVer string
	expiresAt time.Time
	closed    bool

	maxSensitive    int // from the signed context's budgets
	softUntrustedPC int
	sensitive       int // admitted calls; never refunded
	perOp           map[authz.Op]int
	untrustedPC     int
	handoffs        map[HandoffKey]int // consumed
	handoffMax      map[HandoffKey]int // from the signed workflow
	approvals       map[policy.ApprovalKey]*policy.Approval
	attempts        map[IdemKey]*Attempt
	reads           []*Attempt
}

func newRunState(ac *authz.AuthContext, h [32]byte) *RunState {
	rs := &RunState{
		runID: ac.RunID, ctxHash: h, principal: ac.Principal, task: ac.Task,
		agents: slices.Clone(ac.Agents), policyVer: ac.PolicyVersion, expiresAt: ac.ExpiresAt,
		maxSensitive: ac.Budgets.MaxSensitiveCalls, softUntrustedPC: ac.Budgets.SoftUntrustedPC,
		perOp:      map[authz.Op]int{},
		handoffs:   map[HandoffKey]int{},
		handoffMax: map[HandoffKey]int{},
		approvals:  map[policy.ApprovalKey]*policy.Approval{},
		attempts:   map[IdemKey]*Attempt{},
	}
	for _, w := range ac.Workflow {
		k := HandoffKey{From: w.From, To: w.To, Task: w.Task}
		rs.handoffMax[k] = max(rs.handoffMax[k], w.Max)
	}
	return rs
}

// RunID returns the run's ID.
func (rs *RunState) RunID() string { return rs.runID }

// CtxHash returns the hash of the context the run is bound to.
func (rs *RunState) CtxHash() [32]byte { return rs.ctxHash }

// Principal returns the context's principal.
func (rs *RunState) Principal() string { return rs.principal }

// ExpiresAt returns the context's expiry.
func (rs *RunState) ExpiresAt() time.Time { return rs.expiresAt }

// Runs is one agent process's table of runs. The process start time it holds
// is the only global state: contexts issued before it are refused.
type Runs struct {
	mu        sync.Mutex
	byID      map[string]*RunState
	startedAt time.Time // process start
	self      string
}

// NewRuns returns an empty table for agent self, started at startedAt.
func NewRuns(self string, startedAt time.Time) *Runs {
	return &Runs{byID: map[string]*RunState{}, startedAt: startedAt, self: self}
}

// StartedAt returns the process start time (the restart watermark).
func (r *Runs) StartedAt() time.Time { return r.startedAt }

// Self returns the agent this table belongs to.
func (r *Runs) Self() string { return r.self }

// Get returns a run by ID.
func (r *Runs) Get(runID string) (*RunState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rs, ok := r.byID[runID]
	return rs, ok
}

// Activate binds a verified context to this process.
func (r *Runs) Activate(ac *authz.AuthContext, h [32]byte, now time.Time) (*RunState, error) {
	switch {
	case ac.IssuedAt.Before(r.startedAt):
		return nil, fmt.Errorf("%w: context issued %s, before this process started %s", value.ErrPreStart,
			ac.IssuedAt.Format(time.RFC3339), r.startedAt.Format(time.RFC3339)) // state from before a restart is gone: fail closed
	case !now.Before(ac.ExpiresAt):
		return nil, fmt.Errorf("%w: context expired", value.ErrExpired)
	case !slices.Contains(ac.Agents, r.self):
		return nil, fmt.Errorf("%w: %s is not a participant", value.ErrNotParticipant, r.self)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rs, ok := r.byID[ac.RunID]; ok {
		if rs.ctxHash != h {
			return nil, fmt.Errorf("%w: run %s is bound to a different context", value.ErrContextConflict, ac.RunID)
		}
		if rs.IsClosed() { // takes rs.mu: allowed lock order
			return nil, fmt.Errorf("%w: run %s", value.ErrRunClosed, ac.RunID)
		}
		return rs, nil
	}
	rs := newRunState(ac, h)
	r.byID[ac.RunID] = rs
	return rs, nil
}

func denyA0(reason string) policy.Decision {
	return policy.Decision{Verdict: policy.Deny, Rule: "A0", Group: "A", Reason: reason}
}

// Admit is the only path from a policy decision to a tool call. Budgets,
// duplicate detection, and approval consumption happen in one critical
// section. It returns the attempt to execute, or nil and the decision that
// stopped the call: Deny, or Escalate when an approval is needed.
func (rs *RunState) Admit(c *policy.CallCtx, d policy.Decision, now time.Time) (*Attempt, policy.Decision) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.closed || !now.Before(rs.expiresAt) {
		return nil, denyA0("run closed or context expired")
	}
	if c.RunID != rs.runID || c.CtxHash != rs.ctxHash {
		return nil, denyA0("call does not belong to this run's context")
	}
	if d.Verdict == policy.Deny {
		return nil, d
	}
	target := ""
	if c.Target != nil {
		target = c.Target.Canonical()
	}
	if !authz.IsStateChanging(c.Op) {
		if d.Verdict != policy.Allow {
			return nil, d
		}
		a := &Attempt{Key: IdemKeyFor(c), RunID: rs.runID, Op: c.Op, Target: target, State: Attempted, Started: now, issuer: rs}
		rs.reads = append(rs.reads, a)
		return a, d
	}
	k := IdemKeyFor(c) // run, context hash, agent, tool, action, normalized arguments
	if a, seen := rs.attempts[k]; seen {
		return nil, policy.Decision{Verdict: policy.Deny, Rule: "A5", Group: "A", Reason: "identical call already attempted: " + a.State.String()}
	}
	if rs.sensitive >= rs.maxSensitive || rs.overOpLimit(c) {
		return nil, policy.Decision{Verdict: policy.Deny, Rule: "A4", Group: "A",
			Reason: fmt.Sprintf("budget exhausted: %d sensitive calls, %d %s", rs.sensitive, rs.perOp[c.Op], c.Op)}
	}
	untrusted := !c.PC.Trusted(c.Trust)
	if d.Verdict == policy.Allow && untrusted && rs.untrustedPC >= rs.softUntrustedPC {
		d = policy.Decision{Verdict: policy.Escalate, Rule: "F3", Group: "F",
			Reason: fmt.Sprintf("volume under an untrusted loop: %d calls, soft budget %d", rs.untrustedPC, rs.softUntrustedPC)}
	}
	if d.Verdict == policy.Escalate {
		ap := rs.approvals[policy.KeyFor(c)]
		if ap == nil || ap.State != policy.Granted || !now.Before(ap.ExpiresAt) {
			return nil, d // caller requests approval and pauses; timeout means Deny
		}
		ap.State = policy.Used
		d = policy.Decision{Verdict: policy.Allow, Rule: d.Rule, Group: d.Group, Reason: d.Reason + "; approved once by " + ap.Approver}
	}
	rs.sensitive++
	rs.perOp[c.Op]++
	if untrusted {
		rs.untrustedPC++
	}
	a := &Attempt{Key: k, RunID: rs.runID, Op: c.Op, Target: target, Sensitive: true, State: Attempted, Started: now, issuer: rs}
	rs.attempts[k] = a
	return a, d
}

// overOpLimit applies the strictest per-operation limit among the effective
// capabilities that match the call.
func (rs *RunState) overOpLimit(c *policy.CallCtx) bool {
	limit := 0
	for _, cp := range authz.MatchingCaps(c.Eff, c.Op) {
		if cp.Scope.MaxCalls > 0 && (limit == 0 || cp.Scope.MaxCalls < limit) {
			limit = cp.Scope.MaxCalls
		}
	}
	return limit > 0 && rs.perOp[c.Op] >= limit
}

// Settle records an attempt's outcome. Only an unsettled attempt issued by
// this run can be settled, and only once.
func (rs *RunState) Settle(a *Attempt, s AttemptState, reconciled bool, detail string, now time.Time) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if a == nil || a.issuer != rs {
		return fmt.Errorf("%w: attempt not issued by this run", value.ErrNotAdmitted)
	}
	if a.State != Attempted || s == Attempted {
		return fmt.Errorf("%w: attempt already settled as %s", value.ErrNotAdmitted, a.State)
	}
	a.State, a.Reconciled, a.Detail, a.Settled = s, reconciled, detail, now
	return nil
}

// RequestApproval opens an approval request for key k if none exists. It
// expires at the earlier of 10 minutes and the context's expiry.
func (rs *RunState) RequestApproval(k policy.ApprovalKey, now time.Time) policy.Approval {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if _, ok := rs.approvals[k]; !ok {
		exp := now.Add(policy.ApprovalLifetime)
		if rs.expiresAt.Before(exp) {
			exp = rs.expiresAt
		}
		rs.approvals[k] = &policy.Approval{Key: k, State: policy.Pending, ExpiresAt: exp}
	}
	return *rs.approvals[k]
}

// Approve records the principal's answer. It is idempotent for a repeated
// "yes" and never revives a used, rejected, or expired approval.
func (rs *RunState) Approve(k policy.ApprovalKey, approver string, yes bool, now time.Time) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	a, ok := rs.approvals[k]
	switch {
	case !ok:
		return fmt.Errorf("%w: %s", value.ErrNoSuchApproval, k)
	case approver != rs.principal:
		return fmt.Errorf("%w: %q may not approve for %q", value.ErrNotPrincipal, value.Truncate(approver), rs.principal)
	case rs.closed:
		return fmt.Errorf("%w: run closed", value.ErrApprovalClosed)
	case !now.Before(a.ExpiresAt):
		if a.State == policy.Pending || a.State == policy.Granted {
			a.State = policy.Expired
		}
		return fmt.Errorf("%w: %s", value.ErrApprovalExpired, k)
	case a.State == policy.Pending && yes:
		a.State, a.Approver = policy.Granted, approver
	case a.State == policy.Pending:
		a.State, a.Approver = policy.Rejected, approver
	case a.State == policy.Granted && yes:
		// repeated click: no change
	default:
		return fmt.Errorf("%w: approval is %s", value.ErrApprovalClosed, a.State)
	}
	return nil
}

// Approval returns a copy of an approval's current state.
func (rs *RunState) Approval(k policy.ApprovalKey) (policy.Approval, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	a, ok := rs.approvals[k]
	if !ok {
		return policy.Approval{}, false
	}
	return *a, true
}

// CommitHandoff consumes the handoff allowance and installs staged values
// atomically. install is the only place staged values enter the run.
func (rs *RunState) CommitHandoff(k HandoffKey, install func(), now time.Time) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.closed || !now.Before(rs.expiresAt) {
		return fmt.Errorf("%w: run closed or context expired", value.ErrAuthCtx)
	}
	if rs.handoffs[k] >= rs.handoffMax[k] {
		return fmt.Errorf("%w: handoff allowance for %s->%s %s spent", value.ErrWorkflow, k.From, k.To, k.Task) // remaining budget is local state, never read from a signature
	}
	rs.handoffs[k]++
	install()
	return nil
}

// ReserveHandoff is the sender's side of the allowance: it spends one
// handoff before the envelope is signed, so a retransmission resends the
// same bytes instead of creating a second envelope.
func (rs *RunState) ReserveHandoff(k HandoffKey, now time.Time) error {
	return rs.CommitHandoff(k, func() {}, now)
}

// Close ends the run. A closed run never reopens.
func (rs *RunState) Close() {
	rs.mu.Lock()
	rs.closed = true
	rs.mu.Unlock()
}

// IsClosed reports whether the run has ended.
func (rs *RunState) IsClosed() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.closed
}

// Stats is a consistent snapshot of a run's counters, for tests, the
// invariant checker, and events.
type Stats struct {
	Sensitive     int
	PerOp         map[authz.Op]int
	UntrustedPC   int
	Handoffs      map[HandoffKey]int
	HandoffMax    map[HandoffKey]int
	MaxSensitive  int
	Approvals     []policy.Approval
	Attempts      []Attempt // sensitive attempts, by start time then key
	Reads         []Attempt
	UsedApprovals int
}

// Stats returns a snapshot of the run's counters.
func (rs *RunState) Stats() Stats {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	s := Stats{
		Sensitive: rs.sensitive, PerOp: maps.Clone(rs.perOp), UntrustedPC: rs.untrustedPC,
		Handoffs: maps.Clone(rs.handoffs), HandoffMax: maps.Clone(rs.handoffMax), MaxSensitive: rs.maxSensitive,
	}
	for _, a := range rs.approvals {
		s.Approvals = append(s.Approvals, *a)
		if a.State == policy.Used {
			s.UsedApprovals++
		}
	}
	slices.SortFunc(s.Approvals, func(a, b policy.Approval) int { return slices.Compare(a.Key[:], b.Key[:]) })
	for _, a := range rs.attempts {
		cp := *a
		cp.issuer = nil
		s.Attempts = append(s.Attempts, cp)
	}
	slices.SortFunc(s.Attempts, func(a, b Attempt) int {
		if c := a.Started.Compare(b.Started); c != 0 {
			return c
		}
		return slices.Compare(a.Key[:], b.Key[:])
	})
	for _, a := range rs.reads {
		cp := *a
		cp.issuer = nil
		s.Reads = append(s.Reads, cp)
	}
	return s
}

// Snapshot returns a copy of an attempt's current fields, safe to read while
// the run continues.
func (rs *RunState) Snapshot(a *Attempt) Attempt {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	cp := *a
	cp.issuer = nil
	return cp
}
