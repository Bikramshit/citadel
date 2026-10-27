// Package authz holds the authorization context the orchestrator signs, the
// capability and scope types, and the intersection arithmetic that computes
// an agent's effective permissions:
//
//	Eff(a) = Static(a) ∩ Grant(run, a) ∩ TaskOps(t, a) ∩ Requested
//
// Every step is an intersection, so effective permissions never exceed the
// signed grant.
package authz

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"citadel/internal/value"
)

// Op names a tool and a literal action.
type Op struct {
	Tool   string `json:"tool"`
	Action string `json:"action"`
}

// String renders the op as "tool.action".
func (o Op) String() string { return o.Tool + "." + o.Action }

// Cap is one capability: a tool, an action, and a resource scope.
type Cap struct {
	Tool   string `json:"tool"`
	Action string `json:"action"`
	Scope  Scope  `json:"scope"`
}

// Op returns the capability's tool and action.
func (c Cap) Op() Op { return Op{Tool: c.Tool, Action: c.Action} }

// String renders the capability for logs and prompts.
func (c Cap) String() string { return c.Op().String() + c.Scope.String() }

// Scope constrains the resources a capability covers. The JSON tags carry no
// omitempty: an empty host list must never be re-read as nil ("any").
type Scope struct {
	Hosts            []string      `json:"hosts"`             // nil means any
	Window           time.Duration `json:"window"`            // 0 means any; logs.read only
	IPClass          string        `json:"ip_class"`          // "" means any; else "public_external"
	AccountKinds     []string      `json:"account_kinds"`     // nil means any
	ExcludeProtected bool          `json:"exclude_protected"` // protected resources excluded
	HandoffTo        string        `json:"handoff_to"`        // handoff.request only
	HandoffTask      string        `json:"handoff_task"`      // handoff.request only
	MaxCalls         int           `json:"max_calls"`         // 0 means no per-operation limit
}

// IPClassPublicExternal is the only IP class the catalog uses.
const IPClassPublicExternal = "public_external"

// String renders the scope's constraints compactly.
func (s Scope) String() string {
	var parts []string
	if s.Hosts != nil {
		parts = append(parts, "hosts="+strings.Join(s.Hosts, "|"))
	}
	if s.Window != 0 {
		parts = append(parts, "window="+value.FormatDuration(s.Window))
	}
	if s.IPClass != "" {
		parts = append(parts, "ip_class="+s.IPClass)
	}
	if s.AccountKinds != nil {
		parts = append(parts, "account_kinds="+strings.Join(s.AccountKinds, "|"))
	}
	if s.ExcludeProtected {
		parts = append(parts, "exclude_protected")
	}
	if s.HandoffTo != "" {
		parts = append(parts, "to="+s.HandoffTo)
	}
	if s.HandoffTask != "" {
		parts = append(parts, "task="+s.HandoffTask)
	}
	if s.MaxCalls != 0 {
		parts = append(parts, fmt.Sprintf("max_calls=%d", s.MaxCalls))
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func meetEq(a, b string) (string, bool) {
	switch {
	case a == "":
		return b, true
	case b == "", a == b:
		return a, true
	}
	return "", false
}

// meetSet intersects two constraint sets where nil means any. Both
// constrained with an empty overlap has no meet.
func meetSet(a, b []string) ([]string, bool) {
	switch {
	case a == nil:
		return slices.Clone(b), true
	case b == nil:
		return slices.Clone(a), true
	}
	out := []string{}
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out, len(out) > 0
}

func minNonZero[T int | time.Duration](a, b T) T {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	}
	return min(a, b)
}

// Meet returns a scope at least as strict as both, or ok=false if none exists.
func (a Scope) Meet(b Scope) (s Scope, ok bool) {
	if s.IPClass, ok = meetEq(a.IPClass, b.IPClass); !ok {
		return Scope{}, false
	}
	if s.HandoffTo, ok = meetEq(a.HandoffTo, b.HandoffTo); !ok {
		return Scope{}, false
	}
	if s.HandoffTask, ok = meetEq(a.HandoffTask, b.HandoffTask); !ok {
		return Scope{}, false
	}
	if s.Hosts, ok = meetSet(a.Hosts, b.Hosts); !ok { // both constrained, empty overlap
		return Scope{}, false
	}
	if s.AccountKinds, ok = meetSet(a.AccountKinds, b.AccountKinds); !ok {
		return Scope{}, false
	}
	s.ExcludeProtected = a.ExcludeProtected || b.ExcludeProtected
	s.MaxCalls = minNonZero(a.MaxCalls, b.MaxCalls)
	s.Window = minNonZero(a.Window, b.Window)
	return s, true
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// Within reports whether s is at least as strict as t: everything s permits,
// t permits.
func (s Scope) Within(t Scope) bool {
	switch {
	case t.IPClass != "" && s.IPClass != t.IPClass,
		s.HandoffTo != t.HandoffTo && t.HandoffTo != "",
		s.HandoffTask != t.HandoffTask && t.HandoffTask != "",
		t.Hosts != nil && (s.Hosts == nil || !subset(s.Hosts, t.Hosts)),
		t.AccountKinds != nil && (s.AccountKinds == nil || !subset(s.AccountKinds, t.AccountKinds)),
		t.ExcludeProtected && !s.ExcludeProtected,
		t.MaxCalls != 0 && (s.MaxCalls == 0 || s.MaxCalls > t.MaxCalls),
		t.Window != 0 && (s.Window == 0 || s.Window > t.Window):
		return false
	}
	return true
}

// Intersect keeps an operation only if both sets have the same tool and
// action, and combines their scopes with Meet. Operations whose scopes cannot
// both hold drop out.
func Intersect(a, b []Cap) []Cap {
	var out []Cap
	for _, x := range a {
		for _, y := range b {
			if x.Tool != y.Tool || x.Action != y.Action {
				continue
			}
			if s, ok := x.Scope.Meet(y.Scope); ok {
				out = append(out, Cap{Tool: x.Tool, Action: x.Action, Scope: s})
			}
		}
	}
	return out
}

// Effective never exceeds grant: every step is an intersection. requested
// applies only on the receiving side of a handoff and only narrows.
func Effective(static, grant, taskOps, requested []Cap) []Cap {
	eff := Intersect(Intersect(static, grant), taskOps)
	if requested != nil {
		eff = Intersect(eff, requested)
	}
	return eff
}

// Covers reports whether some capability in caps has c's tool and action and
// a scope that c's scope is within.
func Covers(caps []Cap, c Cap) bool {
	return slices.ContainsFunc(caps, func(x Cap) bool {
		return x.Tool == c.Tool && x.Action == c.Action && c.Scope.Within(x.Scope)
	})
}

// CoversOp reports whether some capability in caps has op's tool and action.
func CoversOp(caps []Cap, op Op) bool {
	return slices.ContainsFunc(caps, func(x Cap) bool { return x.Tool == op.Tool && x.Action == op.Action })
}

// SubsetOf holds when every capability in x is covered by one in y with the
// same tool and action and a scope at least as strict.
func SubsetOf(x, y []Cap) bool {
	for _, c := range x {
		if !Covers(y, c) {
			return false
		}
	}
	return true
}

// OpsSubsetOf holds when every requested operation names a tool and action
// present in y. Requested operations carry no scope of their own: they narrow
// by operation, and the receiver keeps the granted scope.
func OpsSubsetOf(ops []Op, y []Cap) bool {
	for _, o := range ops {
		if !CoversOp(y, o) {
			return false
		}
	}
	return true
}

// CapsFromOps turns requested operations into unscoped capabilities for
// Intersect. A nil input stays nil (no narrowing); an empty one narrows to
// nothing.
func CapsFromOps(ops []Op) []Cap {
	if ops == nil {
		return nil
	}
	out := make([]Cap, 0, len(ops))
	for _, o := range ops {
		out = append(out, Cap{Tool: o.Tool, Action: o.Action})
	}
	return out
}

// HandoffCap is the capability to request task from agent to.
func HandoffCap(to, task string) Cap {
	return Cap{Tool: "handoff", Action: "request", Scope: Scope{HandoffTo: to, HandoffTask: task}}
}

// MatchingCaps returns the capabilities in caps for op.
func MatchingCaps(caps []Cap, op Op) []Cap {
	var out []Cap
	for _, c := range caps {
		if c.Tool == op.Tool && c.Action == op.Action {
			out = append(out, c)
		}
	}
	return out
}

// HasFirewallOrAccountOp reports whether caps contain any firewall or account
// operation. Invariant 4 requires this to be false for the Investigator.
func HasFirewallOrAccountOp(caps []Cap) bool {
	return slices.ContainsFunc(caps, func(c Cap) bool { return c.Tool == "firewall" || c.Tool == "accounts" })
}

// HandoffGrant permits one agent to ask another to perform a task, at most
// Max times per run.
type HandoffGrant struct {
	From string `json:"from"`
	To   string `json:"to"`
	Task string `json:"task"`
	Max  int    `json:"max"`
}

// Budgets are the run's counted limits.
type Budgets struct {
	MaxSensitiveCalls int `json:"max_sensitive_calls"` // hard; exceeding denies (A4)
	SoftUntrustedPC   int `json:"soft_untrusted_pc"`   // calls under untrusted pc before escalating (F3)
}

// ContextVersion is the authorization context format version.
const ContextVersion = 1

// AuthContext is the orchestrator-signed authority for one run.
type AuthContext struct {
	V             int                        `json:"v"`
	RunID         string                     `json:"run_id"`
	Principal     string                     `json:"principal"`
	Role          string                     `json:"role"`
	Task          string                     `json:"task"`
	TaskVersion   int                        `json:"task_version"`
	Params        map[string]json.RawMessage `json:"params"`    // validated by the orchestrator
	UserNote      string                     `json:"user_note"` // context only, no authority
	Agents        []string                   `json:"agents"`    // participating agents; any other agent is refused
	Grants        map[string][]Cap           `json:"grants"`    // agent -> granted operations with scopes
	Workflow      []HandoffGrant             `json:"workflow"`
	PolicyVersion string                     `json:"policy_version"`
	IssuedAt      time.Time                  `json:"issued_at"`
	ExpiresAt     time.Time                  `json:"expires_at"`
	Budgets       Budgets                    `json:"budgets"`
}

// HasAgent reports whether agent participates in the run.
func (ac *AuthContext) HasAgent(agent string) bool { return slices.Contains(ac.Agents, agent) }

// WorkflowAllows reports whether the signed workflow lists (from, to, task)
// with a positive allowance. It never says whether any allowance remains:
// that is local run state.
func (ac *AuthContext) WorkflowAllows(from, to, task string) bool {
	return ac.HandoffMax(from, to, task) > 0
}

// HandoffMax returns the signed allowance for (from, to, task), or 0.
func (ac *AuthContext) HandoffMax(from, to, task string) int {
	m := 0
	for _, w := range ac.Workflow {
		if w.From == from && w.To == to && w.Task == task {
			m = max(m, w.Max)
		}
	}
	return m
}

// Validate checks the context's structure after strict decoding. It does not
// check signatures, expiry against a clock, or local run state.
func (ac *AuthContext) Validate() error {
	switch {
	case ac.V != ContextVersion:
		return fmt.Errorf("%w: context version %d", value.ErrAuthCtx, ac.V)
	case ac.RunID == "" || len(ac.RunID) > 64:
		return fmt.Errorf("%w: run id", value.ErrAuthCtx)
	case ac.Principal == "" || ac.Role == "" || ac.Task == "" || ac.TaskVersion < 1:
		return fmt.Errorf("%w: principal, role, or task missing", value.ErrAuthCtx)
	case len(ac.Agents) == 0:
		return fmt.Errorf("%w: no participating agents", value.ErrAuthCtx)
	case ac.PolicyVersion == "":
		return fmt.Errorf("%w: policy version missing", value.ErrAuthCtx)
	case !ac.ExpiresAt.After(ac.IssuedAt):
		return fmt.Errorf("%w: expires before it is issued", value.ErrAuthCtx)
	case ac.Budgets.MaxSensitiveCalls < 0 || ac.Budgets.SoftUntrustedPC < 0:
		return fmt.Errorf("%w: negative budget", value.ErrAuthCtx)
	}
	for agent, caps := range ac.Grants {
		if !ac.HasAgent(agent) {
			return fmt.Errorf("%w: grant for non-participant %q", value.ErrAuthCtx, agent)
		}
		for _, c := range caps {
			if err := c.Scope.validate(); err != nil {
				return fmt.Errorf("%w: grant %s: %v", value.ErrAuthCtx, c.Op(), err)
			}
		}
	}
	for _, w := range ac.Workflow {
		if !ac.HasAgent(w.From) || !ac.HasAgent(w.To) || w.Max < 0 {
			return fmt.Errorf("%w: workflow entry %s->%s", value.ErrAuthCtx, w.From, w.To)
		}
	}
	return nil
}

func (s Scope) validate() error {
	if s.Hosts != nil && len(s.Hosts) == 0 {
		return fmt.Errorf("empty host set")
	}
	if s.AccountKinds != nil && len(s.AccountKinds) == 0 {
		return fmt.Errorf("empty account-kind set")
	}
	if s.MaxCalls < 0 || s.Window < 0 {
		return fmt.Errorf("negative limit")
	}
	if s.IPClass != "" && s.IPClass != IPClassPublicExternal {
		return fmt.Errorf("unknown ip class %q", s.IPClass)
	}
	return nil
}

// TaskOps returns the catalog's operations for agent in task at version,
// evaluated with the run's validated parameters. ok is false when the task
// or version is not in the catalog.
type TaskOps func(task string, version int, agent string, params map[string]json.RawMessage) (ops []Cap, ok bool, err error)

// ReceiverEffective computes the receiver's effective capabilities after the
// envelope's signature and the embedded context are verified (rule H5). The
// handoff allowance is spent later, in runstate.CommitHandoff; it is never
// read from the signature.
func ReceiverEffective(self string, static []Cap, ac *AuthContext, from, task string, version int, requested []Op, catalogOps TaskOps) ([]Cap, error) {
	taskOps, ok, err := catalogOps(task, version, self, ac.Params) // the receiver's own catalog
	if err != nil {
		return nil, fmt.Errorf("%w: %v", value.ErrUnknownTask, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s v%d", value.ErrUnknownTask, task, version)
	}
	if !ac.WorkflowAllows(from, self, task) {
		return nil, fmt.Errorf("%w: workflow does not allow %s -> %s for %s", value.ErrWorkflow, from, self, task)
	}
	if task != ac.Task || version != ac.TaskVersion {
		return nil, fmt.Errorf("%w: handoff task %s v%d differs from the context's %s v%d", value.ErrWorkflow, task, version, ac.Task, ac.TaskVersion)
	}
	if requested != nil && !OpsSubsetOf(requested, Intersect(ac.Grants[self], taskOps)) {
		return nil, fmt.Errorf("%w: requested operations exceed grant ∩ task operations", value.ErrExcessGrant) // reject the envelope; never trim silently
	}
	return Effective(static, ac.Grants[self], taskOps, CapsFromOps(requested)), nil
}
