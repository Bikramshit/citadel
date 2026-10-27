// Package policy is Citadel's default-deny policy engine. Decide is a pure
// function of the call and the signed context: every applicable rule runs and
// the strictest verdict wins (Deny over Escalate over Allow). A call can be
// allowed or escalated only if A1 matched a capability and a routing rule
// (F0, F1, E1, E2) applied; otherwise D0 denies. Rules that depend on run
// state (A4, A5, F3) and approval consumption run afterward in
// runstate.Admit, under the run lock.
package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/evidence"
	"citadel/internal/label"
	"citadel/internal/value"
)

// Verdict is a policy outcome.
type Verdict uint8

// Verdicts, ordered by strictness.
const (
	Allow Verdict = iota
	Escalate
	Deny
)

// String names the verdict.
func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Escalate:
		return "escalate"
	case Deny:
		return "deny"
	}
	return "invalid"
}

// MarshalText writes the verdict's name.
func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// Decision is one rule's result, or the final result of a call.
type Decision struct {
	Verdict  Verdict          `json:"verdict"`
	Rule     string           `json:"rule"`  // "A3", "E1", ...
	Group    string           `json:"group"` // A authorization, I intent, F routing, E evidence, H handoff, C confidentiality, D default
	Reason   string           `json:"reason"`
	Evidence *evidence.Counts `json:"evidence,omitempty"`
}

// Inventory is the trusted system of record the policy engine queries
// directly. No model ever queries it.
type Inventory interface {
	HostExists(name string) bool
	InternalRanges() []netip.Prefix
	IsProtectedIP(a netip.Addr) bool
	IsProtectedAccount(name string) bool
	AccountKind(name string) (kind string, ok bool)
}

// CallCtx is everything Decide may read. It holds no counters: budgets,
// duplicates, and approvals are checked by runstate.Admit under the run lock.
type CallCtx struct {
	RunID       string
	Agent       string
	Op          authz.Op
	TargetArg   string       // name of the target argument, "" if none
	Target      *value.Value // nil for operations without a target
	Args        map[string]value.Value
	PC          label.Label
	Eff         []authz.Cap
	Ctx         *authz.AuthContext
	CtxHash     [32]byte // SHA-256 of the context's signed payload bytes
	CtxVerified bool     // set by the runtime only after the context's signature verified
	Task        *catalog.Task
	Inv         Inventory
	Evidence    *evidence.Store
	Trust       label.TrustTable
	Now         time.Time
}

// Rule is one entry of the rule table.
type Rule struct {
	ID    string
	Group string
	Check func(c *CallCtx) (d Decision, applies bool)
}

// EvidenceMode selects the routing for untrusted targets.
type EvidenceMode uint8

// Evidence modes. EvidenceOn is the specification's E1 and E2. EvidenceOff
// gives untrusted targets no routing rule at all, so D0 denies them (the
// milestone M1 configuration, before evidence rules exist). EvidenceLegacy is
// the old rule used only in the Experiment 3 ablation: an untrusted,
// unprotected address may be blocked, and accounts escalate.
const (
	EvidenceOn EvidenceMode = iota
	EvidenceOff
	EvidenceLegacy
)

// RuleLegacy is the ablation's stand-in for the superseded rule (old P6).
const RuleLegacy = "OLD-P6"

// Config configures an Engine.
type Config struct {
	PolicyVersions []string // supported policy versions
	Mode           EvidenceMode
	Thresholds     evidence.Thresholds
	LoginPath      string
}

// Engine evaluates the rule table.
type Engine struct {
	Rules  []Rule
	cfg    Config
	routes []string
}

// NewEngine builds the rule table for cfg.
func NewEngine(cfg Config) (*Engine, error) {
	if len(cfg.PolicyVersions) == 0 {
		return nil, fmt.Errorf("%w: no supported policy versions", value.ErrConfig)
	}
	if cfg.Mode != EvidenceOff && (cfg.Thresholds.K < 1 || cfg.Thresholds.MinFlows < 1) {
		return nil, fmt.Errorf("%w: evidence thresholds must be positive", value.ErrConfig)
	}
	e := &Engine{cfg: cfg, routes: []string{"F0", "F1", "E1", "E2"}}
	e.Rules = []Rule{
		{"A0", "A", e.ruleA0},
		{"A1", "A", ruleA1},
		{"A2", "A", ruleA2},
		{"A3", "A", ruleA3},
		{"I1", "I", ruleI1},
		{"I2", "I", ruleI2},
		{"I3", "I", ruleI3},
		{"C1", "C", ruleC1},
		{"F0", "F", ruleF0},
		{"F1", "F", ruleF1},
	}
	switch cfg.Mode {
	case EvidenceOn:
		e.Rules = append(e.Rules, Rule{"E1", "E", e.ruleE1}, Rule{"E2", "E", e.ruleE2})
	case EvidenceLegacy:
		e.Rules = append(e.Rules, Rule{RuleLegacy, "E", ruleLegacy})
		e.routes = append(e.routes, RuleLegacy)
	}
	return e, nil
}

// Mode returns the engine's evidence mode.
func (e *Engine) Mode() EvidenceMode { return e.cfg.Mode }

// Thresholds returns the engine's evidence thresholds.
func (e *Engine) Thresholds() evidence.Thresholds { return e.cfg.Thresholds }

// SupportsPolicyVersion reports whether v is a supported policy version.
func (e *Engine) SupportsPolicyVersion(v string) bool {
	return slices.Contains(e.cfg.PolicyVersions, v)
}

// Decide evaluates every applicable rule and returns the strictest verdict.
// A call can be allowed or escalated only if A1 matched a capability and a
// routing rule applied. Other rules only add Deny or Escalate. If either is
// missing, D0 adds Deny. State-dependent rules (A4, A5, F3) run afterward in
// runstate.Admit.
func (e *Engine) Decide(c *CallCtx) (final Decision, all []Decision) {
	for _, r := range e.Rules {
		if d, ok := r.Check(c); ok {
			d.Rule, d.Group = r.ID, r.Group
			all = append(all, d)
		}
	}
	if !allowedBy(all, "A1") || !appliedAny(all, e.routes...) {
		all = append(all, Decision{Verdict: Deny, Rule: "D0", Group: "D", Reason: "no positive authorization or route"})
	}
	return Strictest(all), all
}

func allowedBy(all []Decision, rule string) bool {
	return slices.ContainsFunc(all, func(d Decision) bool { return d.Rule == rule && d.Verdict == Allow })
}

func appliedAny(all []Decision, rules ...string) bool {
	return slices.ContainsFunc(all, func(d Decision) bool { return slices.Contains(rules, d.Rule) })
}

// precedence orders rules for reporting when several share the strictest
// verdict: the most fundamental fact is named first (an invalid context,
// a missing capability, a protected resource), then scope, intent,
// evidence, run-state rules, routes, and the default.
var precedence = []string{"A0", "A1", "A3", "A2", "I1", "I2", "I3", "C1", "E1", "E2", RuleLegacy, "A4", "A5", "F3", "F0", "F1", "D0"}

func rank(rule string) int {
	if i := slices.Index(precedence, rule); i >= 0 {
		return i
	}
	return len(precedence)
}

// Strictest returns the strictest decision; among equals, the one whose rule
// comes first in the reporting precedence.
func Strictest(all []Decision) Decision {
	if len(all) == 0 {
		return Decision{Verdict: Deny, Rule: "D0", Group: "D", Reason: "no rule applied"}
	}
	best := all[0]
	for _, d := range all[1:] {
		if d.Verdict > best.Verdict || d.Verdict == best.Verdict && rank(d.Rule) < rank(best.Rule) {
			best = d
		}
	}
	if best.Verdict == Allow {
		// Report the route that allowed the call.
		for _, d := range all {
			if d.Group == "F" || d.Group == "E" {
				return d
			}
		}
	}
	return best
}

// Has reports whether all contains a decision from rule with verdict v.
func Has(all []Decision, rule string, v Verdict) bool {
	return slices.ContainsFunc(all, func(d Decision) bool { return d.Rule == rule && d.Verdict == v })
}

func pass(reason string) (Decision, bool) { return Decision{Verdict: Allow, Reason: reason}, true }

func deny(reason string) (Decision, bool) { return Decision{Verdict: Deny, Reason: reason}, true }

func notApplicable() (Decision, bool) { return Decision{}, false }

// A0: the context's signature verified, it has not expired, the run ID
// matches, the policy version is supported, and this agent participates.
// Run closure is re-checked in Admit, which may read run state.
func (e *Engine) ruleA0(c *CallCtx) (Decision, bool) {
	ac := c.Ctx
	switch {
	case ac == nil || !c.CtxVerified:
		return deny("authorization context missing or not verified")
	case ac.RunID != c.RunID:
		return deny("context run ID differs")
	case !e.SupportsPolicyVersion(ac.PolicyVersion):
		return deny("unsupported policy version " + ac.PolicyVersion)
	case !ac.HasAgent(c.Agent):
		return deny("agent is not a participant")
	case !c.Now.Before(ac.ExpiresAt):
		return deny("context expired")
	}
	return pass("context valid")
}

// A1: allow if (tool, action) is covered by effective capabilities.
func ruleA1(c *CallCtx) (Decision, bool) {
	m := authz.MatchingCaps(c.Eff, c.Op)
	if len(m) == 0 {
		return deny(c.Op.String() + " not in effective capabilities")
	}
	return pass("matched " + m[0].String())
}

// A2: deny if the target fails strict parsing or the matched scope.
func ruleA2(c *CallCtx) (Decision, bool) {
	if c.Target == nil {
		return notApplicable()
	}
	caps := authz.MatchingCaps(c.Eff, c.Op)
	if len(caps) == 0 {
		return deny("no capability scope to check " + c.Op.String() + " against")
	}
	var last string
	for _, cp := range caps {
		reason := scopeViolation(c, cp.Scope)
		if reason == "" {
			return pass("target " + c.Target.Canonical() + " inside scope " + cp.Scope.String())
		}
		last = reason
	}
	return deny(last)
}

func scopeViolation(c *CallCtx, s authz.Scope) string {
	t := *c.Target
	switch c.Op.Tool {
	case "firewall":
		a, err := value.ParseIPv4(t.Canonical())
		if err != nil || t.Kind() != value.KindIPv4 && t.Kind() != value.KindText {
			return "target is not a strict IPv4 address"
		}
		if s.IPClass == authz.IPClassPublicExternal && !authz.PublicExternal(a, c.Inv.InternalRanges()) {
			return a.String() + " is not a public external address"
		}
	case "accounts":
		name, err := value.ParseAccountID(t.Canonical())
		if err != nil || t.Kind() != value.KindAccountID && t.Kind() != value.KindText {
			return "target is not a strict account ID"
		}
		kind, ok := c.Inv.AccountKind(name)
		if !ok {
			return "account " + name + " does not exist"
		}
		if s.AccountKinds != nil && !slices.Contains(s.AccountKinds, kind) {
			return "account kind " + kind + " outside scope"
		}
	case "logs":
		hosts := []value.Value{t}
		if t.Kind() == value.KindList {
			hosts = t.Elems()
		}
		if len(hosts) == 0 {
			return "no host named"
		}
		for _, h := range hosts {
			name, err := value.ParseHostname(h.Canonical(), c.Inv)
			if err != nil {
				return "host " + value.Truncate(h.Canonical()) + " is not an inventory host"
			}
			if s.Hosts != nil && !slices.Contains(s.Hosts, name) {
				return "host " + name + " outside the task's hosts"
			}
		}
		if w, ok := c.Args["window"]; ok && s.Window != 0 {
			d, ok := w.AsDuration()
			if !ok || d > s.Window {
				return "window " + w.Canonical() + " exceeds " + value.FormatDuration(s.Window)
			}
		}
	default:
		return "unknown target kind for " + c.Op.String()
	}
	return ""
}

// A3: deny if the target is a protected asset, protected account, or
// internal address, whatever its label. Approval cannot override.
func ruleA3(c *CallCtx) (Decision, bool) {
	if c.Target == nil {
		return notApplicable()
	}
	t := c.Target.Canonical()
	switch c.Op.Tool {
	case "firewall":
		a, err := value.ParseIPv4(t)
		if err != nil {
			return notApplicable() // A2 reports the parse failure
		}
		if c.Inv.IsProtectedIP(a) {
			return deny(t + " is a protected asset")
		}
		for _, p := range c.Inv.InternalRanges() {
			if p.Contains(a) {
				return deny(t + " is an internal address (" + p.String() + ")")
			}
		}
	case "accounts":
		if c.Inv.IsProtectedAccount(t) {
			return deny(t + " is a protected account")
		}
	default:
		return notApplicable()
	}
	return pass(t + " is not protected")
}

// I1: deny unless the catalog task, with the analyst's parameters, lists
// (tool, action) for this agent. Checked against the catalog, not the grant.
func ruleI1(c *CallCtx) (Decision, bool) {
	if c.Task == nil || c.Ctx == nil || c.Task.Name != c.Ctx.Task || c.Task.Version != c.Ctx.TaskVersion {
		return deny("catalog task does not match the context")
	}
	ops, err := c.Task.Ops(c.Agent, c.Ctx.Params)
	if err != nil {
		return deny("catalog operations unavailable: " + err.Error())
	}
	if !authz.CoversOp(ops, c.Op) {
		return deny(c.Op.String() + " is not an operation of task " + c.Task.Name + " for " + c.Agent)
	}
	return pass(c.Op.String() + " is a task operation")
}

// I2: deny unless the target carries TaskParam or an untrusted data source.
// Literals, notes, runtime values, and inventory values cannot name targets.
func ruleI2(c *CallCtx) (Decision, bool) {
	if c.Target == nil {
		return notApplicable()
	}
	l := c.Target.Label()
	if l.Has(label.SrcTaskParam) || l.HasUntrusted(c.Trust) {
		return pass("target sources " + strings.Join(l.Strings(), ","))
	}
	return deny("target comes from " + strings.Join(l.Strings(), ",") + ", which cannot name a target")
}

// I3: the action must be a literal from the tool's enum.
func ruleI3(c *CallCtx) (Decision, bool) {
	if !slices.Contains(authz.Actions(c.Op.Tool), c.Op.Action) {
		return deny("action " + value.Truncate(c.Op.Action) + " is not in the enum of " + c.Op.Tool)
	}
	return pass("literal action")
}

// C1: deny a sensitive call if an argument's readers exclude the tool's sink.
func ruleC1(c *CallCtx) (Decision, bool) {
	spec, ok := authz.Spec(c.Op)
	if !ok || !spec.StateChanging {
		return notApplicable()
	}
	for _, name := range sortedArgNames(c.Args) {
		if !c.Args[name].Label().ReadableBy(spec.Sink) {
			return deny("argument " + name + " may not flow to sink " + spec.Sink)
		}
	}
	return pass("every argument readable by " + spec.Sink)
}

// F0: read-only operations are routed (A rules still apply).
func ruleF0(c *CallCtx) (Decision, bool) {
	if c.Op != (authz.Op{Tool: "logs", Action: "read"}) && c.Op != (authz.Op{Tool: "inventory", Action: "read"}) {
		return notApplicable()
	}
	return pass("read-only route")
}

// F1: a target that carries TaskParam and no untrusted source is an analyst
// target and needs no evidence.
func ruleF1(c *CallCtx) (Decision, bool) {
	if c.Target == nil || c.Op.Tool == "logs" {
		return notApplicable()
	}
	l := c.Target.Label()
	if !l.Has(label.SrcTaskParam) || l.HasUntrusted(c.Trust) {
		return notApplicable()
	}
	var params []string
	for _, s := range l.Sources() {
		if s.Kind == label.SrcTaskParam {
			params = append(params, s.Name)
		}
	}
	return pass("analyst target from parameter " + strings.Join(params, ","))
}

func (e *Engine) scope(c *CallCtx) (evidence.TaskScope, bool) {
	if c.Ctx == nil || c.Task == nil {
		return evidence.TaskScope{}, false
	}
	vals, err := c.Task.ParamValues(c.Ctx.Params, nil)
	if err != nil {
		return evidence.TaskScope{}, false
	}
	sc := evidence.TaskScope{To: c.Ctx.IssuedAt, LoginPath: e.cfg.LoginPath}
	if hv, ok := vals["hosts"]; ok {
		for _, h := range hv.Elems() {
			s, _ := h.AsString()
			sc.Hosts = append(sc.Hosts, s)
		}
	}
	w, ok := vals["window"].AsDuration()
	if !ok {
		return evidence.TaskScope{}, false
	}
	sc.From = c.Ctx.IssuedAt.Add(-w)
	return sc, true
}

func untrustedTarget(c *CallCtx) bool {
	return c.Target != nil && c.Target.Label().HasUntrusted(c.Trust)
}

// protectedTarget reports whether A3 removes the target. Evidence is
// consulted only for targets that authorization has not already removed.
func protectedTarget(c *CallCtx) bool {
	d, applies := ruleA3(c)
	return applies && d.Verdict == Deny
}

// E1: evidence for an untrusted IP target of firewall.block.
func (e *Engine) ruleE1(c *CallCtx) (Decision, bool) {
	if c.Op != (authz.Op{Tool: "firewall", Action: "block"}) || !untrustedTarget(c) || protectedTarget(c) {
		return notApplicable()
	}
	a, err := value.ParseIPv4(c.Target.Canonical())
	if err != nil {
		return deny("target is not a strict IPv4 address")
	}
	sc, ok := e.scope(c)
	if !ok || c.Evidence == nil {
		return deny("evidence scope unavailable")
	}
	v, counts := c.Evidence.CorroborateIP(a, sc, e.cfg.Thresholds)
	d := Decision{Evidence: &counts}
	switch v {
	case evidence.EvCorroborated:
		d.Verdict, d.Reason = Allow, fmt.Sprintf("corroborated: %d observations, %d established flows", counts.Observations, counts.Flows)
	case evidence.EvAbsent:
		d.Verdict, d.Reason = Deny, "absent: no trusted observation"
	case evidence.EvConflict:
		d.Verdict, d.Reason = Escalate, "conflict: "+counts.Conflict
	default:
		d.Verdict, d.Reason = Escalate, fmt.Sprintf("insufficient: %d observations, %d established flows", counts.Observations, counts.Flows)
	}
	return d, true
}

// E2: evidence for an untrusted account target of accounts.disable. Absent
// denies; anything else escalates, because disabling an account is high
// impact.
func (e *Engine) ruleE2(c *CallCtx) (Decision, bool) {
	if c.Op != (authz.Op{Tool: "accounts", Action: "disable"}) || !untrustedTarget(c) || protectedTarget(c) {
		return notApplicable()
	}
	sc, ok := e.scope(c)
	if !ok || c.Evidence == nil {
		return deny("evidence scope unavailable")
	}
	v, counts := c.Evidence.CorroborateAccount(c.Target.Canonical(), sc, e.cfg.Thresholds)
	d := Decision{Evidence: &counts}
	if v == evidence.EvAbsent {
		d.Verdict, d.Reason = Deny, "absent: no trusted successful login"
	} else {
		d.Verdict, d.Reason = Escalate, fmt.Sprintf("%s: %d trusted successful logins", v, counts.SuccessLogins)
	}
	return d, true
}

// ruleLegacy is the superseded rule, used only by the Experiment 3 ablation:
// an untrusted block target is allowed (A3 still denies protected ones) and
// an untrusted account target escalates.
func ruleLegacy(c *CallCtx) (Decision, bool) {
	if !untrustedTarget(c) {
		return notApplicable()
	}
	switch c.Op {
	case authz.Op{Tool: "firewall", Action: "block"}:
		return pass("ablation: untrusted and unprotected is allowed")
	case authz.Op{Tool: "accounts", Action: "disable"}:
		return Decision{Verdict: Escalate, Reason: "ablation: accounts escalate"}, true
	}
	return notApplicable()
}

func sortedArgNames(args map[string]value.Value) []string {
	names := make([]string, 0, len(args))
	for k := range args {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}
