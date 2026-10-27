package policy_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/evidence"
	"citadel/internal/label"
	"citadel/internal/policy"
	"citadel/internal/tools"
	"citadel/internal/value"
)

var now = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

type world struct {
	t    *testing.T
	task *catalog.Task
	env  *tools.Env
	ac   *authz.AuthContext
	eng  *policy.Engine
}

func loadInventory(t *testing.T) tools.InventoryData {
	b, err := os.ReadFile("../../configs/inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d tools.InventoryData
	if err := value.DecodeYAMLStrict(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

type option func(*tools.Spec, map[string]json.RawMessage)

func params(kv ...string) option {
	return func(_ *tools.Spec, p map[string]json.RawMessage) {
		for i := 0; i < len(kv); i += 2 {
			p[kv[i]] = json.RawMessage(kv[i+1])
		}
	}
}

func records(access []evidence.AccessRecord, flows []evidence.FlowRecord) option {
	return func(s *tools.Spec, _ map[string]json.RawMessage) {
		s.Access = append(s.Access, access...)
		s.Flows = append(s.Flows, flows...)
	}
}

func inventory(f func(*tools.InventoryData)) option {
	return func(s *tools.Spec, _ map[string]json.RawMessage) { f(&s.Inventory) }
}

func newWorld(t *testing.T, mode policy.EvidenceMode, opts ...option) *world {
	t.Helper()
	cat, err := catalog.Load("../../configs/catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	task, _ := cat.Lookup("contain_incident", 1)
	spec := tools.Spec{Inventory: loadInventory(t)}
	raw := map[string]json.RawMessage{"hosts": json.RawMessage(`["web-03"]`), "window": json.RawMessage(`"1h"`), "allow_account_disable": json.RawMessage("true")}
	for _, o := range opts {
		o(&spec, raw)
	}
	env, err := tools.NewEnv(spec, value.NewManualClock(now))
	if err != nil {
		t.Fatal(err)
	}
	p, err := task.ValidateParams(raw, env.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	ac := &authz.AuthContext{V: 1, RunID: "run_p", Principal: "analyst-1", Role: "soc_analyst", Task: task.Name, TaskVersion: 1,
		Params: p, Agents: task.AgentNames(), Grants: map[string][]authz.Cap{}, Workflow: task.Workflow(),
		PolicyVersion: "citadel-policy-v1", IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute),
		Budgets: authz.Budgets{MaxSensitiveCalls: 60, SoftUntrustedPC: 20}}
	for _, a := range task.AgentNames() {
		ac.Grants[a], _ = task.Ops(a, p)
	}
	eng, err := policy.NewEngine(policy.Config{PolicyVersions: []string{"citadel-policy-v1"}, Mode: mode,
		Thresholds: evidence.Thresholds{K: 5, MinFlows: 1}, LoginPath: "/login"})
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, task: task, env: env, ac: ac, eng: eng}
}

var static = map[string][]authz.Cap{
	"investigator": {{Tool: "logs", Action: "read"}, {Tool: "handoff", Action: "request"}},
	"responder":    {{Tool: "firewall", Action: "block"}, {Tool: "firewall", Action: "allow"}, {Tool: "accounts", Action: "disable"}, {Tool: "inventory", Action: "read"}},
}

func (w *world) call(agent string, op authz.Op, target *value.Value, extra map[string]value.Value) *policy.CallCtx {
	ops, _ := w.task.Ops(agent, w.ac.Params)
	c := &policy.CallCtx{RunID: w.ac.RunID, Agent: agent, Op: op, Args: map[string]value.Value{},
		PC: label.New(label.Runtime()), Eff: authz.Effective(static[agent], w.ac.Grants[agent], ops, nil),
		Ctx: w.ac, CtxHash: [32]byte{1}, CtxVerified: true, Task: w.task, Inv: w.env.Inventory(),
		Evidence: w.env.Evidence(), Trust: label.DefaultTrust(), Now: now}
	if spec, ok := authz.Spec(op); ok && target != nil {
		if spec.TargetArg() == "" {
			c.Args["host"] = *target // logs.read: the host is a scope argument, not a target
		} else {
			c.TargetArg = spec.TargetArg()
			c.Target = target
			c.Args[c.TargetArg] = *target
		}
	}
	for k, v := range extra {
		c.Args[k] = v
	}
	return c
}

func (w *world) decide(c *policy.CallCtx) (policy.Decision, []policy.Decision) {
	return w.eng.Decide(c)
}

var (
	block   = authz.Op{Tool: "firewall", Action: "block"}
	allowOp = authz.Op{Tool: "firewall", Action: "allow"}
	disable = authz.Op{Tool: "accounts", Action: "disable"}
	readOp  = authz.Op{Tool: "logs", Action: "read"}
)

func ip(s string, srcs ...label.Source) *value.Value {
	a, err := value.ParseIPv4(s)
	if err != nil {
		panic(err)
	}
	v, _ := value.IPv4(a, label.New(srcs...))
	return &v
}

func acct(s string, srcs ...label.Source) *value.Value {
	v, err := value.AccountID(s, label.New(srcs...))
	if err != nil {
		panic(err)
	}
	return &v
}

var (
	param   = label.TaskParam("confirmed_ips")
	qllm    = label.QLLM("investigator")
	peer    = label.Peer("investigator", "env1")
	literal = label.PlannerLiteral("responder")
)

// failed returns n failed logins from addr to host, one minute apart.
func failed(addr, host string, n int, prefix string) []evidence.AccessRecord {
	out := make([]evidence.AccessRecord, n)
	for i := range out {
		out[i] = evidence.AccessRecord{EventID: fmt.Sprintf("%s-%d", prefix, i), TS: now.Add(-time.Duration(30-i) * time.Minute),
			Host: host, ClientIP: netip.MustParseAddr(addr), Status: 401, AuthResult: "fail",
			SensorID: "web-access", PipelineID: "web-logs", Path: "/login", AttemptedUser: "jdoe"}
	}
	return out
}

func flow(addr, host, state, id string) evidence.FlowRecord {
	return evidence.FlowRecord{FlowID: id, TS: now.Add(-20 * time.Minute), SrcIP: netip.MustParseAddr(addr), DstHost: host,
		State: state, SensorID: "net-flows", PipelineID: "netflow"}
}

func expect(t *testing.T, name string, final policy.Decision, all []policy.Decision, v policy.Verdict, rule string) {
	t.Helper()
	if final.Verdict != v || !policy.Has(all, rule, v) {
		t.Errorf("%s: final %s/%s, want %s with %s among %v", name, final.Verdict, final.Rule, v, rule, all)
	}
}

func TestA0_ContextValid(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	c := w.call("responder", block, ip("203.0.113.7", param), nil)
	final, all := w.decide(c)
	expect(t, "valid context", final, all, policy.Allow, "A0")
	cases := map[string]func(*policy.CallCtx){
		"unverified":        func(c *policy.CallCtx) { c.CtxVerified = false },
		"expired":           func(c *policy.CallCtx) { c.Now = w.ac.ExpiresAt },
		"run differs":       func(c *policy.CallCtx) { c.RunID = "run_other" },
		"policy version":    func(c *policy.CallCtx) { cp := *w.ac; cp.PolicyVersion = "v0"; c.Ctx = &cp },
		"not a participant": func(c *policy.CallCtx) { c.Agent = "mallory" },
		"no context":        func(c *policy.CallCtx) { c.Ctx = nil },
	}
	for name, m := range cases {
		c := w.call("responder", block, ip("203.0.113.7", param), nil)
		m(c)
		final, all := w.decide(c)
		expect(t, name, final, all, policy.Deny, "A0")
	}
}

func TestA1_Capability(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	final, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil))
	expect(t, "responder block", final, all, policy.Allow, "A1")
	final, all = w.decide(w.call("responder", allowOp, ip("203.0.113.7", param), nil))
	expect(t, "responder allow", final, all, policy.Deny, "A1")
	if final.Rule != "A1" {
		t.Errorf("firewall.allow reported as %s", final.Rule)
	}
	final, all = w.decide(w.call("investigator", block, ip("203.0.113.7", param), nil))
	expect(t, "investigator block", final, all, policy.Deny, "A1")
}

func TestA2_ResourceScope(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	final, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil))
	expect(t, "public external", final, all, policy.Allow, "A2")
	_, all = w.decide(w.call("responder", block, ip("10.1.2.3", param), nil))
	if !policy.Has(all, "A2", policy.Deny) {
		t.Error("10.1.2.3 internal must be denied by A2")
	}
	text, _ := value.Text("203.0.113.007", label.New(param))
	final, all = w.decide(w.call("responder", block, &text, nil))
	expect(t, "leading zero", final, all, policy.Deny, "A2")
	host, _ := value.Hostname("web-04", nil, label.New(label.TaskParam("hosts")))
	win, _ := value.Duration(time.Hour, label.New(label.TaskParam("window")))
	final, all = w.decide(w.call("investigator", readOp, &host, map[string]value.Value{"window": win}))
	expect(t, "logs.read on web-04", final, all, policy.Deny, "A2")
	long, _ := value.Duration(2*time.Hour, label.New(label.TaskParam("window")))
	h3, _ := value.Hostname("web-03", nil, label.New(label.TaskParam("hosts")))
	final, all = w.decide(w.call("investigator", readOp, &h3, map[string]value.Value{"window": long}))
	expect(t, "window too long", final, all, policy.Deny, "A2")
	final, all = w.decide(w.call("responder", disable, acct("ghost", peer), nil))
	expect(t, "unknown account", final, all, policy.Deny, "A2")
	final, all = w.decide(w.call("responder", disable, acct("admin-alice", peer), nil))
	expect(t, "admin kind outside scope", final, all, policy.Deny, "A2")
	empty, _ := value.List(value.Scalar(value.KindHostname), nil, label.New(label.TaskParam("hosts")))
	final, all = w.decide(w.call("investigator", readOp, &empty, map[string]value.Value{"window": win}))
	expect(t, "no host", final, all, policy.Deny, "A2")
	badAcct, _ := value.Text("Not An Account", label.New(peer))
	final, all = w.decide(w.call("responder", disable, &badAcct, nil))
	expect(t, "bad account", final, all, policy.Deny, "A2")
	inv := w.call("investigator", block, ip("203.0.113.7", param), nil)
	final, all = w.decide(inv)
	expect(t, "no scope", final, all, policy.Deny, "A2")
}

func TestA3_Protected(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	final, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil))
	expect(t, "unprotected", final, all, policy.Allow, "A3")
	final, all = w.decide(w.call("responder", block, ip("10.0.0.53", qllm), nil))
	expect(t, "10.0.0.53", final, all, policy.Deny, "A3")
	if final.Rule != "A3" {
		t.Errorf("protected asset reported as %s", final.Rule)
	}
	final, all = w.decide(w.call("responder", disable, acct("admin-alice", label.TaskParam("accounts")), nil))
	expect(t, "admin-alice as analyst parameter", final, all, policy.Deny, "A3")
	final, all = w.decide(w.call("responder", disable, acct("svc-backup", label.TaskParam("accounts")), nil))
	expect(t, "unprotected account", final, all, policy.Allow, "A3")
	text, _ := value.Text("not an ip", label.New(qllm))
	if _, all := w.decide(w.call("responder", block, &text, nil)); policy.Has(all, "A3", policy.Deny) || policy.Has(all, "A3", policy.Allow) {
		t.Error("A3 must leave an unparsable target to A2")
	}
}

func TestI1_TaskOperation(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	final, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil))
	expect(t, "block under contain_incident", final, all, policy.Allow, "I1")
	// T-A5's runtime case: a validly signed context that wrongly grants
	// accounts.disable while allow_account_disable is false.
	w = newWorld(t, policy.EvidenceOn, params("allow_account_disable", "false"))
	w.ac.Grants["responder"] = append(w.ac.Grants["responder"], authz.Cap{Tool: "accounts", Action: "disable"})
	c := w.call("responder", disable, acct("svc-backup", label.TaskParam("accounts")), nil)
	c.Eff = authz.Intersect(static["responder"], w.ac.Grants["responder"]) // a runtime that trusted the grant alone
	final, all = w.decide(c)
	expect(t, "context grants too much", final, all, policy.Deny, "I1")
	c.Task = nil
	final, all = w.decide(c)
	expect(t, "no catalog task", final, all, policy.Deny, "I1")
}

func TestI2_TargetAuthority(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	final, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil))
	expect(t, "analyst-confirmed IP", final, all, policy.Allow, "I2")
	_, all = w.decide(w.call("responder", block, ip("198.51.100.23", qllm), nil))
	if !policy.Has(all, "I2", policy.Allow) {
		t.Error("IP from extracted data must pass I2")
	}
	final, all = w.decide(w.call("responder", disable, acct("jdoe", literal), nil))
	expect(t, "literal jdoe", final, all, policy.Deny, "I2")
	final, all = w.decide(w.call("responder", block, ip("203.0.113.7", label.Tool("inventory.read")), nil))
	expect(t, "target read from inventory", final, all, policy.Deny, "I2")
	final, all = w.decide(w.call("responder", block, ip("203.0.113.7", label.UserNote()), nil))
	expect(t, "target from the note", final, all, policy.Deny, "I2")
}

func TestI3_ActionLiteral(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	final, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil))
	expect(t, "block", final, all, policy.Allow, "I3")
	final, all = w.decide(w.call("responder", authz.Op{Tool: "firewall", Action: "{\"op\":\"ref\"}"}, ip("203.0.113.7", param), nil))
	expect(t, "action not in enum", final, all, policy.Deny, "I3")
}

func TestF0_ReadOnlyRoute(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	h3, _ := value.Hostname("web-03", nil, label.New(label.TaskParam("hosts")))
	win, _ := value.Duration(time.Hour, label.New(label.TaskParam("window")))
	final, all := w.decide(w.call("investigator", readOp, &h3, map[string]value.Value{"window": win}))
	expect(t, "logs.read web-03", final, all, policy.Allow, "F0")
	if final.Rule != "F0" {
		t.Errorf("route reported as %s", final.Rule)
	}
	h4, _ := value.Hostname("web-04", nil, label.New(label.TaskParam("hosts")))
	final, all = w.decide(w.call("investigator", readOp, &h4, map[string]value.Value{"window": win}))
	if final.Verdict != policy.Deny || !policy.Has(all, "F0", policy.Allow) || !policy.Has(all, "A2", policy.Deny) {
		t.Errorf("web-04: A2 must deny despite F0: %v", all)
	}
	key := value.Enum("protected_ips", label.New(literal))
	c := w.call("responder", authz.Op{Tool: "inventory", Action: "read"}, nil, map[string]value.Value{"key": key})
	final, all = w.decide(c)
	expect(t, "inventory.read", final, all, policy.Allow, "F0")
}

func TestF1_AnalystTarget(t *testing.T) {
	// The confirmed IP has one observation: F1 skips evidence.
	w := newWorld(t, policy.EvidenceOn, params("confirmed_ips", `["203.0.113.7"]`),
		records(failed("203.0.113.7", "web-03", 1, "f1"), nil))
	final, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil))
	expect(t, "confirmed IP", final, all, policy.Allow, "F1")
	if final.Rule != "F1" {
		t.Errorf("reported as %s", final.Rule)
	}
	final, all = w.decide(w.call("responder", block, ip("10.0.0.53", param), nil))
	if final.Verdict != policy.Deny || final.Rule != "A3" || !policy.Has(all, "F1", policy.Allow) {
		t.Errorf("protected confirmed IP: A3 must win over F1: %v", all)
	}
	mixed := ip("203.0.113.7", param, qllm)
	if _, all := w.decide(w.call("responder", block, mixed, nil)); policy.Has(all, "F1", policy.Allow) {
		t.Error("F1 must not route a target with an untrusted source")
	}
}

func corroborated(addr string) option {
	return records(failed(addr, "web-03", 12, "c-"+addr), []evidence.FlowRecord{flow(addr, "web-03", "established", "fl-"+addr)})
}

func TestE1_IPEvidence(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn, corroborated("198.51.100.23"))
	final, all := w.decide(w.call("responder", block, ip("198.51.100.23", qllm), nil))
	expect(t, "corroborated attacker IP", final, all, policy.Allow, "E1")
	if final.Evidence == nil || final.Evidence.Observations != 12 || final.Evidence.Flows != 1 {
		t.Errorf("evidence counts %+v", final.Evidence)
	}
	final, all = w.decide(w.call("responder", block, ip("192.0.2.44", qllm), nil))
	expect(t, "IP only in a User-Agent", final, all, policy.Deny, "E1")
	w = newWorld(t, policy.EvidenceOn, corroborated("198.51.100.200"),
		inventory(func(d *tools.InventoryData) { d.SharedIPs = []string{"198.51.100.200"} }))
	final, all = w.decide(w.call("responder", block, ip("198.51.100.200", qllm), nil))
	expect(t, "shared address", final, all, policy.Escalate, "E1")
}

func TestE2_AccountEvidence(t *testing.T) {
	login := evidence.AccessRecord{EventID: "s1", TS: now.Add(-5 * time.Minute), Host: "web-03", ClientIP: netip.MustParseAddr("198.51.100.23"),
		Status: 200, AuthResult: "success", AuthPrincipal: "svc-backup", SensorID: "web-access", PipelineID: "web-logs"}
	w := newWorld(t, policy.EvidenceOn, corroborated("198.51.100.23"), records([]evidence.AccessRecord{login}, nil))
	final, all := w.decide(w.call("responder", disable, acct("svc-backup", qllm), nil))
	expect(t, "trusted login from a corroborated IP", final, all, policy.Escalate, "E2")
	final, all = w.decide(w.call("responder", disable, acct("jdoe", qllm), nil))
	expect(t, "name only in attempted_user", final, all, policy.Deny, "E2")
}

func TestC1_Confidentiality(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	a, _ := value.ParseIPv4("203.0.113.7")
	internal, _ := value.IPv4(a, label.NewRestricted([]string{"internal"}, param))
	final, all := w.decide(w.call("responder", block, &internal, nil))
	expect(t, "internal data to an internal sink", final, all, policy.Allow, "C1")
	secret, _ := value.IPv4(a, label.NewRestricted([]string{"analyst-1"}, param))
	final, all = w.decide(w.call("responder", block, &secret, nil))
	expect(t, "readers exclude the sink", final, all, policy.Deny, "C1")
}

func TestD0_Default(t *testing.T) {
	// With evidence rules off (the M1 configuration), an untrusted target has
	// no routing rule.
	w := newWorld(t, policy.EvidenceOff)
	final, all := w.decide(w.call("responder", block, ip("192.0.2.44", qllm), nil))
	expect(t, "untrusted target with no route", final, all, policy.Deny, "D0")
	if final.Rule != "D0" {
		t.Errorf("reported as %s", final.Rule)
	}
	// firewall.allow has no routing rule for an untrusted target.
	w = newWorld(t, policy.EvidenceOn)
	_, all = w.decide(w.call("responder", allowOp, ip("198.51.100.23", qllm), nil))
	if !policy.Has(all, "D0", policy.Deny) {
		t.Error("a tool with no routing rule must be denied by D0")
	}
	if got := policy.Strictest(nil); got.Verdict != policy.Deny || got.Rule != "D0" {
		t.Error("no decisions must deny")
	}
}

func TestLegacyAblationRule(t *testing.T) {
	w := newWorld(t, policy.EvidenceLegacy)
	final, all := w.decide(w.call("responder", block, ip("192.0.2.44", qllm), nil))
	expect(t, "fabricated IP under the old rule", final, all, policy.Allow, policy.RuleLegacy)
	final, all = w.decide(w.call("responder", disable, acct("jdoe", qllm), nil))
	expect(t, "account under the old rule", final, all, policy.Escalate, policy.RuleLegacy)
	final, _ = w.decide(w.call("responder", block, ip("10.0.0.53", qllm), nil))
	if final.Rule != "A3" {
		t.Errorf("protected must still be denied: %s", final.Rule)
	}
	if _, all := w.decide(w.call("responder", block, ip("203.0.113.7", param), nil)); policy.Has(all, policy.RuleLegacy, policy.Allow) {
		t.Error("legacy rule applies only to untrusted targets")
	}
	if _, all := w.decide(w.call("responder", allowOp, ip("203.0.113.7", qllm), nil)); policy.Has(all, policy.RuleLegacy, policy.Allow) {
		t.Error("legacy rule covers block and disable only")
	}
	if w.eng.Mode() != policy.EvidenceLegacy || w.eng.Thresholds().K != 5 || !w.eng.SupportsPolicyVersion("citadel-policy-v1") {
		t.Error("engine accessors")
	}
}

func TestEngineConfig(t *testing.T) {
	if _, err := policy.NewEngine(policy.Config{}); err == nil {
		t.Error("no policy versions")
	}
	if _, err := policy.NewEngine(policy.Config{PolicyVersions: []string{"v"}, Mode: policy.EvidenceOn}); err == nil {
		t.Error("zero thresholds")
	}
	if _, err := policy.NewEngine(policy.Config{PolicyVersions: []string{"v"}, Mode: policy.EvidenceOff}); err != nil {
		t.Error("evidence off needs no thresholds")
	}
	for _, v := range []policy.Verdict{policy.Allow, policy.Escalate, policy.Deny, 9} {
		if b, _ := v.MarshalText(); string(b) != v.String() {
			t.Error("verdict text")
		}
	}
	for _, s := range []policy.ApprovalState{policy.Pending, policy.Granted, policy.Used, policy.Rejected, policy.Expired, 9} {
		if b, _ := s.MarshalText(); string(b) != s.String() {
			t.Error("state text")
		}
	}
}

func TestEvidenceScopeUnavailable(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn)
	c := w.call("responder", block, ip("198.51.100.23", qllm), nil)
	c.Evidence = nil
	if final, all := w.decide(c); final.Verdict != policy.Deny || !policy.Has(all, "E1", policy.Deny) {
		t.Error("E1 without an evidence store must deny")
	}
	d := w.call("responder", disable, acct("jdoe", qllm), nil)
	d.Evidence = nil
	if final, all := w.decide(d); final.Verdict != policy.Deny || !policy.Has(all, "E2", policy.Deny) {
		t.Error("E2 without an evidence store must deny")
	}
	text, _ := value.Text("not-an-ip", label.New(qllm))
	if _, all := w.decide(w.call("responder", block, &text, nil)); !policy.Has(all, "E1", policy.Deny) {
		t.Error("E1 must deny a non-address")
	}
}

type approvalVector struct {
	RunID         string            `json:"run_id"`
	Principal     string            `json:"principal"`
	CtxHash       string            `json:"ctx_hash_hex"`
	PolicyVersion string            `json:"policy_version"`
	Agent         string            `json:"agent"`
	Tool          string            `json:"tool"`
	Action        string            `json:"action"`
	Args          map[string]string `json:"args"`
	Encoding      string            `json:"encoding_hex"`
	Key           string            `json:"key_hex"`
}

func loadApprovalVectors(t testing.TB) []approvalVector {
	b, err := os.ReadFile("../../testdata/vectors/approval_keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []approvalVector
	if err := json.Unmarshal(b, &vs); err != nil || len(vs) == 0 {
		t.Fatal(err)
	}
	return vs
}

func (v approvalVector) fields() policy.ApprovalFields {
	f := policy.ApprovalFields{RunID: v.RunID, Principal: v.Principal, PolicyVersion: v.PolicyVersion, Agent: v.Agent, Tool: v.Tool, Action: v.Action, Args: v.Args}
	h, _ := hex.DecodeString(v.CtxHash)
	copy(f.CtxHash[:], h)
	return f
}

// KeyFor golden vectors: the encoding and key match an independent
// implementation of the documented format, and distinct inputs differ.
func TestApprovalKeyGoldenVectors(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range loadApprovalVectors(t) {
		f := v.fields()
		if got := hex.EncodeToString(policy.EncodeApproval(f)); got != v.Encoding {
			t.Errorf("encoding %s: got %s", v.Key, got)
		}
		if k := policy.KeyForFields(f); k.String() != v.Key {
			t.Errorf("key: got %s want %s", k, v.Key)
		}
		if seen[v.Key] {
			t.Errorf("collision %s", v.Key)
		}
		seen[v.Key] = true
		back, ok := policy.DecodeApproval(policy.EncodeApproval(f))
		if !ok || policy.KeyForFields(back) != policy.KeyForFields(f) {
			t.Errorf("round trip failed for %s", v.Key)
		}
	}
	w := newWorld(t, policy.EvidenceOn)
	c := w.call("responder", block, ip("203.0.113.7", param), nil)
	f := policy.FieldsOf(c)
	if policy.KeyFor(c) != policy.KeyForFields(f) || f.Args["ip"] != "203.0.113.7" || f.Principal != "analyst-1" {
		t.Error("KeyFor must hash the call's fields")
	}
	if txt, _ := policy.KeyFor(c).MarshalText(); string(txt) != policy.KeyFor(c).String() {
		t.Error("MarshalText")
	}
	for _, bad := range [][]byte{nil, []byte("citadel-approval-v1"), append([]byte(policy.ApprovalPrefix), 0, 0, 0, 9)} {
		if _, ok := policy.DecodeApproval(bad); ok {
			t.Errorf("decoded garbage %x", bad)
		}
	}
}

func FuzzApprovalKeyEncoding(f *testing.F) {
	for _, v := range loadApprovalVectors(f) {
		f.Add(v.RunID, v.Principal, v.Agent, v.Tool, v.Action, "ip", v.Args["ip"], "account", v.Args["account"])
	}
	f.Fuzz(func(t *testing.T, run, principal, agent, tool, action, k1, v1, k2, v2 string) {
		in := policy.ApprovalFields{RunID: run, Principal: principal, PolicyVersion: "citadel-policy-v1", Agent: agent, Tool: tool, Action: action,
			Args: map[string]string{k1: v1, k2: v2}}
		enc := policy.EncodeApproval(in)
		out, ok := policy.DecodeApproval(enc)
		if !ok {
			t.Fatalf("encoding not decodable: %x", enc)
		}
		if out.RunID != in.RunID || out.Principal != in.Principal || out.Agent != in.Agent || out.Tool != in.Tool || out.Action != in.Action ||
			len(out.Args) != len(in.Args) {
			t.Fatalf("decode mismatch: %+v vs %+v", out, in)
		}
		for k, v := range in.Args {
			if out.Args[k] != v {
				t.Fatalf("arg %q mismatch", k)
			}
		}
		if string(policy.EncodeApproval(out)) != string(enc) {
			t.Fatal("re-encoding differs: the encoding is not canonical")
		}
	})
}

// A3 negative for a protected asset outside every internal range: the
// protected-asset list alone must deny it, even as an analyst parameter.
func TestA3_ProtectedPublicAsset(t *testing.T) {
	w := newWorld(t, policy.EvidenceOn, inventory(func(d *tools.InventoryData) { d.ProtectedIPs = append(d.ProtectedIPs, "198.51.100.77") }))
	final, all := w.decide(w.call("responder", block, ip("198.51.100.77", param), nil))
	if final.Verdict != policy.Deny || final.Rule != "A3" || policy.Has(all, "A2", policy.Deny) {
		t.Fatalf("protected public asset: %+v %v", final, all)
	}
}

// Experiment 4: the Go layer's per-call decision cost.
func BenchmarkDecide(b *testing.B) {
	t := &testing.T{}
	w := newWorld(t, policy.EvidenceOn, corroborated("198.51.100.23"))
	c := w.call("responder", block, ip("198.51.100.23", qllm), nil)
	for b.Loop() {
		w.eng.Decide(c)
	}
}
