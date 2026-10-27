package authz

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"citadel/internal/value"
)

func TestMeet(t *testing.T) {
	a := Scope{Hosts: []string{"web-03", "web-04"}, IPClass: IPClassPublicExternal, MaxCalls: 50, Window: 2 * time.Hour}
	b := Scope{Hosts: []string{"web-04", "web-05"}, ExcludeProtected: true, MaxCalls: 10, Window: time.Hour}
	s, ok := a.Meet(b)
	if !ok || !slices.Equal(s.Hosts, []string{"web-04"}) || s.IPClass != IPClassPublicExternal ||
		!s.ExcludeProtected || s.MaxCalls != 10 || s.Window != time.Hour {
		t.Fatalf("meet: %+v %v", s, ok)
	}
	if _, ok := (Scope{Hosts: []string{"web-03"}}).Meet(Scope{Hosts: []string{"web-04"}}); ok {
		t.Fatal("disjoint hosts must have no meet")
	}
	if _, ok := (Scope{IPClass: "public_external"}).Meet(Scope{IPClass: "other"}); ok {
		t.Fatal("conflicting ip class")
	}
	if _, ok := (Scope{HandoffTo: "responder"}).Meet(Scope{HandoffTo: "other"}); ok {
		t.Fatal("conflicting handoff target")
	}
	if _, ok := (Scope{HandoffTask: "a"}).Meet(Scope{HandoffTask: "b"}); ok {
		t.Fatal("conflicting handoff task")
	}
	if _, ok := (Scope{AccountKinds: []string{"user"}}).Meet(Scope{AccountKinds: []string{"service"}}); ok {
		t.Fatal("disjoint account kinds")
	}
	s, ok = (Scope{}).Meet(Scope{AccountKinds: []string{"user"}, MaxCalls: 5})
	if !ok || !slices.Equal(s.AccountKinds, []string{"user"}) || s.MaxCalls != 5 {
		t.Fatalf("meet with any: %+v", s)
	}
	if s, _ := (Scope{Hosts: []string{}}).Meet(Scope{}); s.Hosts == nil {
		t.Fatal("an empty host set must not widen to any")
	}
}

func TestWithin(t *testing.T) {
	grant := Scope{Hosts: []string{"web-03"}, IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50, Window: time.Hour, AccountKinds: []string{"user"}}
	if !grant.Within(grant) {
		t.Fatal("scope within itself")
	}
	looser := []Scope{
		{Hosts: []string{"web-03"}, ExcludeProtected: true, MaxCalls: 50, Window: time.Hour, AccountKinds: []string{"user"}},
		{IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50, Window: time.Hour, AccountKinds: []string{"user"}},
		{Hosts: []string{"web-03", "web-04"}, IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50, Window: time.Hour, AccountKinds: []string{"user"}},
		{Hosts: []string{"web-03"}, IPClass: IPClassPublicExternal, MaxCalls: 50, Window: time.Hour, AccountKinds: []string{"user"}},
		{Hosts: []string{"web-03"}, IPClass: IPClassPublicExternal, ExcludeProtected: true, Window: time.Hour, AccountKinds: []string{"user"}},
		{Hosts: []string{"web-03"}, IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 51, Window: time.Hour, AccountKinds: []string{"user"}},
		{Hosts: []string{"web-03"}, IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50, AccountKinds: []string{"user"}},
		{Hosts: []string{"web-03"}, IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50, Window: 2 * time.Hour, AccountKinds: []string{"user"}},
		{Hosts: []string{"web-03"}, IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50, Window: time.Hour},
	}
	for i, s := range looser {
		if s.Within(grant) {
			t.Errorf("case %d: looser scope counted as within: %v", i, s)
		}
	}
	if (Scope{HandoffTo: "x"}).Within(Scope{HandoffTo: "y"}) || (Scope{HandoffTask: "x"}).Within(Scope{HandoffTask: "y"}) {
		t.Fatal("handoff fields")
	}
}

func investigatorStatic() []Cap {
	return []Cap{{Tool: "logs", Action: "read"}, HandoffCap("", "")}
}

func responderStatic() []Cap {
	return []Cap{{Tool: "firewall", Action: "block"}, {Tool: "firewall", Action: "allow"},
		{Tool: "accounts", Action: "disable"}, {Tool: "inventory", Action: "read"}}
}

func workedGrant() map[string][]Cap {
	return map[string][]Cap{
		"investigator": {
			{Tool: "logs", Action: "read", Scope: Scope{Hosts: []string{"web-03"}, Window: time.Hour}},
			HandoffCap("responder", "contain_incident"),
		},
		"responder": {
			{Tool: "firewall", Action: "block", Scope: Scope{IPClass: IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50}},
			{Tool: "accounts", Action: "disable", Scope: Scope{AccountKinds: []string{"service", "user"}, ExcludeProtected: true, MaxCalls: 5}},
			{Tool: "inventory", Action: "read"},
		},
	}
}

// The specification's worked example, with allow_account_disable: true.
func TestEffectiveWorkedExample(t *testing.T) {
	g := workedGrant()
	inv := Effective(investigatorStatic(), g["investigator"], g["investigator"], nil)
	if len(inv) != 2 || HasFirewallOrAccountOp(inv) {
		t.Fatalf("investigator effective: %v", inv)
	}
	resp := Effective(responderStatic(), g["responder"], g["responder"], nil)
	if CoversOp(resp, Op{"firewall", "allow"}) {
		t.Fatal("firewall.allow is static but never granted; it must be absent")
	}
	for _, op := range []Op{{"firewall", "block"}, {"accounts", "disable"}, {"inventory", "read"}} {
		if !CoversOp(resp, op) {
			t.Fatalf("responder lacks %s: %v", op, resp)
		}
	}
	// Requested narrows only.
	narrowed := Effective(responderStatic(), g["responder"], g["responder"], CapsFromOps([]Op{{"firewall", "block"}}))
	if len(narrowed) != 1 || narrowed[0].Scope.MaxCalls != 50 || narrowed[0].Scope.IPClass != IPClassPublicExternal {
		t.Fatalf("narrowed: %v", narrowed)
	}
	if got := Effective(responderStatic(), g["responder"], g["responder"], CapsFromOps([]Op{})); len(got) != 0 {
		t.Fatalf("empty request must narrow to nothing: %v", got)
	}
	if CapsFromOps(nil) != nil {
		t.Fatal("nil request must stay nil")
	}
}

func TestCoversAndSubset(t *testing.T) {
	g := workedGrant()["investigator"]
	if !Covers(g, HandoffCap("responder", "contain_incident")) {
		t.Fatal("handoff covered")
	}
	if Covers(g, HandoffCap("other", "contain_incident")) || Covers(g, HandoffCap("responder", "other")) {
		t.Fatal("unlisted handoff covered")
	}
	if !SubsetOf([]Cap{{Tool: "logs", Action: "read", Scope: Scope{Hosts: []string{"web-03"}, Window: 30 * time.Minute}}}, g) {
		t.Fatal("stricter read must be a subset")
	}
	if SubsetOf([]Cap{{Tool: "logs", Action: "read", Scope: Scope{Hosts: []string{"web-04"}, Window: time.Hour}}}, g) {
		t.Fatal("other host must not be a subset")
	}
	if !OpsSubsetOf([]Op{{"logs", "read"}}, g) || OpsSubsetOf([]Op{{"firewall", "block"}}, g) {
		t.Fatal("OpsSubsetOf")
	}
	if len(MatchingCaps(workedGrant()["responder"], Op{"firewall", "block"})) != 1 {
		t.Fatal("MatchingCaps")
	}
}

func validContext() *AuthContext {
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	return &AuthContext{
		V: ContextVersion, RunID: "run_x", Principal: "analyst-1", Role: "soc_analyst",
		Task: "contain_incident", TaskVersion: 1,
		Params:        map[string]json.RawMessage{"hosts": json.RawMessage(`["web-03"]`)},
		Agents:        []string{"investigator", "responder"},
		Grants:        workedGrant(),
		Workflow:      []HandoffGrant{{From: "investigator", To: "responder", Task: "contain_incident", Max: 1}},
		PolicyVersion: "citadel-policy-v1",
		IssuedAt:      now, ExpiresAt: now.Add(30 * time.Minute),
		Budgets: Budgets{MaxSensitiveCalls: 60, SoftUntrustedPC: 20},
	}
}

func TestContextValidate(t *testing.T) {
	if err := validContext().Validate(); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*AuthContext){
		func(a *AuthContext) { a.V = 2 },
		func(a *AuthContext) { a.RunID = "" },
		func(a *AuthContext) { a.Principal = "" },
		func(a *AuthContext) { a.Agents = nil },
		func(a *AuthContext) { a.PolicyVersion = "" },
		func(a *AuthContext) { a.ExpiresAt = a.IssuedAt },
		func(a *AuthContext) { a.Budgets.MaxSensitiveCalls = -1 },
		func(a *AuthContext) { a.Grants["mallory"] = nil },
		func(a *AuthContext) {
			a.Grants["responder"] = []Cap{{Tool: "x", Action: "y", Scope: Scope{Hosts: []string{}}}}
		},
		func(a *AuthContext) {
			a.Grants["responder"] = []Cap{{Tool: "x", Action: "y", Scope: Scope{AccountKinds: []string{}}}}
		},
		func(a *AuthContext) {
			a.Grants["responder"] = []Cap{{Tool: "x", Action: "y", Scope: Scope{MaxCalls: -1}}}
		},
		func(a *AuthContext) {
			a.Grants["responder"] = []Cap{{Tool: "x", Action: "y", Scope: Scope{IPClass: "lan"}}}
		},
		func(a *AuthContext) { a.Workflow = []HandoffGrant{{From: "investigator", To: "mallory", Max: 1}} },
	}
	for i, m := range mutations {
		ac := validContext()
		m(ac)
		if err := ac.Validate(); !errors.Is(err, value.ErrAuthCtx) {
			t.Errorf("mutation %d accepted: %v", i, err)
		}
	}
	ac := validContext()
	if !ac.WorkflowAllows("investigator", "responder", "contain_incident") || ac.WorkflowAllows("responder", "investigator", "contain_incident") {
		t.Fatal("WorkflowAllows")
	}
	if ac.HandoffMax("investigator", "responder", "contain_incident") != 1 || !ac.HasAgent("responder") || ac.HasAgent("x") {
		t.Fatal("HandoffMax/HasAgent")
	}
}

func catalogStub(task string, version int, agent string, _ map[string]json.RawMessage) ([]Cap, bool, error) {
	if task != "contain_incident" || version != 1 {
		return nil, false, nil
	}
	return workedGrant()[agent], true, nil
}

func TestReceiverEffective(t *testing.T) {
	ac := validContext()
	eff, err := ReceiverEffective("responder", responderStatic(), ac, "investigator", "contain_incident", 1, nil, catalogStub)
	if err != nil || CoversOp(eff, Op{"firewall", "allow"}) || !CoversOp(eff, Op{"firewall", "block"}) {
		t.Fatalf("eff %v err %v", eff, err)
	}
	cases := []struct {
		from, task string
		version    int
		req        []Op
		want       error
	}{
		{"investigator", "other_task", 1, nil, value.ErrUnknownTask},
		{"investigator", "contain_incident", 2, nil, value.ErrUnknownTask},
		{"mallory", "contain_incident", 1, nil, value.ErrWorkflow},
		{"investigator", "contain_incident", 1, []Op{{"firewall", "allow"}}, value.ErrExcessGrant},
	}
	for _, c := range cases {
		if _, err := ReceiverEffective("responder", responderStatic(), ac, c.from, c.task, c.version, c.req, catalogStub); !errors.Is(err, c.want) {
			t.Errorf("%+v: got %v want %v", c, err, c.want)
		}
	}
	other := validContext()
	other.Task = "other"
	other.Workflow = append(other.Workflow, HandoffGrant{From: "investigator", To: "responder", Task: "contain_incident", Max: 1})
	if _, err := ReceiverEffective("responder", responderStatic(), other, "investigator", "contain_incident", 1, nil, catalogStub); !errors.Is(err, value.ErrWorkflow) {
		t.Fatalf("task mismatch: %v", err)
	}
	failing := func(string, int, string, map[string]json.RawMessage) ([]Cap, bool, error) {
		return nil, false, errors.New("bad params")
	}
	if _, err := ReceiverEffective("responder", nil, ac, "investigator", "contain_incident", 1, nil, failing); !errors.Is(err, value.ErrUnknownTask) {
		t.Fatalf("catalog error: %v", err)
	}
}

func TestToolSpecs(t *testing.T) {
	for _, op := range []Op{{"logs", "read"}, {"inventory", "read"}, {"firewall", "block"}, {"firewall", "allow"}, {"accounts", "disable"}} {
		s, ok := Spec(op)
		if !ok || s.Op != op {
			t.Fatalf("missing spec %s", op)
		}
		if !slices.Contains(Actions(op.Tool), op.Action) {
			t.Fatalf("action %s not in enum", op)
		}
	}
	if _, ok := Spec(Op{"handoff", "request"}); ok {
		t.Fatal("handoff is not a callable tool")
	}
	if Actions("nope") != nil || !slices.Equal(Actions("handoff"), []string{"request"}) {
		t.Fatal("Actions")
	}
	fw, _ := Spec(Op{"firewall", "block"})
	if fw.TargetArg() != "ip" || !fw.StateChanging || !IsStateChanging(Op{"accounts", "disable"}) || IsStateChanging(Op{"logs", "read"}) {
		t.Fatal("firewall spec")
	}
	lr, _ := Spec(Op{"logs", "read"})
	a, ok := lr.Arg("host")
	if !ok || !a.Accepts(value.ListOf(value.Scalar(value.KindHostname))) || a.Accepts(value.Scalar(value.KindIPv4)) {
		t.Fatal("logs.read host types")
	}
	if _, ok := lr.Arg("nope"); ok {
		t.Fatal("unknown arg")
	}
	inv, _ := Spec(Op{"inventory", "read"})
	if inv.TargetArg() != "" || len(inv.OutputByKey) != 4 {
		t.Fatal("inventory spec")
	}
	if (Cap{Tool: "firewall", Action: "block", Scope: Scope{Hosts: []string{"a"}, Window: time.Hour, IPClass: "public_external", AccountKinds: []string{"user"}, ExcludeProtected: true, HandoffTo: "r", HandoffTask: "t", MaxCalls: 3}}).String() == "" {
		t.Fatal("Cap.String")
	}
	if (Scope{}).String() != "" {
		t.Fatal("empty scope string")
	}
}
