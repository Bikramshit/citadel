package plan_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/llm"
	"citadel/internal/plan"
	"citadel/internal/value"
)

type hosts struct{}

func (hosts) HostExists(h string) bool { return h == "web-03" || h == "web-04" }

func env(t *testing.T, agent string, allowDisable bool) plan.Env {
	t.Helper()
	cat, err := catalog.Load("../../configs/catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	task, _ := cat.Lookup("contain_incident", 1)
	params := map[string]json.RawMessage{"hosts": json.RawMessage(`["web-03"]`), "window": json.RawMessage(`"1h"`),
		"confirmed_ips": json.RawMessage(`["203.0.113.7"]`), "allow_account_disable": json.RawMessage(map[bool]string{true: "true", false: "false"}[allowDisable])}
	ac := &authz.AuthContext{V: 1, RunID: "run_p", Principal: "a", Role: "soc_analyst", Task: task.Name, TaskVersion: 1, Params: params,
		Agents: task.AgentNames(), Grants: map[string][]authz.Cap{}, Workflow: task.Workflow(), PolicyVersion: "v",
		IssuedAt: time.Unix(0, 0), ExpiresAt: time.Unix(3600, 0)}
	for _, a := range task.AgentNames() {
		ac.Grants[a], _ = task.Ops(a, params)
	}
	eff := ac.Grants[agent]
	data := map[string]plan.DataBinding{}
	if agent == "responder" {
		data["ips"] = plan.DataBinding{Type: value.ListOf(value.Scalar(value.KindIPv4)), Untrusted: true}
		data["accounts"] = plan.DataBinding{Type: value.ListOf(value.Scalar(value.KindAccountID)), Untrusted: true}
	}
	hs := map[string]value.Type{}
	for _, n := range task.DataNames() {
		hs[n], _ = task.DataType(n)
	}
	return plan.Env{Agent: agent, Eff: eff, Task: task, Ctx: ac, Data: data, Schemas: llm.Schemas(), HandoffSchema: hs, Hosts: hosts{}}
}

func decode(t *testing.T, s string) plan.Plan {
	t.Helper()
	p, err := plan.Decode([]byte(s))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}

func rules(err error) []string {
	var rej *plan.RejectError
	if errors.As(err, &rej) {
		return rej.Rules()
	}
	return nil
}

const responderPlan = `{"agent":"responder","steps":[
 {"op":"for_each","var":"ip","over":{"op":"param","param":"confirmed_ips"},"body":[
   {"op":"call","expr":{"op":"call","tool":"firewall","action":"block","args":{"ip":{"op":"ref","ref":"ip"}}}}]},
 {"op":"for_each","var":"ip","over":{"op":"ref","ref":"ips"},"body":[
   {"op":"call","expr":{"op":"call","tool":"firewall","action":"block","args":{"ip":{"op":"ref","ref":"ip"}}}}]},
 {"op":"for_each","var":"acct","over":{"op":"ref","ref":"accounts"},"body":[
   {"op":"call","expr":{"op":"call","tool":"accounts","action":"disable","args":{"account":{"op":"ref","ref":"acct"}}}}]}
]}`

// The specification's demo plan passes the static check.
func TestStaticCheckAcceptsSpecificationPlan(t *testing.T) {
	if err := plan.StaticCheck(decode(t, responderPlan), env(t, "responder", true)); err != nil {
		t.Fatal(err)
	}
	inv := `{"agent":"investigator","steps":[
	 {"op":"let","var":"recs","expr":{"op":"call","tool":"logs","action":"read","args":{"host":{"op":"param","param":"hosts"},"window":{"op":"param","param":"window"}}}},
	 {"op":"let","var":"ioc","expr":{"op":"extract","schema":"IOCList","inputs":[{"op":"ref","ref":"recs"}],"ask":"attackers"}},
	 {"op":"if","cond":{"op":"not_empty","left":{"op":"param","param":"hosts"}},"body":[
	   {"op":"let","var":"known","expr":{"op":"call","tool":"logs","action":"read","args":{"host":{"op":"lit","lit":"web-03"},"window":{"op":"lit","lit":"30m"}}}}]},
	 {"op":"handoff","handoff":{"to":"responder","task":"contain_incident","data":{"ips":{"op":"field","of":{"op":"ref","ref":"ioc"},"field":"ips"}}}}
	]}`
	if err := plan.StaticCheck(decode(t, inv), env(t, "investigator", true)); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	bad := []string{
		`{"agent":"responder","steps":[],"note":"x"}`,
		`{"agent":"responder","steps":[{"op":"call","expr":{"op":"call","tool":"firewall","action":{"op":"ref","ref":"a"}}}]}`,
		`{"agent":"responder","agent":"investigator","steps":[]}`,
		`{"agent":"responder","steps":[{"op":"let","var":"x","expr":{"op":"lit","lit":1},"label":"trusted"}]}`,
	}
	for i, s := range bad {
		if _, err := plan.Decode([]byte(s)); !errors.Is(err, value.ErrPlanInvalid) {
			t.Errorf("case %d decoded: %v", i, err)
		}
	}
	p := decode(t, responderPlan)
	b, err := plan.Encode(p)
	if err != nil || !strings.Contains(string(b), `"action":"block"`) {
		t.Fatal("encode")
	}
}

func TestStaticCheckRejections(t *testing.T) {
	cases := []struct {
		name, agent, plan string
		allow             bool
		want              string
	}{
		{"literal target", "responder", `{"agent":"responder","steps":[{"op":"call","expr":{"op":"call","tool":"accounts","action":"disable","args":{"account":{"op":"lit","lit":"jdoe"}}}}]}`, true, "I2"},
		{"inventory target", "responder", `{"agent":"responder","steps":[{"op":"let","var":"p","expr":{"op":"call","tool":"inventory","action":"read","args":{"key":{"op":"lit","lit":"partner_ips"}}}},{"op":"for_each","var":"ip","over":{"op":"ref","ref":"p"},"body":[{"op":"call","expr":{"op":"call","tool":"firewall","action":"block","args":{"ip":{"op":"ref","ref":"ip"}}}}]}]}`, true, "I2"},
		{"action not in enum", "responder", `{"agent":"responder","steps":[{"op":"call","expr":{"op":"call","tool":"firewall","action":"drop","args":{"ip":{"op":"param","param":"confirmed_ips"}}}}]}`, true, "I3"},
		{"not granted", "responder", `{"agent":"responder","steps":[{"op":"for_each","var":"a","over":{"op":"ref","ref":"accounts"},"body":[{"op":"call","expr":{"op":"call","tool":"accounts","action":"disable","args":{"account":{"op":"ref","ref":"a"}}}}]}]}`, false, "A1"},
		{"investigator block", "investigator", `{"agent":"investigator","steps":[{"op":"for_each","var":"ip","over":{"op":"param","param":"confirmed_ips"},"body":[{"op":"call","expr":{"op":"call","tool":"firewall","action":"block","args":{"ip":{"op":"ref","ref":"ip"}}}}]}]}`, true, "A1"},
		{"not a tool", "responder", `{"agent":"responder","steps":[{"op":"call","expr":{"op":"call","tool":"handoff","action":"request","args":{}}}]}`, true, "A1"},
		{"undefined ref", "responder", `{"agent":"responder","steps":[{"op":"for_each","var":"ip","over":{"op":"ref","ref":"nope"},"body":[{"op":"let","var":"y","expr":{"op":"ref","ref":"ip"}}]}]}`, true, "schema"},
		{"wrong agent", "responder", `{"agent":"investigator","steps":[{"op":"let","var":"x","expr":{"op":"param","param":"hosts"}}]}`, true, "schema"},
		{"empty plan", "responder", `{"agent":"responder","steps":[]}`, true, "schema"},
		{"shadowing", "responder", `{"agent":"responder","steps":[{"op":"let","var":"ips","expr":{"op":"param","param":"hosts"}}]}`, true, "schema"},
		{"param shadow", "responder", `{"agent":"responder","steps":[{"op":"let","var":"hosts","expr":{"op":"param","param":"hosts"}}]}`, true, "schema"},
		{"bad name", "responder", `{"agent":"responder","steps":[{"op":"let","var":"Bad Name","expr":{"op":"param","param":"hosts"}}]}`, true, "schema"},
		{"unknown param", "responder", `{"agent":"responder","steps":[{"op":"let","var":"x","expr":{"op":"param","param":"secret"}}]}`, true, "schema"},
		{"unknown stmt", "responder", `{"agent":"responder","steps":[{"op":"goto"}]}`, true, "schema"},
		{"unknown expr", "responder", `{"agent":"responder","steps":[{"op":"let","var":"x","expr":{"op":"concat"}}]}`, true, "schema"},
		{"lit without type", "responder", `{"agent":"responder","steps":[{"op":"let","var":"x","expr":{"op":"lit","lit":"hi"}}]}`, true, "schema"},
		{"loop over scalar", "responder", `{"agent":"responder","steps":[{"op":"for_each","var":"x","over":{"op":"param","param":"window"},"body":[{"op":"let","var":"y","expr":{"op":"ref","ref":"x"}}]}]}`, true, "schema"},
		{"unregistered schema", "investigator", `{"agent":"investigator","steps":[{"op":"let","var":"x","expr":{"op":"extract","schema":"Secrets","inputs":[{"op":"param","param":"hosts"}],"ask":"a"}}]}`, true, "schema"},
		{"field of non-struct", "responder", `{"agent":"responder","steps":[{"op":"let","var":"x","expr":{"op":"field","of":{"op":"ref","ref":"ips"},"field":"ips"}}]}`, true, "schema"},
		{"eq type mismatch", "responder", `{"agent":"responder","steps":[{"op":"if","cond":{"op":"eq","left":{"op":"param","param":"window"},"right":{"op":"param","param":"allow_account_disable"}},"body":[{"op":"let","var":"x","expr":{"op":"param","param":"hosts"}}]}]}`, true, "schema"},
		{"inventory key not literal", "responder", `{"agent":"responder","steps":[{"op":"let","var":"x","expr":{"op":"call","tool":"inventory","action":"read","args":{"key":{"op":"lit","lit":"secrets"}}}}]}`, true, "schema"},
		{"missing arg", "responder", `{"agent":"responder","steps":[{"op":"call","expr":{"op":"call","tool":"firewall","action":"block","args":{}}}]}`, true, "schema"},
		{"extra arg", "responder", `{"agent":"responder","steps":[{"op":"for_each","var":"ip","over":{"op":"ref","ref":"ips"},"body":[{"op":"call","expr":{"op":"call","tool":"firewall","action":"block","args":{"ip":{"op":"ref","ref":"ip"},"note":{"op":"ref","ref":"ip"}}}}]}]}`, true, "schema"},
		{"handoff not allowed", "responder", `{"agent":"responder","steps":[{"op":"handoff","handoff":{"to":"investigator","task":"contain_incident","data":{"ips":{"op":"ref","ref":"ips"}}}}]}`, true, "H1"},
		{"handoff literal data", "investigator", `{"agent":"investigator","steps":[{"op":"handoff","handoff":{"to":"responder","task":"contain_incident","data":{"ips":{"op":"lit","lit":["1.2.3.4"]}}}}]}`, true, "H3"},
		{"handoff unknown data", "investigator", `{"agent":"investigator","steps":[{"op":"handoff","handoff":{"to":"responder","task":"contain_incident","data":{"note":{"op":"param","param":"hosts"}}}}]}`, true, "schema"},
		{"handoff requests allow", "investigator", `{"agent":"investigator","steps":[{"op":"let","var":"r","expr":{"op":"call","tool":"logs","action":"read","args":{"host":{"op":"param","param":"hosts"},"window":{"op":"param","param":"window"}}}},{"op":"let","var":"i","expr":{"op":"extract","schema":"IOCList","inputs":[{"op":"ref","ref":"r"}],"ask":"x"}},{"op":"handoff","handoff":{"to":"responder","task":"contain_incident","requested_ops":[{"tool":"firewall","action":"allow"}],"data":{"ips":{"op":"field","of":{"op":"ref","ref":"i"},"field":"ips"}}}}]}`, true, "H2"},
		{"let with body", "responder", `{"agent":"responder","steps":[{"op":"let","var":"x","expr":{"op":"param","param":"hosts"},"body":[{"op":"let","var":"y","expr":{"op":"param","param":"hosts"}}]}]}`, true, "schema"},
	}
	for _, c := range cases {
		err := plan.StaticCheck(decode(t, c.plan), env(t, c.agent, c.allow))
		if !errors.Is(err, value.ErrPlanRejected) || !slices.Contains(rules(err), c.want) {
			t.Errorf("%s: got %v (rules %v), want %s", c.name, err, rules(err), c.want)
		}
	}
}

func TestStaticCheckLimits(t *testing.T) {
	deep := `{"op":"let","var":"z","expr":{"op":"param","param":"hosts"}}`
	for i := 0; i < plan.MaxDepth+1; i++ {
		deep = `{"op":"for_each","var":"v` + string(rune('a'+i)) + `","over":{"op":"param","param":"hosts"},"body":[` + deep + `]}`
	}
	if err := plan.StaticCheck(decode(t, `{"agent":"responder","steps":[`+deep+`]}`), env(t, "responder", true)); !slices.Contains(rules(err), "schema") {
		t.Errorf("deep nesting accepted: %v", err)
	}
	var many []string
	for i := 0; i < plan.MaxStatements+1; i++ {
		many = append(many, `{"op":"call","expr":{"op":"call","tool":"inventory","action":"read","args":{"key":{"op":"lit","lit":"hosts"}}}}`)
	}
	if err := plan.StaticCheck(decode(t, `{"agent":"responder","steps":[`+strings.Join(many, ",")+`]}`), env(t, "responder", true)); err == nil {
		t.Error("too many statements accepted")
	}
	if err := plan.StaticCheck(plan.Plan{Agent: "responder"}, plan.Env{Agent: "responder"}); err == nil {
		t.Error("missing task and context")
	}
	var rej *plan.RejectError
	err := plan.StaticCheck(plan.Plan{Agent: "x"}, env(t, "responder", true))
	if !errors.As(err, &rej) || !strings.Contains(rej.Error(), "ERR_PLAN_REJECTED") {
		t.Fatal("RejectError")
	}
}

func BenchmarkStaticCheck(b *testing.B) {
	t := &testing.T{}
	p, _ := plan.Decode([]byte(responderPlan))
	e := env(t, "responder", true)
	for b.Loop() {
		plan.StaticCheck(p, e)
	}
}
