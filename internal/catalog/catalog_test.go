package catalog

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/value"
)

type inv struct{}

func (inv) HostExists(h string) bool { return h == "web-03" || h == "web-04" }
func (inv) InternalRanges() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
}

func load(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load("../../configs/catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func raw(m map[string]string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range m {
		out[k] = json.RawMessage(v)
	}
	return out
}

func TestLoadRepositoryCatalog(t *testing.T) {
	c := load(t)
	task, ok := c.Lookup("contain_incident", 1)
	if !ok || task.TTL() != 30*time.Minute || !task.AllowsRole("soc_analyst") || task.AllowsRole("intern") {
		t.Fatalf("task: %+v", task)
	}
	if !slices.Equal(task.AgentNames(), []string{"investigator", "responder"}) {
		t.Fatal(task.AgentNames())
	}
	if !slices.Equal(task.DataNames(), []string{"accounts", "ips"}) {
		t.Fatal(task.DataNames())
	}
	if ty, ok := task.DataType("ips"); !ok || ty.String() != "list<ipv4>" {
		t.Fatal("data type")
	}
	if ty, ok := task.ParamType("window"); !ok || ty.Kind != value.KindDuration {
		t.Fatal("param type")
	}
	if l, ok := c.Latest("contain_incident"); !ok || l.Version != 1 {
		t.Fatal("latest")
	}
	if _, ok := c.Lookup("contain_incident", 2); ok {
		t.Fatal("version 2 found")
	}
	wf := task.Workflow()
	if len(wf) != 1 || wf[0] != (authz.HandoffGrant{From: "investigator", To: "responder", Task: "contain_incident", Max: 1}) {
		t.Fatalf("workflow %v", wf)
	}
}

func TestValidateParams(t *testing.T) {
	task, _ := load(t).Lookup("contain_incident", 1)
	good, err := task.ValidateParams(raw(map[string]string{
		"hosts": `["web-03"]`, "window": `"1h"`, "confirmed_ips": `["203.0.113.7"]`, "allow_account_disable": `true`,
	}), inv{})
	if err != nil {
		t.Fatal(err)
	}
	if string(good["hosts"]) != `["web-03"]` || string(good["window"]) != `"1h"` || string(good["allow_account_disable"]) != "true" {
		t.Fatalf("canonical params %s", good)
	}
	defaults, err := task.ValidateParams(raw(map[string]string{"hosts": `["web-03"]`, "window": `"1h"`}), inv{})
	if err != nil || string(defaults["confirmed_ips"]) != "[]" || string(defaults["allow_account_disable"]) != "false" {
		t.Fatalf("defaults %s %v", defaults, err)
	}
	bad := []map[string]string{
		{"hosts": `["web-03"]`},                                              // window missing
		{"window": `"1h"`},                                                   // hosts missing
		{"hosts": `[]`, "window": `"1h"`},                                    // below min
		{"hosts": `["web-99"]`, "window": `"1h"`},                            // not in inventory
		{"hosts": `["web-03","web-04","web-03","web-04"]`, "window": `"1h"`}, // over max
		{"hosts": `["web-03","web-03"]`, "window": `"1h"`},                   // repeated
		{"hosts": `["web-03"]`, "window": `"25h"`},                           // over max duration
		{"hosts": `["web-03"]`, "window": `"1h"`, "confirmed_ips": `["10.0.0.53"]`},
		{"hosts": `["web-03"]`, "window": `"1h"`, "confirmed_ips": `["192.168.1.1"]`},
		{"hosts": `["web-03"]`, "window": `"1h"`, "confirmed_ips": `["203.0.113.007"]`},
		{"hosts": `["web-03"]`, "window": `"1h"`, "allow_account_disable": `"yes"`},
		{"hosts": `["web-03"]`, "window": `"1h"`, "note": `"hi"`},
	}
	for i, b := range bad {
		if _, err := task.ValidateParams(raw(b), inv{}); !errors.Is(err, value.ErrType) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	many := make([]string, 21)
	for i := range many {
		many[i] = `"203.0.113.` + string(rune('1'+i%9)) + string(rune('0'+i/9)) + `"`
	}
	if _, err := task.ValidateParams(raw(map[string]string{"hosts": `["web-03"]`, "window": `"1h"`, "confirmed_ips": "[" + strings.Join(many, ",") + "]"}), inv{}); !errors.Is(err, value.ErrType) {
		t.Errorf("21 confirmed IPs accepted: %v", err)
	}
}

func TestOps(t *testing.T) {
	c := load(t)
	task, _ := c.Lookup("contain_incident", 1)
	params, err := task.ValidateParams(raw(map[string]string{"hosts": `["web-03"]`, "window": `"1h"`, "allow_account_disable": `true`}), inv{})
	if err != nil {
		t.Fatal(err)
	}
	invOps, err := task.Ops("investigator", params)
	if err != nil {
		t.Fatal(err)
	}
	if len(invOps) != 2 || invOps[0].Op() != (authz.Op{Tool: "logs", Action: "read"}) ||
		!slices.Equal(invOps[0].Scope.Hosts, []string{"web-03"}) || invOps[0].Scope.Window != time.Hour ||
		!authz.Covers(invOps, authz.HandoffCap("responder", "contain_incident")) || authz.HasFirewallOrAccountOp(invOps) {
		t.Fatalf("investigator ops %v", invOps)
	}
	resp, _ := task.Ops("responder", params)
	if !authz.CoversOp(resp, authz.Op{Tool: "accounts", Action: "disable"}) || authz.CoversOp(resp, authz.Op{Tool: "firewall", Action: "allow"}) {
		t.Fatalf("responder ops %v", resp)
	}
	params["allow_account_disable"] = json.RawMessage("false")
	resp, _ = task.Ops("responder", params)
	if authz.CoversOp(resp, authz.Op{Tool: "accounts", Action: "disable"}) {
		t.Fatal("accounts.disable granted with allow_account_disable false")
	}
	if ops, err := task.Ops("mallory", params); err != nil || len(ops) != 0 {
		t.Fatal("unknown agent must get nothing")
	}
	ops, ok, err := c.TaskOps("contain_incident", 1, "responder", params)
	if !ok || err != nil || len(ops) != 2 {
		t.Fatalf("TaskOps %v %v %v", ops, ok, err)
	}
	if _, ok, _ := c.TaskOps("nope", 1, "responder", params); ok {
		t.Fatal("unknown task")
	}
	delete(params, "window")
	if _, ok, err := c.TaskOps("contain_incident", 1, "responder", params); !ok || err == nil {
		t.Fatal("missing param must error")
	}
	params["window"] = json.RawMessage(`"1h"`)
	params["extra"] = json.RawMessage(`1`)
	if _, err := task.ParamValues(params, nil); !errors.Is(err, value.ErrAuthCtx) {
		t.Fatal("unknown context param")
	}
	params["extra"] = nil
	delete(params, "extra")
	params["hosts"] = json.RawMessage(`["Bad"]`)
	if _, err := task.ParamValues(params, nil); err == nil {
		t.Fatal("bad host value")
	}
}

func TestParseRejectsBadCatalogs(t *testing.T) {
	base := `tasks:
  - task: t
    version: 1
    roles: [r]
    params:
      hosts: {type: list<hostname>, min: 1, max: 3}
      window: {type: duration, max: 24h}
      flag: {type: bool}
    agents:
      a:
        ops:
          - {tool: logs, action: read, scope: {hosts: $hosts, window: $window}}
        handoffs:
          - {to: b, task: t, max: 1}
      b:
        ops:
          - {tool: firewall, action: block, when: $flag}
    data:
      ips: list<ipv4>
    budgets: {max_sensitive_calls: 5, ttl: 10m}
`
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatalf("base catalog: %v", err)
	}
	mutations := map[string][2]string{
		"unknown field":     {"roles: [r]", "roles: [r]\n    color: red"},
		"no roles":          {"roles: [r]", "roles: []"},
		"bad param type":    {"type: bool}", "type: ipv6}"},
		"list without max":  {"min: 1, max: 3", "min: 1"},
		"bad duration max":  {"max: 24h", "max: forever"},
		"bad must_exist":    {"max: 3}", "max: 3, must_exist: dns}"},
		"bad class":         {"type: bool}", "type: bool, class: lan}"},
		"unknown tool":      {"tool: firewall", "tool: shell"},
		"when not bool":     {"when: $flag", "when: $hosts"},
		"hosts not a ref":   {"hosts: $hosts,", "hosts: web-03,"},
		"window not dur":    {"window: $window}", "window: $hosts}"},
		"bad handoff":       {"to: b,", "to: c,"},
		"self handoff":      {"to: b,", "to: a,"},
		"zero budget":       {"max_sensitive_calls: 5", "max_sensitive_calls: 0"},
		"bad ttl":           {"ttl: 10m", "ttl: 0m"},
		"data not list":     {"ips: list<ipv4>", "ips: ipv4"},
		"negative maxcalls": {"when: $flag}", "when: $flag, max_calls: -1}"},
		"bad ip class":      {"when: $flag}", "when: $flag, scope: {ip_class: lan}}"},
		"bad account kind":  {"when: $flag}", "when: $flag, scope: {account_kinds: [admin]}}"},
		"empty kinds":       {"when: $flag}", "when: $flag, scope: {account_kinds: []}}"},
		"no agents":         {"    agents:\n", "    agents: {}\n    ignored:\n"},
	}
	for name, m := range mutations {
		in := strings.Replace(base, m[0], m[1], 1)
		if in == base {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := Parse([]byte(in)); !errors.Is(err, value.ErrConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := Parse([]byte("tasks: []")); !errors.Is(err, value.ErrConfig) {
		t.Error("empty catalog accepted")
	}
	if _, err := Parse([]byte(base + "  - null\n")); !errors.Is(err, value.ErrConfig) {
		t.Error("null entry accepted")
	}
	dup := base + strings.TrimPrefix(base, "tasks:\n")
	if _, err := Parse([]byte(dup)); !errors.Is(err, value.ErrConfig) {
		t.Error("duplicate task accepted")
	}
	if _, err := Load("/nonexistent/catalog.yaml"); !errors.Is(err, value.ErrConfig) {
		t.Error("missing file")
	}
}
