package orchestrator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/signed"
	"citadel/internal/value"
)

type inv struct{}

func (inv) HostExists(h string) bool { return h == "web-03" }
func (inv) InternalRanges() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
}

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

func newOrch(t *testing.T) (*Orchestrator, *signed.Registry) {
	cat, err := catalog.Load("../../configs/catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	reg, _ := signed.NewRegistry(signed.NewKey("orch", "orchestrator", signed.RoleOrchestrator, priv.Public().(ed25519.PublicKey), t0.Add(-time.Hour), t0.Add(time.Hour), signed.StatusActive))
	o, err := New(Config{Catalog: cat, Inventory: inv{}, Signer: signed.NewSigner("orch", "orchestrator", priv), Clock: value.NewManualClock(t0),
		Rand: rand.Reader, PolicyVersion: "citadel-policy-v1", SoftUntrustedPC: 20})
	if err != nil {
		t.Fatal(err)
	}
	return o, reg
}

func req() TaskRequest {
	return TaskRequest{Principal: "analyst-1", Role: "soc_analyst", Task: "contain_incident", Version: 1,
		Params: map[string]json.RawMessage{"hosts": json.RawMessage(`["web-03"]`), "window": json.RawMessage(`"1h"`), "allow_account_disable": json.RawMessage("true")},
		Note:   "brute force"}
}

func TestMintSignsAScopedContext(t *testing.T) {
	o, reg := newOrch(t)
	m, err := o.Mint(req())
	if err != nil {
		t.Fatal(err)
	}
	ac := m.Context
	if !strings.HasPrefix(ac.RunID, "run_") || len(ac.RunID) != 26 || ac.Budgets.MaxSensitiveCalls != 60 || ac.Budgets.SoftUntrustedPC != 20 ||
		!ac.ExpiresAt.Equal(t0.Add(30*time.Minute)) || len(ac.Agents) != 2 || len(ac.Workflow) != 1 {
		t.Fatalf("context %+v", ac)
	}
	if authz.HasFirewallOrAccountOp(ac.Grants["investigator"]) || !authz.CoversOp(ac.Grants["responder"], authz.Op{Tool: "accounts", Action: "disable"}) ||
		authz.CoversOp(ac.Grants["responder"], authz.Op{Tool: "firewall", Action: "allow"}) {
		t.Fatalf("grants %v", ac.Grants)
	}
	p, _, err := signed.Verify(reg, m.Wire, signed.PrefixAuthCtx, signed.RoleOrchestrator, t0)
	if err != nil || !bytes.Equal(p, m.Payload) {
		t.Fatalf("verify: %v", err)
	}
	m2, _ := o.Mint(req())
	if m2.Context.RunID == ac.RunID {
		t.Fatal("run IDs must not repeat")
	}
}

func TestMintRefusesInvalidRequests(t *testing.T) {
	o, _ := newOrch(t)
	cases := map[string]func(*TaskRequest){
		"unknown task":    func(r *TaskRequest) { r.Task = "wipe_disks" },
		"unknown version": func(r *TaskRequest) { r.Version = 2 },
		"no principal":    func(r *TaskRequest) { r.Principal = "" },
		"role":            func(r *TaskRequest) { r.Role = "intern" },
		"long note":       func(r *TaskRequest) { r.Note = strings.Repeat("x", MaxNoteBytes+1) },
		"internal ip":     func(r *TaskRequest) { r.Params["confirmed_ips"] = json.RawMessage(`["10.0.0.53"]`) },
		"unknown host":    func(r *TaskRequest) { r.Params["hosts"] = json.RawMessage(`["web-99"]`) },
		"unknown param":   func(r *TaskRequest) { r.Params["extra"] = json.RawMessage(`1`) },
	}
	for name, m := range cases {
		r := req()
		m(&r)
		if _, err := o.Mint(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(Config{}); !errors.Is(err, value.ErrConfig) {
		t.Fatal("empty config")
	}
	if _, err := NewRunID(bytes.NewReader(nil)); err == nil {
		t.Fatal("short random source")
	}
}
