package handoff_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/catalog"
	"citadel/internal/events"
	"citadel/internal/handoff"
	"citadel/internal/label"
	"citadel/internal/orchestrator"
	"citadel/internal/runstate"
	"citadel/internal/signed"
	"citadel/internal/tools"
	"citadel/internal/value"
)

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

// seeded returns a deterministic test key: tests never use crypto/rand for
// keys they compare across runs.
func seeded(b byte) ed25519.PrivateKey {
	seed := bytes.Repeat([]byte{b}, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

type rig struct {
	t        testing.TB
	clock    *value.ManualClock
	reg      *signed.Registry
	orch     *signed.Signer
	inv      *signed.Signer
	resp     *signed.Signer
	revoked  *signed.Signer
	cat      *catalog.Catalog
	task     *catalog.Task
	minted   orchestrator.Minted
	runs     *runstate.Runs
	replay   *runstate.ReplayTable
	rcv      *handoff.Receiver
	rec      *events.Recorder
	env      *tools.Env
	mode     string
	installs int
	mu       sync.Mutex
}

type deterministicReader struct{ n byte }

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = r.n
	}
	return len(p), nil
}

func loadInventory(t testing.TB) tools.InventoryData {
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

func newRig(t testing.TB, params map[string]string) *rig {
	t.Helper()
	r := &rig{t: t, clock: value.NewManualClock(t0), mode: handoff.ModeC2}
	keys := []signed.Key{}
	mk := func(seed byte, kid, agent, role, status string) *signed.Signer {
		priv := seeded(seed)
		keys = append(keys, signed.NewKey(kid, agent, role, priv.Public().(ed25519.PublicKey), t0.Add(-24*time.Hour), t0.Add(24*time.Hour), status))
		return signed.NewSigner(kid, agent, priv)
	}
	r.orch = mk(1, "orchestrator-2026-10-a", "orchestrator", signed.RoleOrchestrator, signed.StatusActive)
	r.inv = mk(2, "investigator-2026-10-a", "investigator", signed.RoleAgent, signed.StatusActive)
	r.resp = mk(3, "responder-2026-10-a", "responder", signed.RoleAgent, signed.StatusActive)
	r.revoked = mk(4, "investigator-2026-09-z", "investigator", signed.RoleAgent, signed.StatusRevoked)
	reg, err := signed.NewRegistry(keys...)
	if err != nil {
		t.Fatal(err)
	}
	r.reg = reg
	if r.cat, err = catalog.Load("../../configs/catalog.yaml"); err != nil {
		t.Fatal(err)
	}
	r.task, _ = r.cat.Lookup("contain_incident", 1)
	if r.env, err = tools.NewEnv(tools.Spec{Inventory: loadInventory(t)}, r.clock); err != nil {
		t.Fatal(err)
	}
	raw := map[string]json.RawMessage{"hosts": json.RawMessage(`["web-03"]`), "window": json.RawMessage(`"1h"`), "allow_account_disable": json.RawMessage("true")}
	for k, v := range params {
		raw[k] = json.RawMessage(v)
	}
	o, err := orchestrator.New(orchestrator.Config{Catalog: r.cat, Inventory: r.env.Inventory(), Signer: r.orch, Clock: r.clock,
		Rand: &deterministicReader{}, PolicyVersion: "citadel-policy-v1", SoftUntrustedPC: 20})
	if err != nil {
		t.Fatal(err)
	}
	if r.minted, err = o.Mint(orchestrator.TaskRequest{Principal: "analyst-1", Role: "soc_analyst", Task: "contain_incident", Version: 1, Params: raw}); err != nil {
		t.Fatal(err)
	}
	r.restart(t0.Add(-time.Minute))
	return r
}

// restart builds a fresh receiver process: empty run table and replay
// table, a new start time.
func (r *rig) restart(startedAt time.Time) {
	r.runs = runstate.NewRuns("responder", startedAt)
	r.replay = runstate.NewReplayTable()
	r.rec = &events.Recorder{}
	rcv, err := handoff.NewReceiver(handoff.ReceiverConfig{Self: "responder", Static: []authz.Cap{
		{Tool: "firewall", Action: "block"}, {Tool: "firewall", Action: "allow"}, {Tool: "accounts", Action: "disable"}, {Tool: "inventory", Action: "read"}},
		Registry: r.reg, Runs: r.runs, Replay: r.replay, Catalog: r.cat, Hosts: r.env.Inventory(), PolicyVersions: []string{"citadel-policy-v1"},
		Mode: r.mode, Events: r.rec, Clock: r.clock})
	if err != nil {
		r.t.Fatal(err)
	}
	r.rcv = rcv
}

var idCounter byte

func freshID() string {
	idCounter++
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{idCounter}, 16))
}

// payload returns a valid payload for the rig's context.
func (r *rig) payload() handoff.Payload {
	now := r.clock.Now()
	return handoff.Payload{V: 1, KID: r.inv.KID(), ID: freshID(), RunID: r.minted.Context.RunID, From: "investigator", To: "responder",
		Task: "contain_incident", TaskVersion: 1, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), AuthCtx: r.minted.Wire,
		Data: []handoff.DataItem{
			{Name: "ips", Type: "list<ipv4>", Values: []string{"203.0.113.7", "198.51.100.23"}, ClaimedSources: []string{"qllm:investigator", "tool:logs.read"}},
			{Name: "accounts", Type: "list<account_id>", Values: []string{"svc-backup"}, ClaimedSources: []string{"qllm:investigator", "tool:logs.read"}},
		}}
}

func payloadBytes(t testing.TB, p handoff.Payload) []byte {
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seal signs payload bytes with s and returns the wire body.
func seal(s *signed.Signer, p []byte) []byte {
	return signed.EncodeWire(s.Sign(signed.PrefixHandoff, p))
}

func (r *rig) envelope(p handoff.Payload) []byte { return seal(r.inv, payloadBytes(r.t, p)) }

func (r *rig) accept(body []byte) (handoff.Response, *handoff.Staged) {
	return r.rcv.Accept(context.Background(), body, func(*handoff.Staged) {
		r.mu.Lock()
		r.installs++
		r.mu.Unlock()
	})
}

func expectCode(t testing.TB, name string, resp handoff.Response, code value.Code) {
	t.Helper()
	if resp.Accepted() || resp.Code != string(code) {
		t.Errorf("%s: got %+v, want %s", name, resp, code)
	}
}

// signContext signs an arbitrary context with signer, for tests that need a
// context the orchestrator would never mint.
func signContext(t testing.TB, s *signed.Signer, ac *authz.AuthContext) (signed.Wire, [32]byte) {
	b, err := json.Marshal(ac)
	if err != nil {
		t.Fatal(err)
	}
	return s.Sign(signed.PrefixAuthCtx, b), sha256.Sum256(b)
}

func cloneContext(ac *authz.AuthContext) *authz.AuthContext {
	b, _ := json.Marshal(ac)
	var out authz.AuthContext
	json.Unmarshal(b, &out)
	return &out
}

func allUntrusted(vals map[string]value.Value) error {
	for name, v := range vals {
		if v.Label().Trusted(label.DefaultTrust()) || !v.Label().Has(label.SrcPeer) {
			return fmt.Errorf("%s labeled %v", name, v.Label())
		}
		for _, e := range v.Elems() {
			if e.Label().Trusted(label.DefaultTrust()) {
				return fmt.Errorf("element of %s trusted", name)
			}
		}
	}
	return nil
}
