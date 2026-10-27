package runstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/label"
	"citadel/internal/policy"
	"citadel/internal/value"
)

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

func testContext() *authz.AuthContext {
	return &authz.AuthContext{
		V: authz.ContextVersion, RunID: "run_test", Principal: "analyst-1", Role: "soc_analyst",
		Task: "contain_incident", TaskVersion: 1,
		Agents:        []string{"investigator", "responder"},
		Workflow:      []authz.HandoffGrant{{From: "investigator", To: "responder", Task: "contain_incident", Max: 1}},
		PolicyVersion: "citadel-policy-v1",
		IssuedAt:      t0, ExpiresAt: t0.Add(30 * time.Minute),
		Budgets: authz.Budgets{MaxSensitiveCalls: 60, SoftUntrustedPC: 20},
	}
}

func hashOf(ac *authz.AuthContext) [32]byte {
	b, _ := json.Marshal(ac)
	return sha256.Sum256(b)
}

var blockEff = []authz.Cap{
	{Tool: "firewall", Action: "block", Scope: authz.Scope{IPClass: authz.IPClassPublicExternal, ExcludeProtected: true, MaxCalls: 50}},
	{Tool: "accounts", Action: "disable", Scope: authz.Scope{MaxCalls: 5}},
	{Tool: "logs", Action: "read"},
}

func activate(t testing.TB) (*RunState, *authz.AuthContext, [32]byte) {
	t.Helper()
	ac := testContext()
	h := hashOf(ac)
	rs, err := NewRuns("responder", t0.Add(-time.Hour)).Activate(ac, h, t0)
	if err != nil {
		t.Fatal(err)
	}
	return rs, ac, h
}

func blockCall(ac *authz.AuthContext, h [32]byte, ip string, pc label.Label) *policy.CallCtx {
	a, err := value.ParseIPv4(ip)
	if err != nil {
		panic(err)
	}
	v, _ := value.IPv4(a, label.New(label.QLLM("investigator")))
	return &policy.CallCtx{
		RunID: ac.RunID, Agent: "responder", Op: authz.Op{Tool: "firewall", Action: "block"}, TargetArg: "ip",
		Target: &v, Args: map[string]value.Value{"ip": v}, PC: pc, Eff: blockEff, Ctx: ac, CtxHash: h,
		CtxVerified: true, Trust: label.DefaultTrust(), Now: t0,
	}
}

var trustedPC = label.New(label.Runtime())
var untrustedPC = label.New(label.Peer("investigator", "env1"))

func allow() policy.Decision {
	return policy.Decision{Verdict: policy.Allow, Rule: "E1", Group: "E", Reason: "corroborated"}
}

func escalate() policy.Decision {
	return policy.Decision{Verdict: policy.Escalate, Rule: "E1", Group: "E", Reason: "insufficient"}
}

func ipN(i int) string { return fmt.Sprintf("203.0.%d.%d", 113+i/250, 1+i%250) }

func TestActivate(t *testing.T) {
	runs := NewRuns("responder", t0)
	ac := testContext()
	h := hashOf(ac)
	rs, err := runs.Activate(ac, h, t0)
	if err != nil || rs.RunID() != "run_test" || rs.Principal() != "analyst-1" || rs.CtxHash() != h || !rs.ExpiresAt().Equal(ac.ExpiresAt) {
		t.Fatalf("activate: %v", err)
	}
	again, err := runs.Activate(ac, h, t0)
	if err != nil || again != rs {
		t.Fatal("same context must return the same run")
	}
	if got, ok := runs.Get("run_test"); !ok || got != rs {
		t.Fatal("Get")
	}
	if runs.StartedAt() != t0 || runs.Self() != "responder" {
		t.Fatal("accessors")
	}
	other := testContext()
	other.UserNote = "different bytes"
	if _, err := runs.Activate(other, hashOf(other), t0); !errors.Is(err, value.ErrContextConflict) {
		t.Fatalf("conflict: %v", err)
	}
	rs.Close()
	if _, err := runs.Activate(ac, h, t0); !errors.Is(err, value.ErrRunClosed) {
		t.Fatalf("closed: %v", err)
	}
	if _, err := runs.Activate(ac, h, ac.ExpiresAt); !errors.Is(err, value.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	notMe := testContext()
	notMe.Agents = []string{"investigator"}
	if _, err := runs.Activate(notMe, hashOf(notMe), t0); !errors.Is(err, value.ErrNotParticipant) {
		t.Fatalf("participant: %v", err)
	}
	later := NewRuns("responder", t0.Add(time.Second))
	if _, err := later.Activate(ac, h, t0.Add(2*time.Second)); !errors.Is(err, value.ErrPreStart) {
		t.Fatalf("pre-start: %v", err)
	}
}

// A4 positive: the 50th block is admitted. Negative: the 51st is denied, and
// the run-wide limit applies across operations.
func TestA4_Budgets(t *testing.T) {
	rs, ac, h := activate(t)
	for i := 0; i < 50; i++ {
		if a, d := rs.Admit(blockCall(ac, h, ipN(i), trustedPC), allow(), t0); a == nil {
			t.Fatalf("block %d denied: %+v", i+1, d)
		}
	}
	a, d := rs.Admit(blockCall(ac, h, ipN(50), trustedPC), allow(), t0)
	if a != nil || d.Rule != "A4" || d.Verdict != policy.Deny {
		t.Fatalf("51st block: %+v", d)
	}
	small := testContext()
	small.Budgets.MaxSensitiveCalls = 2
	srs, _ := NewRuns("responder", t0.Add(-time.Hour)).Activate(small, hashOf(small), t0)
	sh := hashOf(small)
	srs.Admit(blockCall(small, sh, ipN(0), trustedPC), allow(), t0)
	srs.Admit(blockCall(small, sh, ipN(1), trustedPC), allow(), t0)
	if _, d := srs.Admit(blockCall(small, sh, ipN(2), trustedPC), allow(), t0); d.Rule != "A4" {
		t.Fatalf("run limit: %+v", d)
	}
}

// A5 positive: the first call is admitted. Negative: the identical call is
// denied whatever the first attempt's outcome.
func TestA5_DuplicateAttempt(t *testing.T) {
	rs, ac, h := activate(t)
	a, _ := rs.Admit(blockCall(ac, h, "203.0.113.7", trustedPC), allow(), t0)
	if a == nil || !a.Admitted() {
		t.Fatal("first call must be admitted")
	}
	if err := rs.Settle(a, Failed, false, "rejected", t0); err != nil {
		t.Fatal(err)
	}
	b, d := rs.Admit(blockCall(ac, h, "203.0.113.7", trustedPC), allow(), t0)
	if b != nil || d.Rule != "A5" || d.Reason != "identical call already attempted: failed" {
		t.Fatalf("duplicate: %+v", d)
	}
	if s := rs.Stats(); s.Sensitive != 1 {
		t.Fatalf("a refused duplicate must not spend budget: %d", s.Sensitive)
	}
}

// F3 positive: the 20th block in an untrusted loop is allowed. Negative: the
// 21st escalates.
func TestF3_UntrustedLoopVolume(t *testing.T) {
	rs, ac, h := activate(t)
	for i := 0; i < 20; i++ {
		if a, d := rs.Admit(blockCall(ac, h, ipN(i), untrustedPC), allow(), t0); a == nil {
			t.Fatalf("block %d: %+v", i+1, d)
		}
	}
	a, d := rs.Admit(blockCall(ac, h, ipN(20), untrustedPC), allow(), t0)
	if a != nil || d.Rule != "F3" || d.Verdict != policy.Escalate {
		t.Fatalf("21st: %+v", d)
	}
	// Trusted-pc calls do not count toward F3.
	if a, _ := rs.Admit(blockCall(ac, h, ipN(21), trustedPC), allow(), t0); a == nil {
		t.Fatal("trusted pc must not escalate")
	}
	// Approving the escalated call admits it once.
	c := blockCall(ac, h, ipN(20), untrustedPC)
	k := policy.KeyFor(c)
	rs.RequestApproval(k, t0)
	if err := rs.Approve(k, "analyst-1", true, t0); err != nil {
		t.Fatal(err)
	}
	if a, d := rs.Admit(c, allow(), t0); a == nil {
		t.Fatalf("approved F3 escalation: %+v", d)
	}
}

func TestAdmitPassesDenyAndChecksBinding(t *testing.T) {
	rs, ac, h := activate(t)
	deny := policy.Decision{Verdict: policy.Deny, Rule: "A3", Group: "A"}
	if a, d := rs.Admit(blockCall(ac, h, "203.0.113.7", trustedPC), deny, t0); a != nil || d.Rule != "A3" {
		t.Fatal("deny must pass through")
	}
	wrong := blockCall(ac, [32]byte{1}, "203.0.113.7", trustedPC)
	if a, d := rs.Admit(wrong, allow(), t0); a != nil || d.Rule != "A0" {
		t.Fatal("a call bound to another context must be refused")
	}
	read := blockCall(ac, h, "203.0.113.7", trustedPC)
	read.Op, read.Target, read.Args = authz.Op{Tool: "logs", Action: "read"}, nil, map[string]value.Value{}
	a, _ := rs.Admit(read, policy.Decision{Verdict: policy.Allow, Rule: "F0"}, t0)
	if a == nil || a.Sensitive {
		t.Fatal("read must be admitted as a non-sensitive attempt")
	}
	if a2, _ := rs.Admit(read, policy.Decision{Verdict: policy.Allow, Rule: "F0"}, t0); a2 == nil {
		t.Fatal("a repeated read is not a duplicate attempt")
	}
	if a3, d := rs.Admit(read, policy.Decision{Verdict: policy.Escalate, Rule: "X"}, t0); a3 != nil || d.Verdict != policy.Escalate {
		t.Fatal("non-allow read")
	}
	if s := rs.Stats(); len(s.Reads) != 2 || s.Sensitive != 0 {
		t.Fatalf("stats %+v", s)
	}
}

// barrier starts n goroutines at once.
func barrier(n int, f func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			f(i)
		}(i)
	}
	close(start)
	wg.Wait()
}

// CT3: 100 goroutines call Admit for distinct allowed targets with a block
// limit of 50 and a run limit of 60: exactly 50 are admitted, and the
// counters equal the admitted attempts.
func TestCT3_ConcurrentAdmitExactlyTheLimit(t *testing.T) {
	rs, ac, h := activate(t)
	var admitted, a4 atomic.Int64
	barrier(100, func(i int) {
		a, d := rs.Admit(blockCall(ac, h, ipN(i), trustedPC), allow(), t0)
		switch {
		case a != nil:
			admitted.Add(1)
		case d.Rule == "A4":
			a4.Add(1)
		}
	})
	s := rs.Stats()
	if admitted.Load() != 50 || a4.Load() != 50 || s.Sensitive != 50 || len(s.Attempts) != 50 ||
		s.PerOp[authz.Op{Tool: "firewall", Action: "block"}] != 50 {
		t.Fatalf("admitted %d, A4 %d, stats %+v", admitted.Load(), a4.Load(), s.Sensitive)
	}
}

// CT4: 10 concurrent admissions with one granted approval admit exactly one;
// reuse is denied (A5); an approval for call X does not cover call Y; an
// approval after expiry fails; a non-principal cannot approve.
func TestCT4_ApprovalsAtomic(t *testing.T) {
	rs, ac, h := activate(t)
	x := blockCall(ac, h, "198.51.100.23", untrustedPC)
	kx := policy.KeyFor(x)
	if _, d := rs.Admit(x, escalate(), t0); d.Verdict != policy.Escalate {
		t.Fatal("must escalate before approval")
	}
	rs.RequestApproval(kx, t0)
	if err := rs.Approve(kx, "analyst-1", true, t0); err != nil {
		t.Fatal(err)
	}
	var admitted, a5, esc atomic.Int64
	barrier(10, func(int) {
		a, d := rs.Admit(blockCall(ac, h, "198.51.100.23", untrustedPC), escalate(), t0)
		switch {
		case a != nil:
			admitted.Add(1)
		case d.Rule == "A5":
			a5.Add(1)
		case d.Verdict == policy.Escalate:
			esc.Add(1)
		}
	})
	if admitted.Load() != 1 || a5.Load()+esc.Load() != 9 {
		t.Fatalf("admitted %d a5 %d escalated %d", admitted.Load(), a5.Load(), esc.Load())
	}
	if ap, _ := rs.Approval(kx); ap.State != policy.Used {
		t.Fatalf("approval state %s", ap.State)
	}
	if _, d := rs.Admit(blockCall(ac, h, "198.51.100.23", untrustedPC), escalate(), t0); d.Rule != "A5" {
		t.Fatalf("reuse afterward: %+v", d)
	}
	y := blockCall(ac, h, "198.51.100.24", untrustedPC)
	if a, d := rs.Admit(y, escalate(), t0); a != nil || d.Verdict != policy.Escalate {
		t.Fatal("approval for X must not cover Y")
	}
	ky := policy.KeyFor(y)
	rs.RequestApproval(ky, t0)
	if err := rs.Approve(ky, "mallory", true, t0); !errors.Is(err, value.ErrNotPrincipal) {
		t.Fatalf("non-principal: %v", err)
	}
	if err := rs.Approve(ky, "analyst-1", true, t0.Add(11*time.Minute)); !errors.Is(err, value.ErrApprovalExpired) {
		t.Fatalf("after expiry: %v", err)
	}
	if err := rs.Approve(ky, "analyst-1", true, t0); !errors.Is(err, value.ErrApprovalClosed) {
		t.Fatalf("expired approval revived: %v", err)
	}
}

// CT5 (run-state part): the clock passes the context's expiry between
// Decide and Admit; an approval granted before expiry is not consumable
// after it.
func TestCT5_ExpiryBetweenDecideAndAdmit(t *testing.T) {
	rs, ac, h := activate(t)
	c := blockCall(ac, h, "203.0.113.7", trustedPC)
	if a, d := rs.Admit(c, allow(), ac.ExpiresAt); a != nil || d.Rule != "A0" {
		t.Fatalf("expired between Decide and Admit: %+v", d)
	}
	e := blockCall(ac, h, "198.51.100.23", untrustedPC)
	k := policy.KeyFor(e)
	ap := rs.RequestApproval(k, ac.ExpiresAt.Add(-time.Minute))
	if !ap.ExpiresAt.Equal(ac.ExpiresAt) {
		t.Fatalf("approval must expire with the context: %v", ap.ExpiresAt)
	}
	if err := rs.Approve(k, "analyst-1", true, ac.ExpiresAt.Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if a, d := rs.Admit(e, escalate(), ac.ExpiresAt); a != nil || d.Rule != "A0" {
		t.Fatalf("granted approval consumed after expiry: %+v", d)
	}
	if got, _ := rs.Approval(k); got.State != policy.Granted {
		t.Fatalf("a refused admission must not consume the approval: %s", got.State)
	}
}

// L7: an approval is bound to one exact call: a call with one different
// argument, a second use, a non-principal, and an expired approval are each
// denied.
func TestL7_ApprovalBoundToOneCall(t *testing.T) {
	rs, ac, h := activate(t)
	c := blockCall(ac, h, "198.51.100.23", untrustedPC)
	k := policy.KeyFor(c)
	rs.RequestApproval(k, t0)
	if err := rs.Approve(k, "analyst-1", true, t0); err != nil {
		t.Fatal(err)
	}
	if a, _ := rs.Admit(blockCall(ac, h, "198.51.100.24", untrustedPC), escalate(), t0); a != nil {
		t.Fatal("approval reused on a different argument")
	}
	if a, _ := rs.Admit(c, escalate(), t0); a == nil {
		t.Fatal("approved call not admitted")
	}
	if a, _ := rs.Admit(c, escalate(), t0); a != nil {
		t.Fatal("approval used twice")
	}
	if err := rs.Approve(k, "analyst-1", true, t0); !errors.Is(err, value.ErrApprovalClosed) {
		t.Fatalf("used approval revived: %v", err)
	}
	d := blockCall(ac, h, "198.51.100.25", untrustedPC)
	kd := policy.KeyFor(d)
	rs.RequestApproval(kd, t0)
	if err := rs.Approve(kd, "someone-else", true, t0); !errors.Is(err, value.ErrNotPrincipal) {
		t.Fatal("non-principal approval")
	}
	if a, _ := rs.Admit(d, escalate(), t0); a != nil {
		t.Fatal("non-principal approval admitted the call")
	}
	if err := rs.Approve(kd, "analyst-1", true, t0.Add(policy.ApprovalLifetime)); !errors.Is(err, value.ErrApprovalExpired) {
		t.Fatal("expired approval")
	}
	if a, _ := rs.Admit(d, escalate(), t0); a != nil {
		t.Fatal("expired approval admitted the call")
	}
}

func TestApproveStateMachine(t *testing.T) {
	rs, ac, h := activate(t)
	k := policy.KeyFor(blockCall(ac, h, "198.51.100.23", untrustedPC))
	if err := rs.Approve(k, "analyst-1", true, t0); !errors.Is(err, value.ErrNoSuchApproval) {
		t.Fatal("unknown key")
	}
	if _, ok := rs.Approval(k); ok {
		t.Fatal("approval before request")
	}
	rs.RequestApproval(k, t0)
	first := rs.RequestApproval(k, t0.Add(time.Minute))
	if !first.ExpiresAt.Equal(t0.Add(policy.ApprovalLifetime)) {
		t.Fatal("a repeated request must not extend the approval")
	}
	if err := rs.Approve(k, "analyst-1", true, t0); err != nil {
		t.Fatal(err)
	}
	if err := rs.Approve(k, "analyst-1", true, t0); err != nil {
		t.Fatal("repeated yes must be idempotent")
	}
	if err := rs.Approve(k, "analyst-1", false, t0); !errors.Is(err, value.ErrApprovalClosed) {
		t.Fatal("no after yes")
	}
	k2 := policy.KeyFor(blockCall(ac, h, "198.51.100.24", untrustedPC))
	rs.RequestApproval(k2, t0)
	if err := rs.Approve(k2, "analyst-1", false, t0); err != nil {
		t.Fatal(err)
	}
	if ap, _ := rs.Approval(k2); ap.State != policy.Rejected {
		t.Fatal("rejected")
	}
	if err := rs.Approve(k2, "analyst-1", true, t0); !errors.Is(err, value.ErrApprovalClosed) {
		t.Fatal("rejected approval revived")
	}
	k3 := policy.KeyFor(blockCall(ac, h, "198.51.100.26", untrustedPC))
	rs.RequestApproval(k3, t0)
	rs.Close()
	if err := rs.Approve(k3, "analyst-1", true, t0); !errors.Is(err, value.ErrApprovalClosed) {
		t.Fatal("approval on a closed run")
	}
	if s := rs.Stats(); len(s.Approvals) != 3 {
		t.Fatalf("stats approvals %d", len(s.Approvals))
	}
}

func TestHandoffAllowance(t *testing.T) {
	rs, _, _ := activate(t)
	k := HandoffKey{From: "investigator", To: "responder", Task: "contain_incident"}
	installed := 0
	if err := rs.CommitHandoff(k, func() { installed++ }, t0); err != nil || installed != 1 {
		t.Fatal(err)
	}
	if err := rs.CommitHandoff(k, func() { installed++ }, t0); !errors.Is(err, value.ErrWorkflow) || installed != 1 {
		t.Fatalf("second handoff: %v", err)
	}
	if err := rs.CommitHandoff(HandoffKey{From: "x", To: "y", Task: "z"}, func() {}, t0); !errors.Is(err, value.ErrWorkflow) {
		t.Fatal("unlisted handoff")
	}
	rs2, ac, _ := activate(t)
	if err := rs2.ReserveHandoff(k, ac.ExpiresAt); !errors.Is(err, value.ErrAuthCtx) {
		t.Fatal("expired")
	}
	if err := rs2.ReserveHandoff(k, t0); err != nil {
		t.Fatal(err)
	}
	if err := rs2.ReserveHandoff(k, t0); !errors.Is(err, value.ErrWorkflow) {
		t.Fatal("reserve twice")
	}
	rs2.Close()
	if !rs2.IsClosed() {
		t.Fatal("IsClosed")
	}
	if a, d := rs2.Admit(&policy.CallCtx{RunID: "run_test"}, allow(), t0); a != nil || d.Rule != "A0" {
		t.Fatal("admit on closed run")
	}
}

func TestSettle(t *testing.T) {
	rs, ac, h := activate(t)
	a, _ := rs.Admit(blockCall(ac, h, "203.0.113.7", trustedPC), allow(), t0)
	if err := rs.Settle(a, Attempted, false, "", t0); !errors.Is(err, value.ErrNotAdmitted) {
		t.Fatal("settle to attempted")
	}
	if err := rs.Settle(a, Succeeded, true, "confirmed", t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if a.Admitted() {
		t.Fatal("a settled attempt is no longer admitted")
	}
	snap := rs.Snapshot(a)
	if snap.State != Succeeded || !snap.Reconciled || snap.Detail != "confirmed" {
		t.Fatalf("snapshot %+v", snap)
	}
	if err := rs.Settle(a, Failed, false, "", t0); !errors.Is(err, value.ErrNotAdmitted) {
		t.Fatal("settled twice")
	}
	other, _, _ := activate(t)
	b, _ := other.Admit(blockCall(ac, h, "203.0.113.8", trustedPC), allow(), t0)
	if err := rs.Settle(b, Succeeded, false, "", t0); !errors.Is(err, value.ErrNotAdmitted) {
		t.Fatal("settled another run's attempt")
	}
	forged := &Attempt{State: Attempted}
	if forged.Admitted() || (*Attempt)(nil).Admitted() {
		t.Fatal("an attempt not from Admit must not be admitted")
	}
	for _, s := range []AttemptState{Attempted, Succeeded, Failed, Uncertain, 9} {
		if b, _ := s.MarshalText(); string(b) != s.String() {
			t.Fatal("MarshalText")
		}
	}
}

func TestReplayTable(t *testing.T) {
	rt := NewReplayTable()
	d1, d2 := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	until := t0.Add(5*time.Minute + 30*time.Second)
	if p, err := rt.Begin("investigator", "id1", d1, until, t0); p != nil || err != nil {
		t.Fatal("first sight")
	}
	if _, err := rt.Begin("investigator", "id1", d1, until, t0); !errors.Is(err, value.ErrInProgress) {
		t.Fatal("in progress")
	}
	if _, err := rt.Begin("investigator", "id1", d2, until, t0); !errors.Is(err, value.ErrReplay) {
		t.Fatal("different bytes")
	}
	if err := rt.Finish("investigator", "id1", ""); err != nil {
		t.Fatal(err)
	}
	if err := rt.Finish("investigator", "id1", ""); err == nil {
		t.Fatal("finish twice")
	}
	if err := rt.Finish("investigator", "nope", ""); err == nil {
		t.Fatal("finish unknown")
	}
	p, err := rt.Begin("investigator", "id1", d1, until, t0)
	if err != nil || p == nil || p.State != Accepted || !errors.Is(p.Result(), value.ErrReplay) {
		t.Fatalf("identical retransmission: %+v %v", p, err)
	}
	rt.Begin("investigator", "id2", d2, until, t0)
	rt.Finish("investigator", "id2", "ERR_EXCESS_GRANT")
	p, _ = rt.Begin("investigator", "id2", d2, until, t0)
	if p == nil || p.State != Rejected || !errors.Is(p.Result(), value.ErrExcessGrant) {
		t.Fatalf("recorded rejection: %+v", p)
	}
	if rt.Len() != 2 {
		t.Fatal("len")
	}
	rt.Begin("investigator", "id3", d1, until, until.Add(time.Second))
	if rt.Len() != 1 {
		t.Fatalf("expired entries must be purged, have %d", rt.Len())
	}
	for _, s := range []ReplayState{Processing, Accepted, Rejected, 9} {
		if s.String() == "" {
			t.Fatal("String")
		}
	}
}

type idemVector struct {
	RunID   string            `json:"run_id"`
	CtxHash string            `json:"ctx_hash_hex"`
	Agent   string            `json:"agent"`
	Tool    string            `json:"tool"`
	Action  string            `json:"action"`
	Args    map[string]string `json:"args"`
	Key     string            `json:"key_hex"`
}

// Golden vectors pin the documented idempotency-key encoding.
func TestIdemKeyGoldenVectors(t *testing.T) {
	b, err := os.ReadFile("../../testdata/vectors/idempotency_keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []idemVector
	if err := json.Unmarshal(b, &vs); err != nil || len(vs) == 0 {
		t.Fatal(err)
	}
	for _, v := range vs {
		var h [32]byte
		hb, err := hex.DecodeString(v.CtxHash)
		if err != nil {
			t.Fatal(err)
		}
		copy(h[:], hb)
		k := IdemKeyOf(IdemFields{RunID: v.RunID, CtxHash: h, Agent: v.Agent, Tool: v.Tool, Action: v.Action, Args: v.Args})
		if k.String() != v.Key {
			t.Errorf("vector %s %s: got %s want %s", v.Tool, v.Args, k, v.Key)
		}
	}
	// IdemKeyFor uses the same encoding.
	ac := testContext()
	h := [32]byte{}
	c := blockCall(ac, h, "203.0.113.7", trustedPC)
	want := IdemKeyOf(IdemFields{RunID: ac.RunID, CtxHash: h, Agent: "responder", Tool: "firewall", Action: "block", Args: map[string]string{"ip": "203.0.113.7"}})
	if IdemKeyFor(c) != want {
		t.Fatal("IdemKeyFor")
	}
	if txt, _ := want.MarshalText(); string(txt) != want.String() {
		t.Fatal("MarshalText")
	}
}

// Experiment 4: admission under the run lock.
func BenchmarkAdmit(b *testing.B) {
	for b.Loop() {
		rs, ac, h := activate(b)
		for i := 0; i < 50; i++ {
			rs.Admit(blockCall(ac, h, ipN(i), trustedPC), allow(), t0)
		}
	}
}
