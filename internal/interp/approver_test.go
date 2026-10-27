package interp

import (
	"context"
	"errors"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/policy"
	"citadel/internal/runstate"
	"citadel/internal/value"
)

var t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

func run(t *testing.T) *runstate.RunState {
	ac := &authz.AuthContext{V: 1, RunID: "run_a", Principal: "analyst-1", Role: "r", Task: "t", TaskVersion: 1, Agents: []string{"responder"},
		PolicyVersion: "v", IssuedAt: t0, ExpiresAt: t0.Add(time.Hour)}
	rs, err := runstate.NewRuns("responder", t0.Add(-time.Minute)).Activate(ac, [32]byte{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestGroundTruthAndNoApprover(t *testing.T) {
	rs := run(t)
	k := policy.ApprovalKey{1}
	rs.RequestApproval(k, t0)
	g := GroundTruthApprover{Principal: "analyst-1", Clock: value.NewManualClock(t0), Decide: func(ApprovalRequest) bool { return true }}
	if err := g.Await(context.Background(), rs, ApprovalRequest{Key: k}); err != nil {
		t.Fatal(err)
	}
	if a, _ := rs.Approval(k); a.State != policy.Granted {
		t.Fatal("ground truth approval")
	}
	if err := (NoApprover{}).Await(context.Background(), rs, ApprovalRequest{}); !errors.Is(err, value.ErrApprovalDeclined) {
		t.Fatal("no approver must decline")
	}
}

// Only the principal's answer releases a waiting call; a refused answer
// leaves it waiting, and the wait ends in a Deny when it times out.
func TestChannelApprover(t *testing.T) {
	rs := run(t)
	k := policy.ApprovalKey{2}
	rs.RequestApproval(k, t0)
	notified := make(chan ApprovalRequest, 1)
	c := NewChannelApprover(value.NewManualClock(t0), 2*time.Second, func(r ApprovalRequest) { notified <- r })
	done := make(chan error, 1)
	go func() { done <- c.Await(context.Background(), rs, ApprovalRequest{Key: k}) }()
	<-notified
	if len(c.List()) != 1 {
		t.Fatal("pending list")
	}
	if err := c.Answer(k, "mallory", true); !errors.Is(err, value.ErrNotPrincipal) {
		t.Fatalf("non-principal: %v", err)
	}
	select {
	case <-done:
		t.Fatal("a non-principal answer must not release the call")
	case <-time.After(50 * time.Millisecond):
	}
	if err := c.Answer(k, "analyst-1", true); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := c.Answer(k, "analyst-1", true); !errors.Is(err, value.ErrNoSuchApproval) {
		t.Fatal("answered request is no longer pending")
	}
	short := NewChannelApprover(value.NewManualClock(t0), 10*time.Millisecond, nil)
	if err := short.Await(context.Background(), rs, ApprovalRequest{Key: policy.ApprovalKey{3}}); !errors.Is(err, value.ErrApprovalDeclined) {
		t.Fatal("timeout must decline")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := short.Await(ctx, rs, ApprovalRequest{Key: policy.ApprovalKey{4}}); !errors.Is(err, value.ErrApprovalDeclined) {
		t.Fatal("cancelled wait must decline")
	}
}

// An answer is stamped on the run's timeline: the request time plus the
// wait. A wall clock far past the fixture's time does not expire a request;
// waiting longer than the approval's lifetime does.
func TestChannelApproverRunTimeline(t *testing.T) {
	rs := run(t)
	wall := value.NewManualClock(t0.AddDate(0, 1, 0))
	notified := make(chan ApprovalRequest, 1)
	c := NewChannelApprover(wall, time.Minute, func(r ApprovalRequest) { notified <- r })
	await := func(ctx context.Context, k policy.ApprovalKey) chan error {
		rs.RequestApproval(k, t0)
		done := make(chan error, 1)
		go func() { done <- c.Await(ctx, rs, ApprovalRequest{Key: k, RequestedAt: t0}) }()
		<-notified
		return done
	}

	done := await(context.Background(), policy.ApprovalKey{5})
	wall.Advance(time.Minute)
	if err := c.Answer(policy.ApprovalKey{5}, "analyst-1", true); err != nil {
		t.Fatalf("answer within the lifetime: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done = await(ctx, policy.ApprovalKey{6})
	wall.Advance(policy.ApprovalLifetime)
	if err := c.Answer(policy.ApprovalKey{6}, "analyst-1", true); !errors.Is(err, value.ErrApprovalExpired) {
		t.Fatalf("answer after the lifetime: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, value.ErrApprovalDeclined) {
		t.Fatal("cancelled wait must decline")
	}
}
