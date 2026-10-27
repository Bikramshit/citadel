package interp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"citadel/internal/policy"
	"citadel/internal/runstate"
	"citadel/internal/value"
)

// GroundTruthApprover answers in place of the analyst in harness runs, from
// the fixture's ground truth. It approves as the context's principal.
type GroundTruthApprover struct {
	Principal string
	Clock     value.Clock
	// Decide returns the fixture's answer for a call.
	Decide func(req ApprovalRequest) bool
}

// Await answers immediately.
func (g GroundTruthApprover) Await(_ context.Context, rs *runstate.RunState, req ApprovalRequest) error {
	return rs.Approve(req.Key, g.Principal, g.Decide(req), g.Clock.Now())
}

// NoApprover never approves: every escalation times out into a Deny. It is
// the default when no principal is reachable.
type NoApprover struct{}

// Await returns at once without approving.
func (NoApprover) Await(context.Context, *runstate.RunState, ApprovalRequest) error {
	return fmt.Errorf("%w: no approver is configured", value.ErrApprovalDeclined)
}

// Pending is an approval request waiting for the principal.
type Pending struct {
	Request ApprovalRequest
	rs      *runstate.RunState
	answer  chan error
}

// ChannelApprover holds escalations until the principal answers through the
// dashboard or the agent's approval endpoint, or the approval expires.
type ChannelApprover struct {
	Clock value.Clock
	// Wait bounds how long a request waits in wall-clock time; the approval's
	// own expiry is enforced by the run state.
	Wait time.Duration

	mu      sync.Mutex
	pending map[policy.ApprovalKey]*Pending
	notify  func(ApprovalRequest)
}

// NewChannelApprover returns an approver that calls notify for each new
// request (for the dashboard's approval card).
func NewChannelApprover(clock value.Clock, wait time.Duration, notify func(ApprovalRequest)) *ChannelApprover {
	return &ChannelApprover{Clock: clock, Wait: wait, pending: map[policy.ApprovalKey]*Pending{}, notify: notify}
}

// Await waits for Answer, the wall-clock bound, or ctx.
func (c *ChannelApprover) Await(ctx context.Context, rs *runstate.RunState, req ApprovalRequest) error {
	p := &Pending{Request: req, rs: rs, answer: make(chan error, 1)}
	c.mu.Lock()
	c.pending[req.Key] = p
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, req.Key)
		c.mu.Unlock()
	}()
	if c.notify != nil {
		c.notify(req)
	}
	t := time.NewTimer(c.Wait)
	defer t.Stop()
	select {
	case err := <-p.answer:
		return err
	case <-t.C:
		return fmt.Errorf("%w: no answer within %s", value.ErrApprovalDeclined, c.Wait)
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", value.ErrApprovalDeclined, ctx.Err())
	}
}

// Answer records the approver's answer. Only the context's principal may
// approve: run state checks it.
func (c *ChannelApprover) Answer(key policy.ApprovalKey, approver string, yes bool) error {
	c.mu.Lock()
	p, ok := c.pending[key]
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s is not pending", value.ErrNoSuchApproval, key)
	}
	err := p.rs.Approve(key, approver, yes, c.Clock.Now())
	if err == nil { // a refused answer (a non-principal, say) leaves the request waiting
		select {
		case p.answer <- nil:
		default:
		}
	}
	return err
}

// List returns the pending requests.
func (c *ChannelApprover) List() []ApprovalRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ApprovalRequest, 0, len(c.pending))
	for _, p := range c.pending {
		out = append(out, p.Request)
	}
	return out
}
