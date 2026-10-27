// Package events is Citadel's audit log: a JSONL writer synced when a run
// ends, and server-sent-events fan-out for the dashboard. Events are written
// only; nothing reads them back into execution. A decision carries a verdict
// and an attempt carries an outcome. They are separate kinds, so no report
// can turn an unknown outcome into a denial.
package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"citadel/internal/authz"
	"citadel/internal/evidence"
	"citadel/internal/policy"
	"citadel/internal/runstate"
)

// Event kinds.
const (
	KindRunStart        = "run_start"
	KindPlanRejected    = "plan_rejected"
	KindValue           = "value"
	KindCall            = "call"
	KindDecision        = "decision"
	KindApprovalRequest = "approval_request"
	KindApproval        = "approval"
	KindAttempt         = "attempt"
	KindHandoffSend     = "handoff_send"
	KindHandoffAccept   = "handoff_accept"
	KindHandoffReject   = "handoff_reject"
	KindEnvChange       = "env_change"
	KindRunAbort        = "run_abort"
	KindRunEnd          = "run_end"
)

// Kinds lists every event kind, in the order runs usually emit them.
func Kinds() []string {
	return []string{KindRunStart, KindPlanRejected, KindValue, KindCall, KindDecision, KindApprovalRequest, KindApproval,
		KindAttempt, KindHandoffSend, KindHandoffAccept, KindHandoffReject, KindEnvChange, KindRunAbort, KindRunEnd}
}

// Approval describes an approval request or answer.
type Approval struct {
	Key       policy.ApprovalKey  `json:"key"`
	State     string              `json:"state"`
	Approver  string              `json:"approver,omitempty"`
	ExpiresAt time.Time           `json:"expires_at"`
	Args      map[string]string   `json:"args,omitempty"`    // canonical arguments of the bound call
	Sources   map[string][]string `json:"sources,omitempty"` // each argument's sources
	Rule      string              `json:"rule,omitempty"`    // the rule that escalated
	Reason    string              `json:"reason,omitempty"`
}

// Event is one audit record.
type Event struct {
	Seq       int64              `json:"seq"`
	At        time.Time          `json:"at"`
	Run       string             `json:"run"`
	Config    string             `json:"config"` // C0 | C1-instr | C1-data | C2
	Agent     string             `json:"agent"`
	Kind      string             `json:"kind"`
	ValueID   string             `json:"value_id,omitempty"`
	ValueType string             `json:"value_type,omitempty"`
	Deps      []string           `json:"deps,omitempty"`
	Op        *authz.Op          `json:"op,omitempty"`
	Target    string             `json:"target,omitempty"`
	Sources   []string           `json:"sources,omitempty"`
	Trusted   bool               `json:"trusted"`
	PCTrusted bool               `json:"pc_trusted"`
	Decisions []policy.Decision  `json:"decisions,omitempty"` // every applicable rule, then the final verdict
	Evidence  *evidence.Counts   `json:"evidence,omitempty"`
	Attempt   *runstate.Attempt  `json:"attempt,omitempty"` // attempt events: Succeeded, Failed, or Uncertain; never a verdict
	Approval  *Approval          `json:"approval,omitempty"`
	Change    *EnvChange         `json:"change,omitempty"`
	Code      string             `json:"code,omitempty"` // reject or abort reason
	Detail    string             `json:"detail,omitempty"`
	Handoff   *HandoffInfo       `json:"handoff,omitempty"`
	Extra     map[string]float64 `json:"extra,omitempty"` // timings in milliseconds and similar measured numbers
}

// EnvChange is one environment difference after a run, with how the runtime
// saw the matching attempt.
type EnvChange struct {
	Tool    string `json:"tool"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"` // "executed" or "executed; runtime outcome unconfirmed"
}

// HandoffInfo describes a handoff envelope.
type HandoffInfo struct {
	ID     string   `json:"id"`
	From   string   `json:"from"`
	To     string   `json:"to"`
	Task   string   `json:"task"`
	Data   []string `json:"data,omitempty"` // "name:type"
	Bytes  int      `json:"bytes"`
	Status string   `json:"status,omitempty"`
}

// Sink receives events.
type Sink interface {
	Emit(e Event)
}

// Clock is the time source for event timestamps.
type Clock interface {
	Now() time.Time
}

// Log assigns sequence numbers and timestamps, then forwards each event to
// its sinks in order. It is safe for concurrent use.
type Log struct {
	mu    sync.Mutex
	seq   int64
	clock Clock
	sinks []Sink
}

// NewLog returns a log that stamps events with clock and fans out to sinks.
func NewLog(clock Clock, sinks ...Sink) *Log { return &Log{clock: clock, sinks: sinks} }

// Emit stamps and forwards one event.
func (l *Log) Emit(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq = l.seq
	if e.At.IsZero() {
		e.At = l.clock.Now()
	}
	for _, s := range l.sinks {
		s.Emit(e)
	}
}

// AddSink attaches another sink.
func (l *Log) AddSink(s Sink) {
	l.mu.Lock()
	l.sinks = append(l.sinks, s)
	l.mu.Unlock()
}

// Writer is a JSONL file sink. Close flushes and syncs the file; runs call
// it when they end.
type Writer struct {
	mu  sync.Mutex
	f   *os.File
	w   *bufio.Writer
	err error
}

// NewWriter creates or truncates path, creating its directory.
func NewWriter(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("events: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil, fmt.Errorf("events: %w", err)
	}
	return &Writer{f: f, w: bufio.NewWriter(f)}, nil
}

// Emit appends one JSON line. The first write error is kept and returned by
// Close, so nothing fails silently.
func (w *Writer) Emit(e Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return
	}
	b, err := json.Marshal(e)
	if err == nil {
		b = append(b, '\n')
		_, err = w.w.Write(b)
	}
	if err != nil {
		w.err = fmt.Errorf("events: write: %w", err)
	}
}

// Close flushes, syncs, and closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return w.err
	}
	err := w.err
	if ferr := w.w.Flush(); err == nil && ferr != nil {
		err = ferr
	}
	if serr := w.f.Sync(); err == nil && serr != nil {
		err = serr
	}
	if cerr := w.f.Close(); err == nil && cerr != nil {
		err = cerr
	}
	w.f = nil
	return err
}

// Recorder keeps events in memory, for tests and the invariant checker.
type Recorder struct {
	mu     sync.Mutex
	events []Event
}

// Emit records an event.
func (r *Recorder) Emit(e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

// Events returns a copy of the recorded events.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// Hub fans events out to server-sent-event subscribers. A subscriber that
// falls behind loses events rather than blocking the run: the dashboard can
// always replay the run's JSONL log.
type Hub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan Event]struct{}{}} }

// Emit sends e to every subscriber without blocking.
func (h *Hub) Emit(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe returns a channel of events and a function that unsubscribes.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 256)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// ReadFile parses a JSONL event log, for replay and table generation.
func ReadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("events: %w", err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for line := 1; sc.Scan(); line++ {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("events: %s line %d: %w", path, line, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("events: %s: %w", path, err)
	}
	return out, nil
}
