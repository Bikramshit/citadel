package events

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"citadel/internal/authz"
	"citadel/internal/policy"
	"citadel/internal/runstate"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func TestLogWriterRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "events.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := &Recorder{}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	l := NewLog(fixedClock{now}, w, rec)
	op := authz.Op{Tool: "firewall", Action: "block"}
	l.Emit(Event{Kind: KindDecision, Op: &op, Target: "203.0.113.7", Decisions: []policy.Decision{{Verdict: policy.Deny, Rule: "A3", Group: "A"}}})
	l.Emit(Event{Kind: KindAttempt, Attempt: &runstate.Attempt{Op: op, Target: "203.0.113.7", State: runstate.Uncertain}})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); l.Emit(Event{Kind: KindValue}) }()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal("second close")
	}
	evs, err := ReadFile(path)
	if err != nil || len(evs) != 22 {
		t.Fatalf("read %d events: %v", len(evs), err)
	}
	for i, e := range evs {
		if e.Seq != int64(i+1) || !e.At.Equal(now) {
			t.Fatalf("event %d seq %d at %v", i, e.Seq, e.At)
		}
	}
	if evs[0].Decisions[0].Verdict != policy.Deny || evs[1].Attempt.State != runstate.Uncertain {
		t.Fatal("verdicts and attempt states must round trip")
	}
	if len(rec.Events()) != 22 {
		t.Fatal("recorder")
	}
	l.AddSink(&Recorder{})
	if _, err := ReadFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.jsonl")
	os.WriteFile(bad, []byte("{\n"), 0o644)
	if _, err := ReadFile(bad); err == nil {
		t.Fatal("bad line")
	}
	if _, err := NewWriter(filepath.Join(bad, "x", "y")); err == nil {
		t.Fatal("writer under a file")
	}
	if len(Kinds()) != 14 {
		t.Fatal("kinds")
	}
}

func TestHubFanOutDoesNotBlock(t *testing.T) {
	h := NewHub()
	a, cancelA := h.Subscribe()
	_, cancelB := h.Subscribe()
	for i := 0; i < 1000; i++ { // more than the buffer: the slow subscriber loses events, the run never blocks
		h.Emit(Event{Seq: int64(i)})
	}
	if e := <-a; e.Seq != 0 {
		t.Fatal("first event")
	}
	cancelA()
	cancelA()
	cancelB()
	h.Emit(Event{})
}
