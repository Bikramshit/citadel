package runstate

import (
	"fmt"
	"sync"
	"time"

	"citadel/internal/value"
)

// ReplayState is a replay-table entry's state.
type ReplayState uint8

// Replay entry states.
const (
	Processing ReplayState = iota
	Accepted
	Rejected
)

// String names the state.
func (s ReplayState) String() string {
	switch s {
	case Processing:
		return "processing"
	case Accepted:
		return "accepted"
	case Rejected:
		return "rejected"
	}
	return "invalid"
}

type entry struct {
	digest [32]byte // SHA-256 of the exact payload bytes
	state  ReplayState
	code   string
	until  time.Time // expires_at plus skew
}

// Prior is the recorded outcome of an envelope already decided, returned for
// an identical retransmission.
type Prior struct {
	State ReplayState
	Code  string
}

// Result is the answer to an identical retransmission. Nothing is imported
// either way. A retransmission of an accepted envelope is answered with
// ERR_REPLAY and the recorded acceptance; one of a rejected envelope gets its
// recorded code again.
func (p Prior) Result() error {
	if p.State == Accepted {
		return fmt.Errorf("%w: identical retransmission; recorded result: accepted; nothing imported", value.ErrReplay)
	}
	return fmt.Errorf("%w: identical retransmission; recorded result: rejected", value.Code(p.Code))
}

// ReplayTable makes retransmissions idempotent on the receiver and keeps
// concurrent duplicates from both importing. Entries live until the
// envelope's expiry plus skew, which bounds the table by the lifetime limit.
type ReplayTable struct {
	mu sync.Mutex
	m  map[string]*entry
}

// NewReplayTable returns an empty table.
func NewReplayTable() *ReplayTable { return &ReplayTable{m: map[string]*entry{}} }

// Begin claims (from, id). A new pair is marked processing and Begin
// returns (nil, nil): verify and commit. The same ID with different bytes is
// ERR_REPLAY. A duplicate still being processed is ERR_IN_PROGRESS. Identical
// bytes already decided return the recorded outcome.
func (t *ReplayTable) Begin(from, id string, digest [32]byte, until, now time.Time) (*Prior, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.m {
		if e.state != Processing && now.After(e.until) {
			delete(t.m, k)
		}
	}
	k := from + "/" + id
	e, ok := t.m[k]
	switch {
	case !ok:
		t.m[k] = &entry{digest: digest, state: Processing, until: until}
		return nil, nil // first sight: verify and commit
	case e.digest != digest:
		return nil, fmt.Errorf("%w: envelope %s reused with different bytes", value.ErrReplay, value.Truncate(id)) // same ID, different bytes
	case e.state == Processing:
		return nil, fmt.Errorf("%w: envelope %s", value.ErrInProgress, value.Truncate(id))
	default:
		return &Prior{State: e.state, Code: e.code}, nil // identical retransmission: answer with the recorded result, import nothing
	}
}

// Finish records accepted (code "") or rejected with its code, under the
// same mutex. Finishing an unknown or already decided entry is an error.
func (t *ReplayTable) Finish(from, id, code string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[from+"/"+id]
	if !ok || e.state != Processing {
		return fmt.Errorf("replay entry %s/%s is not processing", from, value.Truncate(id))
	}
	if code == "" {
		e.state = Accepted
	} else {
		e.state, e.code = Rejected, code
	}
	return nil
}

// Len returns the number of entries, for tests.
func (t *ReplayTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}
