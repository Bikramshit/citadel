package value

import (
	"sync"
	"time"
)

// Clock is the only source of time for Citadel components, so tests and
// fixture runs control it.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the wall clock in UTC.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// ManualClock is a clock that moves only when told to. Fixture runs use it
// to replay a fixture at the fixture's own time, and tests use it to cross
// expiry boundaries deterministically. It is safe for concurrent use.
type ManualClock struct {
	mu sync.Mutex
	t  time.Time
}

// NewManualClock returns a clock reading t.
func NewManualClock(t time.Time) *ManualClock { return &ManualClock{t: t.UTC()} }

// Now returns the clock's time.
func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward by d.
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Set moves the clock to t.
func (c *ManualClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t.UTC()
	c.mu.Unlock()
}

// OffsetClock maps wall time onto another timeline: it reads Base plus the
// wall time elapsed since Epoch. Processes that share Base and Epoch share
// a timeline, which lets a multi-process demo replay a fixture at the
// fixture's own time while time still passes.
type OffsetClock struct {
	Base  time.Time
	Epoch time.Time
	Wall  func() time.Time // time.Now outside tests
}

// Now returns Base plus the wall time since Epoch.
func (c OffsetClock) Now() time.Time { return c.Base.Add(c.Wall().Sub(c.Epoch)).UTC() }
