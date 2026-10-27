package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"
)

// ApprovalKey binds an approval to one exact call.
type ApprovalKey [32]byte

// String renders the key in hex.
func (k ApprovalKey) String() string { return hex.EncodeToString(k[:]) }

// MarshalText writes the key in hex.
func (k ApprovalKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText parses a hex key, for replaying event logs.
func (k *ApprovalKey) UnmarshalText(b []byte) error {
	if len(b) != 64 {
		return fmt.Errorf("approval key: want 64 hex characters")
	}
	_, err := hex.Decode(k[:], b)
	return err
}

// ApprovalPrefix is the domain prefix of approval keys.
const ApprovalPrefix = "citadel-approval-v1\x00"

// ApprovalFields are the inputs KeyFor binds, in encoding order. Args are
// encoded sorted by name, each as its canonical form.
type ApprovalFields struct {
	RunID, Principal string
	CtxHash          [32]byte
	PolicyVersion    string
	Agent            string
	Tool, Action     string
	Args             map[string]string // name -> canonical value
}

// EncodeApproval is the documented encoding KeyFor hashes: the domain
// prefix, then length-prefixed fields (uint32 big-endian length, then bytes)
// in this order: run ID, principal, context hash (raw 32 bytes), policy
// version, agent, tool, action; then each argument, sorted by name, as its
// length-prefixed name followed by its length-prefixed canonical value. The
// encoding is decodable, so distinct inputs cannot collide.
func EncodeApproval(f ApprovalFields) []byte {
	var b sliceWriter
	b.buf = append(b.buf, ApprovalPrefix...)
	for _, s := range []string{f.RunID, f.Principal, string(f.CtxHash[:]), f.PolicyVersion, f.Agent, f.Tool, f.Action} {
		b.lp(s)
	}
	for _, name := range slices.Sorted(maps.Keys(f.Args)) {
		b.lp(name)
		b.lp(f.Args[name])
	}
	return b.buf
}

type sliceWriter struct{ buf []byte }

func (w *sliceWriter) lp(s string) {
	w.buf = binary.BigEndian.AppendUint32(w.buf, uint32(len(s)))
	w.buf = append(w.buf, s...)
}

// KeyFor returns the approval key of a call: SHA-256 over EncodeApproval of
// its run, principal, context hash, policy version, agent, tool, action, and
// normalized arguments.
func KeyFor(c *CallCtx) ApprovalKey {
	return KeyForFields(FieldsOf(c))
}

// FieldsOf extracts the approval-bound fields of a call.
func FieldsOf(c *CallCtx) ApprovalFields {
	f := ApprovalFields{RunID: c.RunID, CtxHash: c.CtxHash, Agent: c.Agent, Tool: c.Op.Tool, Action: c.Op.Action, Args: map[string]string{}}
	if c.Ctx != nil {
		f.Principal, f.PolicyVersion = c.Ctx.Principal, c.Ctx.PolicyVersion
	}
	for name, v := range c.Args {
		f.Args[name] = v.Canonical() // netip.Addr.String(); validated account id
	}
	return f
}

// KeyForFields hashes approval fields.
func KeyForFields(f ApprovalFields) ApprovalKey {
	h := sha256.New()
	h.Write(EncodeApproval(f))
	var k ApprovalKey
	copy(k[:], h.Sum(nil))
	return k
}

// DecodeApproval parses an encoding produced by EncodeApproval. It exists so
// tests and fuzzing can show the encoding is injective.
func DecodeApproval(b []byte) (ApprovalFields, bool) {
	if len(b) < len(ApprovalPrefix) || string(b[:len(ApprovalPrefix)]) != ApprovalPrefix {
		return ApprovalFields{}, false
	}
	b = b[len(ApprovalPrefix):]
	next := func() (string, bool) {
		if len(b) < 4 {
			return "", false
		}
		n := binary.BigEndian.Uint32(b)
		if uint64(len(b)-4) < uint64(n) {
			return "", false
		}
		s := string(b[4 : 4+n])
		b = b[4+n:]
		return s, true
	}
	var parts [7]string
	for i := range parts {
		s, ok := next()
		if !ok {
			return ApprovalFields{}, false
		}
		parts[i] = s
	}
	if len(parts[2]) != 32 {
		return ApprovalFields{}, false
	}
	f := ApprovalFields{RunID: parts[0], Principal: parts[1], PolicyVersion: parts[3], Agent: parts[4], Tool: parts[5], Action: parts[6], Args: map[string]string{}}
	copy(f.CtxHash[:], parts[2])
	prev := ""
	for len(b) > 0 {
		name, ok := next()
		if !ok {
			return ApprovalFields{}, false
		}
		val, ok := next()
		if !ok {
			return ApprovalFields{}, false
		}
		if _, dup := f.Args[name]; dup || (len(f.Args) > 0 && name <= prev) {
			return ApprovalFields{}, false
		}
		f.Args[name], prev = val, name
	}
	return f, true
}

// ApprovalState is an approval's lifecycle state.
type ApprovalState uint8

// Approval states. Pending -> Granted -> Used, or Rejected, or Expired.
const (
	Pending ApprovalState = iota
	Granted
	Used
	Rejected
	Expired
)

// String names the state.
func (s ApprovalState) String() string {
	switch s {
	case Pending:
		return "pending"
	case Granted:
		return "granted"
	case Used:
		return "used"
	case Rejected:
		return "rejected"
	case Expired:
		return "expired"
	}
	return "invalid"
}

// MarshalText writes the state's name.
func (s ApprovalState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Approval is a request to authorize one exact call once. Its state changes
// only under the run lock, in runstate.
type Approval struct {
	Key       ApprovalKey   `json:"key"`
	Approver  string        `json:"approver"`   // must equal the context's principal
	ExpiresAt time.Time     `json:"expires_at"` // min(request time + 10 min, context expiry)
	State     ApprovalState `json:"state"`
}

// ApprovalLifetime is how long an approval request stays open at most.
const ApprovalLifetime = 10 * time.Minute
