// Package label implements Citadel's provenance labels.
//
// Labels answer only the integrity question: did attacker-influenced data
// shape this value? They only grow. The runtime assigns them, no model output
// contains them, and nothing in this package's API removes a source. A Label
// has unexported fields; its only constructors (New, Join, and the readers
// variants) add sources.
package label

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
)

// SourceKind identifies where a value came from.
type SourceKind uint8

// Source kinds, in the specification's order.
const (
	SrcTaskParam      SourceKind = iota + 1 // trusted; may name targets
	SrcUserNote                             // trusted; no authority
	SrcPlannerLiteral                       // trusted; may not name targets
	SrcRuntime                              // trusted
	SrcTool                                 // Name = "logs.read" | "inventory.read"
	SrcQLLM                                 // untrusted; Name = agent
	SrcPeer                                 // untrusted; Name = envelope id, From = sender
	SrcClaimed                              // untrusted; a source name a peer claimed, kept for audit
)

var kindNames = map[SourceKind]string{
	SrcTaskParam:      "task_param",
	SrcUserNote:       "user_note",
	SrcPlannerLiteral: "planner_literal",
	SrcRuntime:        "runtime",
	SrcTool:           "tool",
	SrcQLLM:           "qllm",
	SrcPeer:           "peer",
	SrcClaimed:        "claimed",
}

// String returns the kind's stable name, as written to the event log.
func (k SourceKind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return "invalid"
}

// Source is one origin of a value.
type Source struct {
	Kind SourceKind
	Name string
	From string
}

// TaskParam is the source of an analyst's typed parameter.
func TaskParam(name string) Source { return Source{Kind: SrcTaskParam, Name: name} }

// UserNote is the source of the analyst's free-text note.
func UserNote() Source { return Source{Kind: SrcUserNote} }

// PlannerLiteral is the source of a literal written in agent's plan.
func PlannerLiteral(agent string) Source { return Source{Kind: SrcPlannerLiteral, Name: agent} }

// Runtime is the source of values the runtime generates.
func Runtime() Source { return Source{Kind: SrcRuntime} }

// Tool is the source of a tool's output, named "tool.action".
func Tool(name string) Source { return Source{Kind: SrcTool, Name: name} }

// QLLM is the source of any processor output in agent's process.
func QLLM(agent string) Source { return Source{Kind: SrcQLLM, Name: agent} }

// Peer is the source of every value imported from envelope id sent by from.
func Peer(from, id string) Source { return Source{Kind: SrcPeer, Name: id, From: from} }

// Claimed records a source name that a peer claimed for an imported value.
func Claimed(name string) Source { return Source{Kind: SrcClaimed, Name: name} }

// String renders the source in the event-log form, for example
// "tool:logs.read" or "peer:investigator/<id>".
func (s Source) String() string {
	var b strings.Builder
	b.WriteString(s.Kind.String())
	switch {
	case s.From != "":
		b.WriteString(":" + s.From + "/" + s.Name)
	case s.Name != "":
		b.WriteString(":" + s.Name)
	}
	return b.String()
}

func compareSource(a, b Source) int {
	if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	return cmp.Compare(a.From, b.From)
}

// trustedKind reports whether a kind is trusted for integrity on its own.
// SrcTool depends on the TrustTable.
func trustedKind(k SourceKind) bool {
	switch k {
	case SrcTaskParam, SrcUserNote, SrcPlannerLiteral, SrcRuntime:
		return true
	default:
		return false
	}
}

// TrustTable lists the tools whose outputs are trusted for integrity.
type TrustTable struct {
	TrustedTools map[string]bool // {"inventory.read": true}
}

// DefaultTrust is the trust table of the specification: only the inventory,
// the trusted system of record, is a trusted tool.
func DefaultTrust() TrustTable {
	return TrustTable{TrustedTools: map[string]bool{"inventory.read": true}}
}

// Trusted reports whether s is trusted for integrity under t.
func (t TrustTable) Trusted(s Source) bool {
	if s.Kind == SrcTool {
		return t.TrustedTools[s.Name]
	}
	return trustedKind(s.Kind)
}

// readers is the confidentiality half of a label: either everyone (all) or a
// sorted, deduplicated set of reader principals.
type readers struct {
	restricted bool
	set        []string
}

func (r readers) includes(reader string) bool {
	if !r.restricted {
		return true
	}
	_, ok := slices.BinarySearch(r.set, reader)
	return ok
}

func meetReaders(a, b readers) readers {
	switch {
	case !a.restricted:
		return b
	case !b.restricted:
		return a
	}
	out := make([]string, 0, min(len(a.set), len(b.set)))
	for _, x := range a.set {
		if _, ok := slices.BinarySearch(b.set, x); ok {
			out = append(out, x)
		}
	}
	return readers{restricted: true, set: out}
}

// Label is immutable. Its fields are unexported and no function removes a
// source.
type Label struct {
	srcs    []Source // sorted, deduplicated
	readers readers
}

// New returns a label with the given sources, readable by everyone.
func New(s ...Source) Label {
	srcs := slices.Clone(s)
	slices.SortFunc(srcs, compareSource)
	srcs = slices.CompactFunc(srcs, func(a, b Source) bool { return compareSource(a, b) == 0 })
	return Label{srcs: srcs}
}

// NewRestricted returns a label with the given sources whose readers are
// limited to the named principals.
func NewRestricted(readersList []string, s ...Source) Label {
	l := New(s...)
	set := slices.Clone(readersList)
	slices.Sort(set)
	l.readers = readers{restricted: true, set: slices.Compact(set)}
	return l
}

// Join returns the union of the inputs' sources and the intersection of their
// readers. A derived value takes this label.
func Join(ls ...Label) Label {
	n := 0
	for _, l := range ls {
		n += len(l.srcs)
	}
	srcs := make([]Source, 0, n)
	r := readers{}
	for _, l := range ls {
		srcs = append(srcs, l.srcs...)
		r = meetReaders(r, l.readers)
	}
	out := New(srcs...)
	out.readers = r
	return out
}

// Sources returns a copy of the label's sources, sorted.
func (l Label) Sources() []Source { return slices.Clone(l.srcs) }

// Len returns the number of distinct sources.
func (l Label) Len() int { return len(l.srcs) }

// Has reports whether any source has kind k.
func (l Label) Has(k SourceKind) bool {
	return slices.ContainsFunc(l.srcs, func(s Source) bool { return s.Kind == k })
}

// HasUntrusted reports whether any source is untrusted under t.
func (l Label) HasUntrusted(t TrustTable) bool {
	return slices.ContainsFunc(l.srcs, func(s Source) bool { return !t.Trusted(s) })
}

// Trusted is true only if the label has at least one source and every source
// is trusted under t. A label with no sources is never trusted: the runtime
// gives every value a source, so an empty label means something went wrong.
func (l Label) Trusted(t TrustTable) bool {
	return len(l.srcs) > 0 && !l.HasUntrusted(t)
}

// ReadableBy reports whether reader may read a value with this label.
func (l Label) ReadableBy(reader string) bool { return l.readers.includes(reader) }

// Restricted reports whether the label limits its readers, and returns a copy
// of the reader set when it does.
func (l Label) Restricted() (bool, []string) {
	return l.readers.restricted, slices.Clone(l.readers.set)
}

// Strings renders every source in event-log form.
func (l Label) Strings() []string {
	out := make([]string, len(l.srcs))
	for i, s := range l.srcs {
		out[i] = s.String()
	}
	return out
}

// String renders the label for logs.
func (l Label) String() string { return "{" + strings.Join(l.Strings(), ",") + "}" }

// MarshalJSON writes the label's sources for the audit log. Label has no
// UnmarshalJSON: decoding never produces a label, so no serialization can
// upgrade trust.
func (l Label) MarshalJSON() ([]byte, error) { return json.Marshal(l.Strings()) }
