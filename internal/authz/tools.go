package authz

import (
	"slices"

	"citadel/internal/value"
)

// ArgSpec describes one argument of a tool call.
type ArgSpec struct {
	Name   string
	Types  []value.Type // accepted types, first is canonical
	Target bool         // the resource the call acts on; I2 applies
	Host   bool         // a host the call reads from; A2 checks it against the scope
}

// Accepts reports whether t is one of the argument's types.
func (a ArgSpec) Accepts(t value.Type) bool {
	return slices.ContainsFunc(a.Types, func(u value.Type) bool { return u.Equal(t) })
}

// ToolSpec is the fixed signature of one tool and action.
type ToolSpec struct {
	Op            Op
	Args          []ArgSpec
	StateChanging bool                  // sensitive: A4, A5, F3, idempotency keys
	Output        value.Type            // result type; KindUnit for state-changing calls
	OutputByKey   map[string]value.Type // inventory.read: result type per key
	Sink          string                // C1: who receives the arguments; "" for reads
}

// Arg returns the named argument spec.
func (s ToolSpec) Arg(name string) (ArgSpec, bool) {
	i := slices.IndexFunc(s.Args, func(a ArgSpec) bool { return a.Name == name })
	if i < 0 {
		return ArgSpec{}, false
	}
	return s.Args[i], true
}

// TargetArg returns the name of the target argument, or "" if the call has
// none.
func (s ToolSpec) TargetArg() string {
	for _, a := range s.Args {
		if a.Target {
			return a.Name
		}
	}
	return ""
}

// InventoryKeys are the keys inventory.read accepts, with their result types.
func InventoryKeys() map[string]value.Type {
	return map[string]value.Type{
		"hosts":              value.ListOf(value.Scalar(value.KindHostname)),
		"protected_accounts": value.ListOf(value.Scalar(value.KindAccountID)),
		"protected_ips":      value.ListOf(value.Scalar(value.KindIPv4)),
		"partner_ips":        value.ListOf(value.Scalar(value.KindIPv4)),
	}
}

// Actions returns the literal action enum of a tool, or nil for an unknown
// tool. Rule I3 checks plan actions against it.
func Actions(tool string) []string {
	switch tool {
	case "logs", "inventory":
		return []string{"read"}
	case "firewall":
		return []string{"block", "allow"}
	case "accounts":
		return []string{"disable"}
	case "handoff":
		return []string{"request"}
	}
	return nil
}

// Spec returns the signature of a callable tool operation. handoff.request is
// a capability but not a callable tool: plans use the handoff statement.
func Spec(op Op) (ToolSpec, bool) {
	host := value.Scalar(value.KindHostname)
	ipv4 := value.Scalar(value.KindIPv4)
	unit := value.Scalar(value.KindUnit)
	switch op {
	case Op{"logs", "read"}:
		return ToolSpec{Op: op, Args: []ArgSpec{
			{Name: "host", Types: []value.Type{host, value.ListOf(host)}, Host: true},
			{Name: "window", Types: []value.Type{value.Scalar(value.KindDuration)}},
		}, Output: value.ListOf(value.Scalar(value.KindRecord))}, true
	case Op{"inventory", "read"}:
		return ToolSpec{Op: op, Args: []ArgSpec{
			{Name: "key", Types: []value.Type{value.Scalar(value.KindEnum)}},
		}, OutputByKey: InventoryKeys()}, true
	case Op{"firewall", "block"}, Op{"firewall", "allow"}:
		return ToolSpec{Op: op, Args: []ArgSpec{{Name: "ip", Types: []value.Type{ipv4}, Target: true}},
			StateChanging: true, Output: unit, Sink: "internal"}, true
	case Op{"accounts", "disable"}:
		return ToolSpec{Op: op, Args: []ArgSpec{{Name: "account", Types: []value.Type{value.Scalar(value.KindAccountID)}, Target: true}},
			StateChanging: true, Output: unit, Sink: "internal"}, true
	}
	return ToolSpec{}, false
}

// IsStateChanging reports whether op changes state in the environment.
func IsStateChanging(op Op) bool {
	s, ok := Spec(op)
	return ok && s.StateChanging
}
