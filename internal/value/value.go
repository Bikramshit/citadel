// Package value defines Citadel's typed, labeled values, the strict parsers
// that produce them, the strict JSON decoder, and the specification's error
// codes.
//
// A Value carries a provenance label that only grows: Joined adds sources and
// nothing removes one. The kinds are narrow on purpose: an IPv4 value can
// only hold an address that parsed strictly, so it cannot carry a sentence.
package value

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"citadel/internal/label"
)

// Kind is a value's kind.
type Kind uint8

// Value kinds.
const (
	KindInvalid Kind = iota
	KindUnit         // result of a state-changing call
	KindBool
	KindInt
	KindDuration
	KindIPv4
	KindAccountID
	KindHostname
	KindText
	KindEnum   // a literal enum string, such as an inventory key
	KindRecord // a log or flow record: named string fields
	KindList
	KindStruct // a registered processor schema
)

var kindNames = map[Kind]string{
	KindUnit: "unit", KindBool: "bool", KindInt: "int", KindDuration: "duration",
	KindIPv4: "ipv4", KindAccountID: "account_id", KindHostname: "hostname",
	KindText: "text", KindEnum: "enum", KindRecord: "record",
}

// Type describes a value's shape: a scalar kind, a list with an element type,
// or a struct named by its registered schema.
type Type struct {
	Kind Kind
	Elem *Type  // KindList
	Name string // KindStruct: schema name
}

// Scalar returns the type of a scalar kind.
func Scalar(k Kind) Type { return Type{Kind: k} }

// ListOf returns list<elem>.
func ListOf(elem Type) Type { return Type{Kind: KindList, Elem: &elem} }

// StructType returns the type of a registered schema.
func StructType(name string) Type { return Type{Kind: KindStruct, Name: name} }

// String renders the type as the specification writes it: "list<ipv4>".
func (t Type) String() string {
	switch t.Kind {
	case KindList:
		if t.Elem == nil {
			return "list<invalid>"
		}
		return "list<" + t.Elem.String() + ">"
	case KindStruct:
		return t.Name
	}
	if n, ok := kindNames[t.Kind]; ok {
		return n
	}
	return "invalid"
}

// Equal reports whether two types are identical.
func (t Type) Equal(u Type) bool {
	if t.Kind != u.Kind || t.Name != u.Name {
		return false
	}
	if t.Kind == KindList {
		return t.Elem != nil && u.Elem != nil && t.Elem.Equal(*u.Elem)
	}
	return true
}

// ParseType parses a type string such as "ipv4" or "list<account_id>".
// Struct types are written by schema name and must be registered with the
// caller; ParseType accepts names that start with an upper-case letter.
func ParseType(s string) (Type, error) {
	if inner, ok := strings.CutPrefix(s, "list<"); ok {
		inner, ok = strings.CutSuffix(inner, ">")
		if !ok {
			return Type{}, fmt.Errorf("%w: type %q", ErrType, truncate(s))
		}
		e, err := ParseType(inner)
		if err != nil {
			return Type{}, err
		}
		if e.Kind == KindList {
			return Type{}, fmt.Errorf("%w: nested list type %q", ErrType, truncate(s))
		}
		return ListOf(e), nil
	}
	for k, n := range kindNames {
		if n == s && k != KindUnit {
			return Scalar(k), nil
		}
	}
	if len(s) > 0 && len(s) <= 32 && s[0] >= 'A' && s[0] <= 'Z' {
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return Type{}, fmt.Errorf("%w: type %q", ErrType, truncate(s))
			}
		}
		return StructType(s), nil
	}
	return Type{}, fmt.Errorf("%w: unknown type %q", ErrType, truncate(s))
}

// Field is one named field of a struct or record value.
type Field struct {
	Name  string
	Value Value
}

// Value is an immutable, typed, labeled value.
type Value struct {
	typ    Type
	lbl    label.Label
	id     string
	b      bool
	i      int64
	d      time.Duration
	ip     netip.Addr
	s      string
	elems  []Value
	fields []Field // sorted by name
}

func mk(t Type, l label.Label) Value { return Value{typ: t, lbl: l} }

// Unit returns the result value of a state-changing call.
func Unit(l label.Label) Value { return mk(Scalar(KindUnit), l) }

// Bool returns a bool value.
func Bool(b bool, l label.Label) Value { v := mk(Scalar(KindBool), l); v.b = b; return v }

// Int returns an int value.
func Int(i int64, l label.Label) Value { v := mk(Scalar(KindInt), l); v.i = i; return v }

// Duration returns a duration value; d must be positive.
func Duration(d time.Duration, l label.Label) (Value, error) {
	if d <= 0 {
		return Value{}, fmt.Errorf("%w: duration must be positive", ErrType)
	}
	v := mk(Scalar(KindDuration), l)
	v.d = d
	return v, nil
}

// IPv4 returns an address value; a must be a plain IPv4 address.
func IPv4(a netip.Addr, l label.Label) (Value, error) {
	if !a.Is4() || a.Zone() != "" {
		return Value{}, fmt.Errorf("%w: not an IPv4 address", ErrType)
	}
	v := mk(Scalar(KindIPv4), l)
	v.ip = a
	return v, nil
}

// AccountID returns an account value after strict validation.
func AccountID(s string, l label.Label) (Value, error) {
	if _, err := ParseAccountID(s); err != nil {
		return Value{}, err
	}
	v := mk(Scalar(KindAccountID), l)
	v.s = s
	return v, nil
}

// Hostname returns a host value after strict validation against known.
func Hostname(s string, known HostSet, l label.Label) (Value, error) {
	if _, err := ParseHostname(s, known); err != nil {
		return Value{}, err
	}
	v := mk(Scalar(KindHostname), l)
	v.s = s
	return v, nil
}

// Text returns a free-text value after validation.
func Text(s string, l label.Label) (Value, error) {
	if _, err := ParseText(s, MaxTextBytes); err != nil {
		return Value{}, err
	}
	v := mk(Scalar(KindText), l)
	v.s = s
	return v, nil
}

// Enum returns an enum literal value.
func Enum(s string, l label.Label) Value { v := mk(Scalar(KindEnum), l); v.s = s; return v }

// List returns a list of elements that all have type elem. The list's label
// applies to every element as well: Elems joins it in.
func List(elem Type, elems []Value, l label.Label) (Value, error) {
	for _, e := range elems {
		if !e.typ.Equal(elem) {
			return Value{}, fmt.Errorf("%w: list<%s> element of type %s", ErrType, elem, e.typ)
		}
	}
	v := mk(ListOf(elem), l)
	v.elems = slices.Clone(elems)
	return v, nil
}

// Struct returns a struct value of a registered schema.
func Struct(name string, fields []Field, l label.Label) (Value, error) {
	v := mk(StructType(name), l)
	if err := v.setFields(fields); err != nil {
		return Value{}, err
	}
	return v, nil
}

// Record returns a record value with string fields, such as a log record.
func Record(fields map[string]string, l label.Label) Value {
	fs := make([]Field, 0, len(fields))
	for k, s := range fields {
		fs = append(fs, Field{Name: k, Value: Value{typ: Scalar(KindText), lbl: l, s: s}})
	}
	v := mk(Scalar(KindRecord), l)
	_ = v.setFields(fs) // names come from a map, so they are unique
	return v
}

func (v *Value) setFields(fields []Field) error {
	fs := slices.Clone(fields)
	slices.SortFunc(fs, func(a, b Field) int { return strings.Compare(a.Name, b.Name) })
	for i := 1; i < len(fs); i++ {
		if fs[i].Name == fs[i-1].Name {
			return fmt.Errorf("%w: duplicate field %q", ErrType, fs[i].Name)
		}
	}
	v.fields = fs
	return nil
}

// Type returns the value's type.
func (v Value) Type() Type { return v.typ }

// Kind returns the value's kind.
func (v Value) Kind() Kind { return v.typ.Kind }

// Label returns the value's provenance label.
func (v Value) Label() label.Label { return v.lbl }

// ID returns the runtime-assigned value ID used in events, or "".
func (v Value) ID() string { return v.id }

// WithID returns a copy of v with a runtime-assigned ID. IDs are audit
// handles, not labels; they never change trust.
func (v Value) WithID(id string) Value { v.id = id; return v }

// Joined returns a copy of v whose label is Join(v's label, l). Labels only
// grow.
func (v Value) Joined(l label.Label) Value { v.lbl = label.Join(v.lbl, l); return v }

// Valid reports whether v was built by a constructor.
func (v Value) Valid() bool { return v.typ.Kind != KindInvalid }

// AsBool returns a bool value's contents.
func (v Value) AsBool() (bool, bool) { return v.b, v.typ.Kind == KindBool }

// AsDuration returns a duration value's contents.
func (v Value) AsDuration() (time.Duration, bool) { return v.d, v.typ.Kind == KindDuration }

// AsIPv4 returns an address value's contents.
func (v Value) AsIPv4() (netip.Addr, bool) { return v.ip, v.typ.Kind == KindIPv4 }

// AsString returns the contents of an account, host, text, or enum value.
func (v Value) AsString() (string, bool) {
	switch v.typ.Kind {
	case KindAccountID, KindHostname, KindText, KindEnum:
		return v.s, true
	}
	return "", false
}

// Elems returns a list's elements, each joined with the list's label.
func (v Value) Elems() []Value {
	out := make([]Value, len(v.elems))
	for i, e := range v.elems {
		out[i] = e.Joined(v.lbl)
	}
	return out
}

// Count returns the number of elements of a list. The runtime uses it for the
// iteration budget; it is never shown to a planner.
func (v Value) Count() int { return len(v.elems) }

// FieldValue returns a struct or record field, joined with the value's label.
func (v Value) FieldValue(name string) (Value, bool) {
	i, ok := slices.BinarySearchFunc(v.fields, name, func(f Field, n string) int { return strings.Compare(f.Name, n) })
	if !ok {
		return Value{}, false
	}
	return v.fields[i].Value.Joined(v.lbl), true
}

// Fields returns a copy of a struct or record's fields, sorted by name.
func (v Value) Fields() []Field { return slices.Clone(v.fields) }

// Canonical returns the value's canonical string: netip.Addr.String() for
// addresses, the validated string for accounts and hosts, and an injective
// JSON encoding for lists and structs. Approval and idempotency keys hash it.
func (v Value) Canonical() string {
	switch v.typ.Kind {
	case KindUnit:
		return ""
	case KindBool:
		return strconv.FormatBool(v.b)
	case KindInt:
		return strconv.FormatInt(v.i, 10)
	case KindDuration:
		return FormatDuration(v.d)
	case KindIPv4:
		return v.ip.String()
	case KindAccountID, KindHostname, KindText, KindEnum:
		return v.s
	case KindList:
		parts := make([]string, len(v.elems))
		for i, e := range v.elems {
			parts[i] = e.Canonical()
		}
		b, _ := json.Marshal(parts) // []string always marshals
		return string(b)
	case KindRecord, KindStruct:
		m := make(map[string]string, len(v.fields))
		for _, f := range v.fields {
			m[f.Name] = f.Value.Canonical()
		}
		b, _ := json.Marshal(m) // map[string]string always marshals, keys sorted
		return string(b)
	}
	return ""
}

// Equal reports whether two values have the same type and canonical form.
// Labels are not compared.
func (v Value) Equal(u Value) bool {
	return v.typ.Equal(u.typ) && v.Canonical() == u.Canonical()
}

// FromJSON parses raw strictly as a value of type t with label l. Strings
// must already be canonical; nothing is normalized. Hosts are checked
// against known when it is not nil. Struct and record types are refused:
// those come only from registered processor schemas.
func FromJSON(raw json.RawMessage, t Type, known HostSet, l label.Label) (Value, error) {
	switch t.Kind {
	case KindBool:
		var b bool
		if err := DecodeStrict(raw, &b, Limits{MaxBytes: 16}); err != nil {
			return Value{}, fmt.Errorf("%w: bool: %v", ErrType, err)
		}
		return Bool(b, l), nil
	case KindInt:
		var i int64
		if err := DecodeStrict(raw, &i, Limits{MaxBytes: 32}); err != nil {
			return Value{}, fmt.Errorf("%w: int: %v", ErrType, err)
		}
		return Int(i, l), nil
	case KindList:
		var raws []json.RawMessage
		if err := DecodeStrict(raw, &raws, Limits{MaxBytes: 1 << 16}); err != nil {
			return Value{}, fmt.Errorf("%w: %s: %v", ErrType, t, err)
		}
		elems := make([]Value, len(raws))
		for i, r := range raws {
			e, err := FromJSON(r, *t.Elem, known, l)
			if err != nil {
				return Value{}, err
			}
			elems[i] = e
		}
		return List(*t.Elem, elems, l)
	case KindDuration, KindIPv4, KindAccountID, KindHostname, KindText, KindEnum:
		var s string
		if err := DecodeStrict(raw, &s, Limits{MaxBytes: MaxTextBytes * 2}); err != nil {
			return Value{}, fmt.Errorf("%w: %s: %v", ErrType, t, err)
		}
		return FromString(s, t, known, l)
	}
	return Value{}, fmt.Errorf("%w: cannot decode type %s from JSON", ErrType, t)
}

// FromString parses s strictly as a scalar of type t.
func FromString(s string, t Type, known HostSet, l label.Label) (Value, error) {
	switch t.Kind {
	case KindDuration:
		d, err := ParseDuration(s)
		if err != nil {
			return Value{}, err
		}
		return Duration(d, l)
	case KindIPv4:
		a, err := ParseIPv4(s)
		if err != nil {
			return Value{}, err
		}
		return IPv4(a, l)
	case KindAccountID:
		return AccountID(s, l)
	case KindHostname:
		return Hostname(s, known, l)
	case KindText:
		return Text(s, l)
	case KindEnum:
		if len(s) == 0 || len(s) > 64 || !utf8.ValidString(s) {
			return Value{}, fmt.Errorf("%w: enum %q", ErrType, truncate(s))
		}
		return Enum(s, l), nil
	}
	return Value{}, fmt.Errorf("%w: cannot parse type %s from a string", ErrType, t)
}

// ToJSON renders the value's contents as canonical JSON (lists as arrays of
// canonical strings, scalars as strings or booleans). It carries no label.
func (v Value) ToJSON() json.RawMessage {
	var x any
	switch v.typ.Kind {
	case KindBool:
		x = v.b
	case KindInt:
		x = v.i
	case KindList:
		parts := make([]json.RawMessage, len(v.elems))
		for i, e := range v.elems {
			parts[i] = e.ToJSON()
		}
		x = parts
	case KindRecord, KindStruct:
		m := make(map[string]json.RawMessage, len(v.fields))
		for _, f := range v.fields {
			m[f.Name] = f.Value.ToJSON()
		}
		x = m
	default:
		x = v.Canonical()
	}
	b, _ := json.Marshal(x) // built only from marshalable parts
	return b
}
