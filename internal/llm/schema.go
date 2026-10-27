package llm

import (
	"fmt"
	"slices"
	"strings"

	"citadel/internal/label"
	"citadel/internal/value"
)

// Registered processor schemas. Each decodes strictly into a Go type, and
// every field parses with the strict value parsers, so an ipv4 field cannot
// carry a sentence.
const (
	SchemaIOCList = "IOCList" // ips: list<ipv4>, accounts: list<account_id>
	SchemaReport  = "Report"  // text: text (C1 comparison handoffs only)
)

// MaxListItems bounds every list a processor returns.
const MaxListItems = 256

// IOCList is the typed indicator list the Investigator's processor extracts.
type IOCList struct {
	IPs      []string `json:"ips"`
	Accounts []string `json:"accounts"`
}

// Report is the free-text report of the C1 comparison handoffs.
type Report struct {
	Text string `json:"text"`
}

// Schemas returns the registered schemas: name -> field -> type.
func Schemas() map[string]map[string]value.Type {
	return map[string]map[string]value.Type{
		SchemaIOCList: {
			"ips":      value.ListOf(value.Scalar(value.KindIPv4)),
			"accounts": value.ListOf(value.Scalar(value.KindAccountID)),
		},
		SchemaReport: {"text": value.Scalar(value.KindText)},
	}
}

// SchemaDecls renders the registered schemas for planner input, sorted.
func SchemaDecls() []SchemaDecl {
	var out []SchemaDecl
	for name, fields := range Schemas() {
		d := SchemaDecl{Name: name}
		for f, t := range fields {
			d.Fields = append(d.Fields, DataDecl{Name: f, Type: t.String()})
		}
		slices.SortFunc(d.Fields, func(a, b DataDecl) int { return strings.Compare(a.Name, b.Name) })
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b SchemaDecl) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// DecodeOutput decodes processor output strictly into the registered Go type
// for schema and returns it as a struct value labeled l. Unknown fields
// (such as a "trusted" flag), duplicate keys, and values that fail strict
// parsing are ERR_DECODE.
func DecodeOutput(schema string, raw []byte, l label.Label) (value.Value, error) {
	lim := value.Limits{MaxBytes: 64 << 10, MaxDepth: 4, MaxStringBytes: value.MaxTextBytes, MaxArrayLen: MaxListItems}
	switch schema {
	case SchemaIOCList:
		var o IOCList
		if err := value.DecodeStrict(raw, &o, lim); err != nil {
			return value.Value{}, fmt.Errorf("%w: %s: %w", value.ErrDecode, schema, err)
		}
		ips, err := typedList(o.IPs, value.Scalar(value.KindIPv4), l)
		if err != nil {
			return value.Value{}, fmt.Errorf("%w: %s.ips: %w", value.ErrDecode, schema, err)
		}
		accts, err := typedList(o.Accounts, value.Scalar(value.KindAccountID), l)
		if err != nil {
			return value.Value{}, fmt.Errorf("%w: %s.accounts: %w", value.ErrDecode, schema, err)
		}
		return value.Struct(schema, []value.Field{{Name: "ips", Value: ips}, {Name: "accounts", Value: accts}}, l)
	case SchemaReport:
		var o Report
		if err := value.DecodeStrict(raw, &o, lim); err != nil {
			return value.Value{}, fmt.Errorf("%w: %s: %w", value.ErrDecode, schema, err)
		}
		t, err := value.Text(o.Text, l)
		if err != nil {
			return value.Value{}, fmt.Errorf("%w: %s.text: %w", value.ErrDecode, schema, err)
		}
		return value.Struct(schema, []value.Field{{Name: "text", Value: t}}, l)
	}
	return value.Value{}, fmt.Errorf("%w: unregistered schema %q", value.ErrDecode, value.Truncate(schema))
}

// typedList parses each string strictly. Duplicates are dropped in order of
// first appearance, so a processor cannot multiply one target.
func typedList(items []string, elem value.Type, l label.Label) (value.Value, error) {
	var elems []value.Value
	seen := map[string]bool{}
	for _, s := range items {
		v, err := value.FromString(s, elem, nil, l)
		if err != nil {
			return value.Value{}, err
		}
		if seen[v.Canonical()] {
			continue
		}
		seen[v.Canonical()] = true
		elems = append(elems, v)
	}
	return value.List(elem, elems, l)
}
