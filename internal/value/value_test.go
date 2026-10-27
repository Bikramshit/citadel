package value

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"citadel/internal/label"
)

func TestParseIPv4Strict(t *testing.T) {
	good := []string{"203.0.113.7", "10.0.0.53", "0.0.0.0", "255.255.255.255", "192.0.2.10"}
	for _, s := range good {
		a, err := ParseIPv4(s)
		if err != nil || a.String() != s {
			t.Errorf("%q: %v %v", s, a, err)
		}
	}
	bad := []string{
		"", "203.0.113.007", "203.0.113.7 ", " 203.0.113.7", "203.0.113", "203.0.113.7.1",
		"::ffff:203.0.113.7", "::1", "2001:db8::1", "fe80::1%eth0", "203.0.113.256",
		"0x7f.0.0.1", "1.2.3.4/24", "01.2.3.4", "1.2.3.4%en0", "1.2.3.-4", "１.2.3.4",
	}
	for _, s := range bad {
		if _, err := ParseIPv4(s); !errors.Is(err, ErrType) {
			t.Errorf("%q accepted or wrong error: %v", s, err)
		}
	}
}

func TestParseAccountID(t *testing.T) {
	for _, s := range []string{"jdoe", "svc-backup", "admin-alice", "breakglass", "a1", strings.Repeat("a", 32)} {
		if got, err := ParseAccountID(s); err != nil || got != s {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "a", "1abc", "Jdoe", "j doe", "jdoe\n", "-a", strings.Repeat("a", 33), "jdoe;rm", "jdöe", "_x"} {
		if _, err := ParseAccountID(s); !errors.Is(err, ErrType) {
			t.Errorf("%q accepted: %v", s, err)
		}
	}
}

type hosts map[string]bool

func (h hosts) HostExists(n string) bool { return h[n] }

func TestParseHostname(t *testing.T) {
	inv := hosts{"web-03": true, "web-04": true}
	if _, err := ParseHostname("web-03", inv); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHostname("web-99", inv); !errors.Is(err, ErrType) {
		t.Fatalf("unknown host accepted: %v", err)
	}
	if _, err := ParseHostname("web-99", nil); err != nil {
		t.Fatalf("syntax-only check: %v", err)
	}
	for _, s := range []string{"", "Web-03", "web_03", "-web", "web-", "web.03", strings.Repeat("a", 64)} {
		if _, err := ParseHostname(s, nil); !errors.Is(err, ErrType) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{"1h": time.Hour, "30m": 30 * time.Minute, "1h30m": 90 * time.Minute, "24h": 24 * time.Hour, "45s": 45 * time.Second, "1h0m5s": time.Hour + 5*time.Second}
	for s, want := range cases {
		got, err := ParseDuration(s)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", s, got, err)
		}
		if back, err := ParseDuration(FormatDuration(got)); err != nil || back != got {
			t.Errorf("%q does not round trip: %q", s, FormatDuration(got))
		}
	}
	for _, s := range []string{"", "0h", "1.5h", "-1h", "1d", "30m1h", "1h1h", "h", "1", "1H", "1000000h"} {
		if _, err := ParseDuration(s); !errors.Is(err, ErrType) {
			t.Errorf("%q accepted", s)
		}
	}
	if FormatDuration(0) != "0s" {
		t.Fatal("FormatDuration(0)")
	}
}

func TestParseText(t *testing.T) {
	if _, err := ParseText("ok", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseText(strings.Repeat("x", 11), 10); !errors.Is(err, ErrType) {
		t.Fatal("long text accepted")
	}
	if _, err := ParseText("\xff", 10); !errors.Is(err, ErrType) {
		t.Fatal("invalid UTF-8 accepted")
	}
	if Truncate(strings.Repeat("y", 100)) != strings.Repeat("y", 64)+"..." {
		t.Fatal("Truncate")
	}
}

func TestDecodeStrict(t *testing.T) {
	type inner struct {
		A string `json:"a"`
	}
	type outer struct {
		KID  string   `json:"kid"`
		List []string `json:"list"`
		In   *inner   `json:"in"`
	}
	ok := `{"kid":"k","list":["x","y"],"in":{"a":"b"}}`
	var o outer
	if err := DecodeStrict([]byte(ok), &o, Limits{}); err != nil || o.KID != "k" || o.In.A != "b" {
		t.Fatalf("valid input: %v %+v", err, o)
	}
	cases := []struct {
		name, in string
		lim      Limits
		want     error
	}{
		{"duplicate key", `{"kid":"a","kid":"b"}`, Limits{}, ErrSchema},
		{"duplicate nested", `{"in":{"a":"1","a":"2"}}`, Limits{}, ErrSchema},
		{"case variant key", `{"kid":"a","KID":"b"}`, Limits{AnyKeyCase: true}, ErrSchema},
		{"kelvin sign key", "{\"kid\":\"a\",\"Kid\":\"b\"}", Limits{AnyKeyCase: true}, ErrSchema},
		{"upper-case key", `{"KID":"a"}`, Limits{}, ErrSchema},
		{"unknown field", `{"kid":"a","note":"hi"}`, Limits{}, ErrSchema},
		{"trailing value", `{"kid":"a"} {"kid":"b"}`, Limits{}, ErrSchema},
		{"trailing garbage", `{"kid":"a"}x`, Limits{}, ErrSchema},
		{"top-level array", `[{"kid":"a"}]`, Limits{}, ErrSchema},
		{"invalid utf8", "{\"kid\":\"\xff\"}", Limits{}, ErrSchema},
		{"empty", ``, Limits{}, ErrSchema},
		{"truncated", `{"kid":"a"`, Limits{}, ErrSchema},
		{"too big", `{"kid":"aaaaaaaaaa"}`, Limits{MaxBytes: 10}, ErrSize},
		{"too deep", `{"in":{"a":"b"}}`, Limits{MaxDepth: 1}, ErrSchema},
		{"long string", `{"kid":"aaaaa"}`, Limits{MaxStringBytes: 4}, ErrSchema},
		{"long array", `{"list":["a","b","c"]}`, Limits{MaxArrayLen: 2}, ErrSchema},
		{"wrong type", `{"kid":5}`, Limits{}, ErrSchema},
		{"non-string key", `{5:"a"}`, Limits{}, ErrSchema},
	}
	for _, c := range cases {
		var o outer
		if err := DecodeStrict([]byte(c.in), &o, c.lim); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	var arr []int
	if err := DecodeStrict([]byte(`[[1],2]`), &arr, Limits{}); !errors.Is(err, ErrSchema) {
		t.Errorf("nested array into []int: %v", err)
	}
	if err := DecodeStrict([]byte(`[1,2,3]`), &arr, Limits{}); err != nil || len(arr) != 3 {
		t.Errorf("array: %v", err)
	}
}

func TestValueConstructorsAndCanonical(t *testing.T) {
	l := label.New(label.QLLM("investigator"))
	a, _ := ParseIPv4("203.0.113.7")
	ip, err := IPv4(a, l)
	if err != nil || ip.Canonical() != "203.0.113.7" || ip.Kind() != KindIPv4 {
		t.Fatalf("ipv4: %v %v", ip, err)
	}
	if _, err := IPv4(netip.MustParseAddr("::ffff:1.2.3.4"), l); !errors.Is(err, ErrType) {
		t.Fatal("mapped address accepted")
	}
	acct, _ := AccountID("jdoe", l)
	if s, ok := acct.AsString(); !ok || s != "jdoe" {
		t.Fatal("account")
	}
	if _, err := AccountID("Bad", l); err == nil {
		t.Fatal("bad account accepted")
	}
	lst, err := List(Scalar(KindIPv4), []Value{ip}, label.New(label.Peer("investigator", "e1")))
	if err != nil {
		t.Fatal(err)
	}
	el := lst.Elems()[0]
	if !el.Label().Has(label.SrcPeer) || !el.Label().Has(label.SrcQLLM) {
		t.Fatalf("element must join the list label: %v", el.Label())
	}
	if lst.Canonical() != `["203.0.113.7"]` || lst.Count() != 1 {
		t.Fatalf("list canonical %s", lst.Canonical())
	}
	if _, err := List(Scalar(KindIPv4), []Value{acct}, l); !errors.Is(err, ErrType) {
		t.Fatal("mixed list accepted")
	}
	st, err := Struct("IOCList", []Field{{Name: "ips", Value: lst}}, l)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := st.FieldValue("ips")
	if !ok || f.Count() != 1 {
		t.Fatal("field")
	}
	if _, ok := st.FieldValue("nope"); ok {
		t.Fatal("missing field found")
	}
	if _, err := Struct("X", []Field{{Name: "a", Value: ip}, {Name: "a", Value: ip}}, l); !errors.Is(err, ErrType) {
		t.Fatal("duplicate field accepted")
	}
	rec := Record(map[string]string{"user_agent": "x", "client_ip": "1.2.3.4"}, l)
	if rec.Canonical() != `{"client_ip":"1.2.3.4","user_agent":"x"}` || len(rec.Fields()) != 2 {
		t.Fatalf("record canonical %s", rec.Canonical())
	}
	d, err := Duration(time.Hour, l)
	if err != nil || d.Canonical() != "1h" {
		t.Fatal("duration")
	}
	if _, err := Duration(0, l); err == nil {
		t.Fatal("zero duration accepted")
	}
	if Bool(true, l).Canonical() != "true" || Int(5, l).Canonical() != "5" || Unit(l).Canonical() != "" {
		t.Fatal("scalar canonicals")
	}
	if !ip.Equal(ip.Joined(label.New(label.Runtime()))) || ip.Equal(acct) {
		t.Fatal("Equal")
	}
	j := ip.Joined(label.New(label.TaskParam("x")))
	if j.Label().Len() != 2 {
		t.Fatal("Joined must add sources")
	}
	if ip.WithID("v1").ID() != "v1" || !ip.Valid() || (Value{}).Valid() {
		t.Fatal("ids")
	}
}

func TestParseTypeAndFromJSON(t *testing.T) {
	for _, s := range []string{"ipv4", "list<ipv4>", "list<account_id>", "bool", "duration", "hostname", "text", "IOCList"} {
		ty, err := ParseType(s)
		if err != nil || ty.String() != s {
			t.Errorf("%q: %v %v", s, ty, err)
		}
	}
	for _, s := range []string{"", "list<list<ipv4>>", "list<ipv4", "ipv6", "unit", "lower", "Bad-Name"} {
		if _, err := ParseType(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	l := label.New(label.TaskParam("confirmed_ips"))
	v, err := FromJSON(json.RawMessage(`["203.0.113.7","198.51.100.23"]`), ListOf(Scalar(KindIPv4)), nil, l)
	if err != nil || v.Count() != 2 {
		t.Fatalf("list: %v", err)
	}
	if v.ToJSON() == nil || string(v.ToJSON()) != `["203.0.113.7","198.51.100.23"]` {
		t.Fatalf("ToJSON %s", v.ToJSON())
	}
	if _, err := FromJSON(json.RawMessage(`["203.0.113.007"]`), ListOf(Scalar(KindIPv4)), nil, l); !errors.Is(err, ErrType) {
		t.Fatal("leading zero accepted")
	}
	if b, err := FromJSON(json.RawMessage(`true`), Scalar(KindBool), nil, l); err != nil || b.Canonical() != "true" {
		t.Fatal("bool")
	}
	if _, err := FromJSON(json.RawMessage(`"true"`), Scalar(KindBool), nil, l); !errors.Is(err, ErrType) {
		t.Fatal("string as bool accepted")
	}
	if d, err := FromJSON(json.RawMessage(`"1h"`), Scalar(KindDuration), nil, l); err != nil || d.Canonical() != "1h" {
		t.Fatal("duration")
	}
	if _, err := FromJSON(json.RawMessage(`{}`), StructType("IOCList"), nil, l); !errors.Is(err, ErrType) {
		t.Fatal("struct from JSON accepted")
	}
	if i, err := FromJSON(json.RawMessage(`7`), Scalar(KindInt), nil, l); err != nil || i.Canonical() != "7" {
		t.Fatal("int")
	}
	if e, err := FromString("protected_accounts", Scalar(KindEnum), nil, l); err != nil || e.Canonical() != "protected_accounts" {
		t.Fatal("enum")
	}
	if _, err := FromString("", Scalar(KindEnum), nil, l); err == nil {
		t.Fatal("empty enum accepted")
	}
	if _, err := FromString("x", Scalar(KindBool), nil, l); err == nil {
		t.Fatal("bool from string accepted")
	}
}

func TestCodeOf(t *testing.T) {
	err := fmt.Errorf("verify: %w", fmt.Errorf("%w: detail", ErrBadSig))
	if CodeOf(err) != "ERR_BAD_SIG" || !errors.Is(err, ErrBadSig) || errors.Is(err, ErrSchema) {
		t.Fatal("code wrapping")
	}
	if CodeOf(errors.New("plain")) != "" || ErrType.Error() != "ERR_TYPE" {
		t.Fatal("CodeOf on plain error")
	}
}

func FuzzParseIPv4(f *testing.F) {
	for _, s := range []string{"203.0.113.7", "203.0.113.007", "::ffff:1.2.3.4", "1.2.3.4%x", "0.0.0.0", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseIPv4(s)
		if err != nil {
			return
		}
		if a.String() != s || !a.Is4() {
			t.Fatalf("accepted %q as %v", s, a)
		}
		v, err := IPv4(a, label.New(label.Runtime()))
		if err != nil || v.Canonical() != s {
			t.Fatalf("canonical %q", v.Canonical())
		}
	})
}

func FuzzParseAccountID(f *testing.F) {
	for _, s := range []string{"jdoe", "svc-backup", "Jdoe", "a", "1x", "x\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseAccountID(s)
		if err != nil {
			return
		}
		if got != s || len(s) < 2 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
			t.Fatalf("accepted %q", s)
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				t.Fatalf("accepted %q", s)
			}
		}
	})
}

func FuzzParseHostname(f *testing.F) {
	for _, s := range []string{"web-03", "WEB", "-a", "a-", "a.b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseHostname(s, nil)
		if err != nil {
			return
		}
		if got != s || strings.ToLower(s) != s || strings.ContainsAny(s, "._ ") {
			t.Fatalf("accepted %q", s)
		}
	})
}

func FuzzDecodeStrict(f *testing.F) {
	for _, s := range []string{`{"kid":"a"}`, `{"kid":"a","kid":"b"}`, `{"kid":"a","KID":"b"}`, `[1]`, `{"list":["x"],"in":{"a":"b"}}`, "{\"kid\":\"\xff\"}"} {
		f.Add([]byte(s))
	}
	type inner struct {
		A string `json:"a"`
	}
	type outer struct {
		KID  string   `json:"kid"`
		List []string `json:"list"`
		In   *inner   `json:"in"`
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var o outer
		if err := DecodeStrict(data, &o, Limits{}); err != nil {
			if !errors.Is(err, ErrSchema) && !errors.Is(err, ErrSize) {
				t.Fatalf("error without a code: %v", err)
			}
			return
		}
		// Anything accepted must have no duplicate keys under folding: a
		// lenient decode into a map counts keys at the top level.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("strict accepted what lenient rejects: %v", err)
		}
		seen := map[string]bool{}
		for k := range m {
			if seen[foldKey(k)] {
				t.Fatalf("accepted case-insensitive duplicate %q", k)
			}
			seen[foldKey(k)] = true
			if _, known := map[string]bool{"kid": true, "list": true, "in": true}[k]; !known {
				t.Fatalf("accepted unknown field %q", k)
			}
		}
	})
}
