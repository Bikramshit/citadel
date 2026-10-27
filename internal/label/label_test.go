package label

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var sampleSources = []Source{
	TaskParam("hosts"), TaskParam("confirmed_ips"), UserNote(), PlannerLiteral("responder"),
	Runtime(), Tool("logs.read"), Tool("inventory.read"), QLLM("investigator"),
	Peer("investigator", "m3B9xQ2rT8vK1pZ7yW4nLg"), Claimed("tool:logs.read"),
}

func randomLabel(r *rand.Rand) Label {
	n := r.IntN(5)
	s := make([]Source, n)
	for i := range s {
		s[i] = sampleSources[r.IntN(len(sampleSources))]
	}
	if r.IntN(3) == 0 {
		return NewRestricted([]string{"analyst", "soc", "internal"}[:1+r.IntN(3)], s...)
	}
	return New(s...)
}

func sameLabel(a, b Label) bool {
	ra, sa := a.Restricted()
	rb, sb := b.Restricted()
	return slices.Equal(a.Sources(), b.Sources()) && ra == rb && slices.Equal(sa, sb)
}

func containsAll(out Label, ins ...Label) bool {
	have := out.Sources()
	for _, in := range ins {
		for _, s := range in.Sources() {
			if !slices.Contains(have, s) {
				return false
			}
		}
	}
	return true
}

// L1: Join is commutative, associative, and idempotent, and never loses a source.
func TestL1_JoinProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 5000; i++ {
		a, b, c := randomLabel(r), randomLabel(r), randomLabel(r)
		if !sameLabel(Join(a, b), Join(b, a)) {
			t.Fatalf("not commutative: %v %v", a, b)
		}
		if !sameLabel(Join(Join(a, b), c), Join(a, Join(b, c))) {
			t.Fatalf("not associative: %v %v %v", a, b, c)
		}
		if !sameLabel(Join(a, a), a) {
			t.Fatalf("not idempotent: %v", a)
		}
		if !containsAll(Join(a, b, c), a, b, c) {
			t.Fatalf("lost a source: %v %v %v", a, b, c)
		}
	}
}

func TestL1_JoinReadersIntersect(t *testing.T) {
	a := NewRestricted([]string{"analyst", "soc"}, Runtime())
	b := NewRestricted([]string{"soc", "internal"}, Runtime())
	j := Join(a, b, New(Runtime()))
	if !j.ReadableBy("soc") || j.ReadableBy("analyst") || j.ReadableBy("internal") {
		t.Fatalf("readers not intersected: %v", j)
	}
	if !New(Runtime()).ReadableBy("anyone") {
		t.Fatal("unrestricted label must be readable by everyone")
	}
}

func TestL1_SourcesSortedDeduplicated(t *testing.T) {
	l := New(QLLM("investigator"), TaskParam("hosts"), QLLM("investigator"), Runtime())
	got := l.Strings()
	want := []string{"task_param:hosts", "runtime", "qllm:investigator"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	srcs := l.Sources()
	srcs[0] = QLLM("x")
	if l.Sources()[0] == srcs[0] {
		t.Fatal("Sources must return a copy")
	}
}

func TestTrustedRequiresEverySourceTrusted(t *testing.T) {
	tt := DefaultTrust()
	cases := []struct {
		l    Label
		want bool
	}{
		{New(TaskParam("hosts")), true},
		{New(UserNote(), PlannerLiteral("r"), Runtime()), true},
		{New(Tool("inventory.read")), true},
		{New(Tool("logs.read")), false},
		{New(QLLM("investigator")), false},
		{New(Peer("investigator", "id")), false},
		{New(Claimed("tool:inventory.read")), false},
		{Join(New(TaskParam("ips")), New(Peer("investigator", "id"))), false},
		{New(), false},
		{Join(), false},
	}
	for i, c := range cases {
		if got := c.l.Trusted(tt); got != c.want {
			t.Errorf("case %d %v: Trusted=%v want %v", i, c.l, got, c.want)
		}
	}
	if !New(Tool("logs.read")).Trusted(TrustTable{TrustedTools: map[string]bool{"logs.read": true}}) {
		t.Fatal("trust table must decide tool trust")
	}
}

func TestSourceStrings(t *testing.T) {
	cases := map[Source]string{
		TaskParam("hosts"):        "task_param:hosts",
		UserNote():                "user_note",
		PlannerLiteral("r"):       "planner_literal:r",
		Runtime():                 "runtime",
		Tool("logs.read"):         "tool:logs.read",
		QLLM("investigator"):      "qllm:investigator",
		Peer("investigator", "x"): "peer:investigator/x",
		Claimed("tool:logs.read"): "claimed:tool:logs.read",
		{Kind: 99}:                "invalid",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("%#v: got %q want %q", s, got, want)
		}
	}
	if New(Runtime(), QLLM("a")).String() != "{runtime,qllm:a}" {
		t.Fatal("label String")
	}
	b, err := New(Runtime()).MarshalJSON()
	if err != nil || string(b) != `["runtime"]` {
		t.Fatalf("MarshalJSON: %s %v", b, err)
	}
	if !New(QLLM("a")).Has(SrcQLLM) || New(QLLM("a")).Has(SrcPeer) || New(QLLM("a")).Len() != 1 {
		t.Fatal("Has/Len")
	}
}

// labelProducers lists every exported function that returns a Label, with a
// property check: the result has every source of its inputs. TestL2 fails if
// a new exported function returning a Label is added without an entry here.
var labelProducers = map[string]func(r *rand.Rand) (out Label, ins []Label, extra []Source){
	"New": func(r *rand.Rand) (Label, []Label, []Source) {
		s := randomLabel(r).Sources()
		return New(s...), nil, s
	},
	"NewRestricted": func(r *rand.Rand) (Label, []Label, []Source) {
		s := randomLabel(r).Sources()
		return NewRestricted([]string{"soc"}, s...), nil, s
	},
	"Join": func(r *rand.Rand) (Label, []Label, []Source) {
		ins := []Label{randomLabel(r), randomLabel(r), randomLabel(r)}
		return Join(ins...), ins, nil
	},
}

// L2: reflection over the package's exported API. Label has no exported
// fields, no method returns a Label, and every exported function returning a
// Label keeps all its inputs' sources.
func TestL2_NoExportedFunctionRemovesSources(t *testing.T) {
	lt := reflect.TypeOf(Label{})
	for i := 0; i < lt.NumField(); i++ {
		if lt.Field(i).IsExported() {
			t.Fatalf("Label field %s is exported", lt.Field(i).Name)
		}
	}
	for _, typ := range []reflect.Type{lt, reflect.PointerTo(lt)} {
		for i := 0; i < typ.NumMethod(); i++ {
			m := typ.Method(i)
			for o := 0; o < m.Type.NumOut(); o++ {
				if m.Type.Out(o) == lt {
					t.Fatalf("method %s returns a Label", m.Name)
				}
			}
		}
	}
	// Package-level functions are not reachable by reflection, so read the
	// package source and list every exported function whose results include
	// a Label.
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || !fd.Name.IsExported() || fd.Type.Results == nil {
				continue
			}
			for _, res := range fd.Type.Results.List {
				if id, ok := res.Type.(*ast.Ident); ok && id.Name == "Label" {
					name := fd.Name.Name
					if fd.Recv != nil {
						t.Fatalf("method %s returns a Label", name)
					}
					found = append(found, name)
				}
			}
		}
	}
	slices.Sort(found)
	var want []string
	for k := range labelProducers {
		want = append(want, k)
	}
	slices.Sort(want)
	if !slices.Equal(found, want) {
		t.Fatalf("exported Label-returning functions %v; property-checked set %v", found, want)
	}
	r := rand.New(rand.NewPCG(3, 4))
	for name, gen := range labelProducers {
		for i := 0; i < 2000; i++ {
			out, ins, extra := gen(r)
			if !containsAll(out, ins...) || !containsAll(out, New(extra...)) {
				t.Fatalf("%s lost a source", name)
			}
		}
	}
}

func FuzzJoinNeverLosesSources(f *testing.F) {
	f.Add([]byte{0, 1, 2}, []byte{3, 4}, "soc")
	f.Add([]byte{}, []byte{7, 7, 7}, "")
	f.Fuzz(func(t *testing.T, a, b []byte, reader string) {
		mk := func(bs []byte) Label {
			s := make([]Source, 0, len(bs))
			for _, x := range bs {
				s = append(s, sampleSources[int(x)%len(sampleSources)])
			}
			if len(bs)%2 == 1 {
				return NewRestricted([]string{reader}, s...)
			}
			return New(s...)
		}
		la, lb := mk(a), mk(b)
		j := Join(la, lb)
		if !containsAll(j, la, lb) {
			t.Fatalf("Join lost a source: %v %v -> %v", la, lb, j)
		}
		if la.HasUntrusted(DefaultTrust()) && j.Trusted(DefaultTrust()) {
			t.Fatal("Join upgraded trust")
		}
		if j.ReadableBy(reader) && !(la.ReadableBy(reader) && lb.ReadableBy(reader)) {
			t.Fatal("Join widened readers")
		}
	})
}
