package harness

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"citadel/internal/llm"
	"citadel/internal/plan"
)

// recordingPlanner wraps a planner and keeps every input and prompt it saw.
type recordingPlanner struct {
	inner   llm.Planner
	mu      *sync.Mutex
	inputs  *[]llm.PlannerInput
	prompts *[]string
}

func (r recordingPlanner) Plan(ctx context.Context, in llm.PlannerInput) (plan.Plan, llm.CallInfo, error) {
	p := llm.BuildPlannerPrompt(in)
	r.mu.Lock()
	*r.inputs = append(*r.inputs, in)
	*r.prompts = append(*r.prompts, p.System+"\n"+p.User)
	r.mu.Unlock()
	return r.inner.Plan(ctx, in)
}

var ipv4Pattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// The planner sees only trusted input: across every fixture and every
// Citadel configuration, no attacker-written text and no log- or
// processor-derived value (an address or account the analyst did not give)
// appears in any planner prompt.
func TestPlannerPromptsContainNoUntrustedValues(t *testing.T) {
	root := repoRoot(t)
	var fixtures []*Fixture
	for _, dir := range []string{"testdata/eval", "testdata/dev"} {
		fx, err := LoadFixtures(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, fx...)
	}
	fixtures = append(fixtures, M1Fixture())
	base := baseOptions(t, C2)
	checked := 0
	for _, fx := range fixtures {
		texts, err := fx.AttackerTexts(base.BaseInventory)
		if err != nil {
			t.Fatal(err)
		}
		spec, _ := fx.EnvSpec(base.BaseInventory)
		trustedParams, _ := fx.ParamsJSON()
		var trusted []string
		for _, v := range trustedParams {
			trusted = append(trusted, string(v))
		}
		trusted = append(trusted, fx.Task.Note)
		var untrusted []string
		for _, r := range spec.Access {
			untrusted = append(untrusted, r.ClientIP.String(), r.AttemptedUser, r.AuthPrincipal)
		}
		for _, s := range texts {
			untrusted = append(untrusted, s)
			untrusted = append(untrusted, ipv4Pattern.FindAllString(s, -1)...)
		}
		for _, cfg := range []string{C1Instr, C1Data, C2} {
			var mu sync.Mutex
			var inputs []llm.PlannerInput
			var prompts []string
			o := base
			o.Config = cfg
			o.Thresholds = DefaultThresholds()
			o.Models = func(agent, config string) llm.Set {
				s := Scripted(nil)(agent, config)
				s.Planner = recordingPlanner{inner: s.Planner, mu: &mu, inputs: &inputs, prompts: &prompts}
				return s
			}
			Run(context.Background(), fx, o)
			for _, p := range prompts {
				checked++
				for _, u := range untrusted {
					if len(u) < 4 || slices.ContainsFunc(trusted, func(t string) bool { return strings.Contains(t, u) }) {
						continue
					}
					if strings.Contains(p, u) {
						t.Errorf("%s/%s: untrusted value %q appears in a planner prompt", fx.ID, cfg, u)
					}
				}
			}
			for _, in := range inputs {
				// The prompt builder is a pure function of its input.
				if llm.BuildPlannerPrompt(in) != llm.BuildPlannerPrompt(in) {
					t.Fatal("prompt builder is not deterministic")
				}
			}
		}
	}
	if checked < 2*len(fixtures) {
		t.Fatalf("only %d prompts checked", checked)
	}
}

// PlannerInput has no field that can carry a data value or a list length:
// only names, types, trusted parameters, the note, and capabilities.
func TestPlannerInputHasNoValueFields(t *testing.T) {
	allowed := map[string]bool{"Agent": true, "Task": true, "TaskVersion": true, "Params": true, "Note": true,
		"Effective": true, "Handoffs": true, "Data": true, "Schemas": true, "HandoffData": true}
	rt := reflect.TypeOf(llm.PlannerInput{})
	for i := 0; i < rt.NumField(); i++ {
		if !allowed[rt.Field(i).Name] {
			t.Errorf("PlannerInput gained field %s: review it for untrusted values", rt.Field(i).Name)
		}
	}
	dt := reflect.TypeOf(llm.DataDecl{})
	if dt.NumField() != 2 || dt.Field(0).Name != "Name" || dt.Field(1).Name != "Type" {
		t.Error("DataDecl must hold only a name and a type")
	}
}

// One path to a tool: outside tests, only the interpreter's executor calls a
// tool's Apply, and only the harness's C0 driver calls the baseline path.
func TestOnePathToTool(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "runs" || d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			dir := filepath.ToSlash(filepath.Dir(rel))
			switch sel.Sel.Name {
			case "Apply":
				if dir != "internal/interp" && dir != "internal/tools" {
					t.Errorf("%s calls Apply: only the interpreter's executor may reach a tool", rel)
				}
			case "BaselineCall", "BaselineRead":
				if filepath.ToSlash(rel) != "internal/harness/baseline.go" {
					t.Errorf("%s calls %s: only the C0 driver may", rel, sel.Sel.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTuneOnDevelopmentFixtures(t *testing.T) {
	root := repoRoot(t)
	fx, err := LoadFixtures(filepath.Join(root, "testdata/dev"))
	if err != nil {
		t.Fatal(err)
	}
	o := baseOptions(t, C2)
	tf, err := Tune(context.Background(), fx, TuneOptions{Catalog: o.Catalog, BaseInventory: o.BaseInventory, Defaults: DefaultThresholds(), MaxK: 50, Rand: o.Rand})
	if err != nil {
		t.Fatal(err)
	}
	// The benign development user mistyped a password four times, so k must
	// exceed four; fabricated indicators are absent at any k.
	if tf.K != 5 || len(tf.Fixtures) != len(fx) || len(tf.Verified) == 0 || tf.Rule != TuningRule {
		t.Fatalf("tuned %+v", tf)
	}
	path := filepath.Join(t.TempDir(), "thresholds.yaml")
	if err := WriteThresholds(path, tf); err != nil {
		t.Fatal(err)
	}
	back, err := LoadThresholds(path)
	if err != nil || back.K != tf.K || back.Thresholds() != tf.Thresholds() {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	eval, _ := LoadFixtures(filepath.Join(root, "testdata/eval/benign"))
	if _, err := Tune(context.Background(), eval, TuneOptions{Catalog: o.Catalog, BaseInventory: o.BaseInventory, Defaults: DefaultThresholds()}); err == nil {
		t.Fatal("tune must refuse evaluation fixtures")
	}
}

func TestExecuteWritesRecordsAndTables(t *testing.T) {
	root := repoRoot(t)
	fx, err := LoadFixtures(filepath.Join(root, "testdata/eval"))
	if err != nil {
		t.Fatal(err)
	}
	var pick []*Fixture
	for _, f := range fx {
		if f.ID == "B1" || f.ID == "A-G3b-downstream" || f.ID == "B12" {
			pick = append(pick, f)
		}
	}
	dir := t.TempDir()
	o := baseOptions(t, C2)
	recs, err := Execute(context.Background(), Plan{Fixtures: pick, Configs: Configs(), Trials: 2, OutDir: dir, Parallel: 3,
		Meta:    Meta{Impl: llm.ImplScripted, Trials: 2, FixturesDir: "testdata/eval", Thresholds: DefaultThresholds()},
		Options: func(string, int) Options { return o }})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3*4*2 {
		t.Fatalf("%d records", len(recs))
	}
	for _, r := range recs {
		if r.Crash != "" {
			t.Errorf("%s/%s crashed: %s", r.Fixture, r.Config, r.Crash)
		}
	}
	tables, err := os.ReadFile(filepath.Join(dir, "tables.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| C0 |", "| C1-instr |", "| C1-data |", "| C2 |", "Wilson", "deterministic, scripted stand-ins"} {
		if !strings.Contains(string(tables), want) {
			t.Errorf("tables lack %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "C2", "B1", "trial-1", "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	again, err := GenerateTables(dir)
	if err != nil || again != string(tables) {
		t.Fatal("tables must regenerate identically from the recorded runs")
	}
}

func TestWilson(t *testing.T) {
	lo, hi := Wilson(0, 15)
	if lo != 0 || hi < 0.2 || hi > 0.21 {
		t.Fatalf("0/15: [%f, %f]", lo, hi)
	}
	lo, hi = Wilson(15, 15)
	if hi != 1 || lo < 0.79 || lo > 0.8 {
		t.Fatalf("15/15: [%f, %f]", lo, hi)
	}
	if lo, hi := Wilson(0, 0); lo != 0 || hi != 0 {
		t.Fatal("n = 0")
	}
	if rate(3, 10).String() != "3/10 = 30% [11, 60]" {
		t.Fatalf("rate string %q", rate(3, 10).String())
	}
}

func BenchmarkRunC2(b *testing.B) {
	o := baseOptions(b, C2)
	fx := scenario("bench")
	for b.Loop() {
		Run(context.Background(), fx, o)
	}
}
