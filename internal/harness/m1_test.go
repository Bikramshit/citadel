package harness

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"citadel/internal/catalog"
	"citadel/internal/policy"
)

func repoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func baseOptions(t testing.TB, config string) Options {
	t.Helper()
	root := repoRoot(t)
	cat, err := catalog.Load(filepath.Join(root, "configs/catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := LoadBaseInventory(filepath.Join(root, "configs/inventory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Config: config, Catalog: cat, BaseInventory: inv, Thresholds: DefaultThresholds(), Evidence: policy.EvidenceOn,
		Models: Scripted(nil), Baseline: ScriptedBaseline(), Rand: rand.Reader}
}

// TestM1 is the first end-to-end milestone, with scripted models only: the
// injected targets are denied with their rules, the analyst-confirmed
// address is blocked, the handoff is verified and accepted once, and the
// JSONL trace holds every step.
func TestM1(t *testing.T) {
	o := baseOptions(t, C2)
	o.Evidence = policy.EvidenceOff // evidence rules arrive after M1 (docs/QUESTIONS.md, Q7)
	o.EventsPath = filepath.Join(t.TempDir(), "m1.jsonl")
	rec := Run(context.Background(), M1Fixture(), o)
	if rec.Crash != "" {
		t.Fatalf("crash: %s", rec.Crash)
	}
	for _, c := range CheckM1(rec) {
		if !c.OK {
			t.Errorf("M1 element %d (%s): %s", c.Element, c.Name, c.Detail)
		}
	}
	for _, v := range rec.Violations {
		t.Errorf("%s", v)
	}
	if fi, err := os.Stat(o.EventsPath); err != nil || fi.Size() == 0 {
		t.Fatalf("trace not written: %v", err)
	}
}
