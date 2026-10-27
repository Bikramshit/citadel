package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"citadel/internal/harness"
	"citadel/internal/llm"
	"citadel/internal/policy"
	"citadel/internal/value"
)

func cmdHarness(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("harness", flag.ContinueOnError)
	configs := fs.String("configs", "C0,C1-instr,C1-data,C2", "configurations to run")
	trials := fs.Int("trials", 5, "trials per fixture and configuration")
	fixtures := fs.String("fixtures", "testdata/eval", "fixture directory")
	impl := fs.String("impl", "model", "model implementation: model or scripted")
	evidence := fs.String("evidence", "on", "evidence rules: on, or legacy for the Experiment 3 ablation")
	only := fs.String("only", "", "comma-separated fixture IDs or prefixes to include (default all)")
	out := fs.String("out", "runs", "parent directory for the run directory")
	parallel := fs.Int("parallel", 4, "runs in parallel")
	thresholds := fs.String("thresholds", "configs/thresholds.yaml", "frozen thresholds")
	root := fs.String("root", ".", "repository root")
	regenerate := fs.String("regenerate", "", "regenerate tables.md from an existing run directory and exit")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *regenerate != "" {
		t, err := harness.GenerateTables(*regenerate)
		if err != nil {
			return err
		}
		path := filepath.Join(*regenerate, "tables.md")
		if err := os.WriteFile(path, []byte(t), 0o644); err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	}
	ev, err := evidenceMode(*evidence)
	if err != nil {
		return err
	}
	if ev == policy.EvidenceOff {
		return fmt.Errorf("%w: the harness runs with evidence on, or legacy for the ablation", value.ErrConfig)
	}
	cfgs := strings.Split(*configs, ",")
	for _, c := range cfgs {
		if c != harness.C0 && c != harness.C1Instr && c != harness.C1Data && c != harness.C2 {
			return fmt.Errorf("%w: configuration %q", value.ErrConfig, c)
		}
	}
	if *trials < 1 {
		return fmt.Errorf("%w: trials must be positive", value.ErrConfig)
	}
	rootAbs, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	fxDir, err := filepath.Abs(*fixtures)
	if err != nil {
		return err
	}
	meta := harness.Meta{Configs: cfgs, Trials: *trials, Evidence: *evidence, FixturesDir: *fixtures, Impl: *impl}
	meta.GitCommit, meta.GitDirty, err = harness.GitState(rootAbs)
	if err != nil {
		return err
	}
	thPath := filepath.Join(rootAbs, *thresholds)
	if filepath.IsAbs(*thresholds) {
		thPath = *thresholds
	}
	if strings.Contains(filepath.ToSlash(fxDir), "testdata/eval") {
		// Evaluation fixtures are scored only under committed thresholds.
		if meta.ThresholdsCommit, err = harness.ThresholdsCommit(rootAbs, thPath); err != nil {
			return err
		}
	}
	tf, err := harness.LoadThresholds(thPath)
	if err != nil {
		return err
	}
	meta.Thresholds = tf.Thresholds()
	cat, baseInv, err := loadCatalogAndInventory(filepath.Join(rootAbs, "configs/catalog.yaml"), filepath.Join(rootAbs, "configs/inventory.yaml"))
	if err != nil {
		return err
	}
	all, err := harness.LoadFixtures(fxDir)
	if err != nil {
		return err
	}
	var fxs []*harness.Fixture
	for _, f := range all {
		if f.Kind == harness.KindDev {
			return fmt.Errorf("%w: development fixture %s is for tuning only", value.ErrConfig, f.ID)
		}
		if *only == "" || matchesAny(f.ID, strings.Split(*only, ",")) {
			fxs = append(fxs, f)
			meta.Fixtures = append(meta.Fixtures, harness.FixtureDigest{ID: f.ID, SHA256: fileDigest(f.Path())})
		}
	}
	if len(fxs) == 0 {
		return fmt.Errorf("%w: no fixtures selected", value.ErrConfig)
	}
	var models harness.Models
	var baseline harness.BaselineModels
	switch *impl {
	case llm.ImplScripted:
		models, baseline = harness.Scripted(nil), harness.ScriptedBaseline()
		for _, r := range []string{"planner", "processor", "intake", "baseline"} {
			meta.Models = append(meta.Models, harness.ModelInfo{Role: r, Model: "scripted-" + r, Provider: "none (deterministic stand-in)"})
		}
	case llm.ImplModel:
		_, err := modelsFor(ModelConfig{Impl: llm.ImplModel}, harness.Responder, "C2")
		return err
	default:
		return fmt.Errorf("%w: impl %q", value.ErrConfig, *impl)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if *evidence != "on" {
		stamp += "-evidence-" + *evidence
	}
	if *impl == llm.ImplScripted {
		stamp += "-scripted"
	}
	dir := filepath.Join(rootAbs, *out, stamp)
	log.Info("harness starting", "dir", dir, "fixtures", len(fxs), "configs", cfgs, "trials", *trials, "impl", *impl)
	recs, err := harness.Execute(ctx, harness.Plan{Fixtures: fxs, Configs: cfgs, Trials: *trials, OutDir: dir, Meta: meta, Parallel: *parallel,
		Options: func(config string, trial int) harness.Options {
			return harness.Options{Catalog: cat, BaseInventory: baseInv, Thresholds: tf.Thresholds(), Evidence: ev,
				Models: models, Baseline: baseline, Rand: rand.Reader}
		},
		Progress: func(done, total int, rec *harness.RunRecord) {
			if rec.Crash != "" {
				log.Warn("run crashed", "fixture", rec.Fixture, "config", rec.Config, "trial", rec.Trial, "crash", value.Truncate(rec.Crash))
			}
			if done%50 == 0 || done == total {
				log.Info("progress", "done", done, "total", total)
			}
		}})
	if err != nil {
		return err
	}
	crashes, invalid := 0, 0
	for _, r := range recs {
		if r.Crash != "" {
			crashes++
		}
		if !r.Valid() {
			invalid++
		}
	}
	fmt.Printf("%d runs in %s (%d crashed, %d with invariant violations)\ntables: %s\n", len(recs), dir, crashes, invalid, filepath.Join(dir, "tables.md"))
	return nil
}

func matchesAny(id string, pats []string) bool {
	for _, p := range pats {
		if p != "" && (id == p || strings.HasPrefix(id, p)) {
			return true
		}
	}
	return false
}

func fileDigest(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	return digestHex(b)
}

func cmdTune(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	fixtures := fs.String("fixtures", "testdata/dev", "development fixture directory")
	out := fs.String("out", "configs/thresholds.yaml", "thresholds file to write")
	root := fs.String("root", ".", "repository root")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if strings.Contains(filepath.ToSlash(*fixtures), "testdata/eval") {
		return fmt.Errorf("%w: tune reads development fixtures only", value.ErrConfig)
	}
	cat, baseInv, err := loadCatalogAndInventory(filepath.Join(*root, "configs/catalog.yaml"), filepath.Join(*root, "configs/inventory.yaml"))
	if err != nil {
		return err
	}
	fxs, err := harness.LoadFixtures(*fixtures)
	if err != nil {
		return err
	}
	tf, err := harness.Tune(ctx, fxs, harness.TuneOptions{Catalog: cat, BaseInventory: baseInv, Defaults: harness.DefaultThresholds(),
		MaxK: 50, Rand: rand.Reader, Now: time.Now()})
	if err != nil {
		return err
	}
	if err := harness.WriteThresholds(*out, tf); err != nil {
		return err
	}
	log.Info("thresholds written", "path", *out, "k", tf.K, "verified", tf.Verified)
	fmt.Printf("k=%d min_flows=%d soft_untrusted_pc=%d iteration_budget=%d -> %s\nCommit this file before any evaluation run.\n",
		tf.K, tf.MinFlows, tf.SoftUntrustedPC, tf.IterationBudget, *out)
	return nil
}
