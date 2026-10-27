package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"citadel/internal/value"
)

// ModelInfo records one configured model role.
type ModelInfo struct {
	Role     string `json:"role"`
	Model    string `json:"model"`
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Settings string `json:"settings"`
}

// Meta is a run directory's metadata.
type Meta struct {
	Started          time.Time       `json:"started"`
	Finished         time.Time       `json:"finished"`
	GitCommit        string          `json:"git_commit"`
	GitDirty         bool            `json:"git_dirty"`
	ThresholdsCommit string          `json:"thresholds_commit"`
	Thresholds       Thresholds      `json:"thresholds"`
	Impl             string          `json:"impl"` // scripted | model
	Models           []ModelInfo     `json:"models"`
	PromptHashes     []string        `json:"prompt_hashes"`
	Configs          []string        `json:"configs"`
	Evidence         string          `json:"evidence"`
	Trials           int             `json:"trials"`
	FixturesDir      string          `json:"fixtures_dir"`
	Fixtures         []FixtureDigest `json:"fixtures"`
	GoVersion        string          `json:"go_version"`
	Runs             int             `json:"runs"`
	Crashes          int             `json:"crashes"`
	Invalid          int             `json:"invalid"`
	Usage            map[string]any  `json:"usage,omitempty"`
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// GitState returns the HEAD commit and whether the work tree is dirty.
func GitState(repo string) (string, bool, error) {
	head, err := git(repo, "rev-parse", "HEAD")
	if err != nil {
		return "", false, fmt.Errorf("%w: git rev-parse: %v", value.ErrConfig, err)
	}
	status, err := git(repo, "status", "--porcelain")
	if err != nil {
		return "", false, fmt.Errorf("%w: git status: %v", value.ErrConfig, err)
	}
	return head, status != "", nil
}

// ThresholdsCommit returns the commit that last changed the thresholds file,
// and refuses when the file is untracked or has uncommitted changes:
// evaluation fixtures are scored only under committed thresholds.
func ThresholdsCommit(repo, path string) (string, error) {
	rel, err := filepath.Rel(repo, path)
	if err != nil {
		return "", fmt.Errorf("%w: %v", value.ErrConfig, err)
	}
	if _, err := git(repo, "ls-files", "--error-unmatch", rel); err != nil {
		return "", fmt.Errorf("%w: %s is not committed; run citadel tune and commit it before scoring evaluation fixtures", value.ErrConfig, rel)
	}
	if out, err := git(repo, "status", "--porcelain", "--", rel); err != nil || out != "" {
		return "", fmt.Errorf("%w: %s has uncommitted changes", value.ErrConfig, rel)
	}
	c, err := git(repo, "log", "-1", "--format=%H", "--", rel)
	if err != nil || c == "" {
		return "", fmt.Errorf("%w: no commit for %s", value.ErrConfig, rel)
	}
	return c, nil
}

// Plan is one batch of runs.
type Plan struct {
	Fixtures []*Fixture
	Configs  []string
	Trials   int
	Options  func(config string, trial int) Options
	OutDir   string
	Meta     Meta
	Parallel int
	Progress func(done, total int, rec *RunRecord)
}

// Execute runs every fixture under every configuration for every trial,
// writes each run's event log and record, and then the metadata and tables.
// No run is dropped: crashes and invariant violations are recorded and
// counted as failed.
func Execute(ctx context.Context, p Plan) ([]*RunRecord, error) {
	if err := os.MkdirAll(p.OutDir, 0o750); err != nil {
		return nil, fmt.Errorf("runs: %w", err)
	}
	type job struct {
		fx     *Fixture
		config string
		trial  int
	}
	var jobs []job
	for _, cfg := range p.Configs {
		for _, fx := range p.Fixtures {
			for t := 1; t <= p.Trials; t++ {
				jobs = append(jobs, job{fx, cfg, t})
			}
		}
	}
	p.Meta.Started = time.Now().UTC()
	recs := make([]*RunRecord, len(jobs))
	par := max(1, p.Parallel)
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, j job) {
			defer wg.Done()
			defer func() { <-sem }()
			dir := filepath.Join(p.OutDir, j.config, j.fx.ID, fmt.Sprintf("trial-%d", j.trial))
			o := p.Options(j.config, j.trial)
			o.Config, o.Trial = j.config, j.trial
			o.EventsPath = filepath.Join(dir, "events.jsonl")
			rec := Run(ctx, j.fx, o)
			if err := writeJSON(filepath.Join(dir, "record.json"), rec); err != nil && rec.Crash == "" {
				rec.Crash = err.Error()
			}
			recs[i] = rec
			mu.Lock()
			done++
			if p.Progress != nil {
				p.Progress(done, len(jobs), rec)
			}
			mu.Unlock()
		}(i, j)
	}
	wg.Wait()
	p.Meta.Finished = time.Now().UTC()
	p.Meta.Runs = len(recs)
	p.Meta.GoVersion = runtime.Version()
	hashes := map[string]bool{}
	for _, r := range recs {
		if r.Crash != "" {
			p.Meta.Crashes++
		}
		if !r.Valid() {
			p.Meta.Invalid++
		}
		if r.Investigator != nil && r.Investigator.Planner.PromptHash != "" {
			hashes[r.Investigator.Planner.PromptHash] = true
		}
		if r.Responder != nil && r.Responder.Planner.PromptHash != "" {
			hashes[r.Responder.Planner.PromptHash] = true
		}
	}
	for h := range hashes {
		p.Meta.PromptHashes = append(p.Meta.PromptHashes, h)
	}
	slices.Sort(p.Meta.PromptHashes)
	if err := writeRecords(filepath.Join(p.OutDir, "records.jsonl"), recs); err != nil {
		return recs, err
	}
	if err := writeJSON(filepath.Join(p.OutDir, "meta.json"), p.Meta); err != nil {
		return recs, err
	}
	tables, err := GenerateTables(p.OutDir)
	if err != nil {
		return recs, err
	}
	return recs, os.WriteFile(filepath.Join(p.OutDir, "tables.md"), []byte(tables), 0o644)
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func writeRecords(path string, recs []*RunRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			f.Close()
			return err
		}
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadRecords reads a run directory's records.jsonl.
func ReadRecords(dir string) ([]*RunRecord, error) {
	f, err := os.Open(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("runs: %w", err)
	}
	defer f.Close()
	var out []*RunRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		var r RunRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("runs: %s: %w", dir, err)
		}
		out = append(out, &r)
	}
	return out, sc.Err()
}

// ReadMeta reads a run directory's meta.json.
func ReadMeta(dir string) (Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return Meta{}, fmt.Errorf("runs: %w", err)
	}
	var m Meta
	return m, json.Unmarshal(b, &m)
}

// GenerateTables builds every table from a run directory's records and
// metadata. Records of different implementations, or of different evidence
// modes, are never mixed in one table.
func GenerateTables(dir string) (string, error) {
	recs, err := ReadRecords(dir)
	if err != nil {
		return "", err
	}
	meta, err := ReadMeta(dir)
	if err != nil {
		return "", err
	}
	groups := map[string][]*RunRecord{}
	for _, r := range recs {
		impl := r.Impl
		if impl == "" {
			impl = "unknown"
		}
		groups[impl] = append(groups[impl], r)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Results generated from %s\n\nGenerated by `citadel harness` from the run records in this directory; nothing here is typed by hand.\n\n", filepath.Base(dir))
	var models []string
	for _, m := range meta.Models {
		models = append(models, fmt.Sprintf("%s=%s", m.Role, m.Model))
	}
	provider := ""
	if len(meta.Models) > 0 {
		provider = meta.Models[0].Provider
	}
	for _, impl := range sortedKeys(groups) {
		title := "Experiment 2: handoff comparison"
		desc := "Model runs: how often attacks and tasks succeed with these models on these dates."
		if impl != "model" {
			title += " (deterministic, scripted stand-ins)"
			desc = "Deterministic results with scripted worst-case stand-ins, not model measurements. They show what the runtime enforces under chosen adversarial inputs and are reported separately from model runs."
		}
		if meta.Evidence != "" && meta.Evidence != "on" {
			title += ", evidence rules: " + meta.Evidence
		}
		h := TableHeader{Title: title, Impl: impl, Models: models, Provider: provider,
			Settings: settings(meta), Dates: meta.Started.Format("2006-01-02") + " to " + meta.Finished.Format("2006-01-02"),
			Thresholds: meta.ThresholdsCommit, GitCommit: meta.GitCommit, Fixtures: meta.FixturesDir, Trials: meta.Trials, Description: desc}
		b.WriteString(MarkdownTable(h, Summarize(groups[impl])))
		fmt.Fprintf(&b, "Runs: %d. Crashed: %d. Runs with invariant violations: %d.\n\n", meta.Runs, meta.Crashes, meta.Invalid)
		b.WriteString(LatencyTable(groups[impl]))
	}
	return b.String(), nil
}

func settings(m Meta) string {
	var parts []string
	for _, x := range m.Models {
		if x.Settings != "" {
			parts = append(parts, x.Role+": "+x.Settings)
		}
	}
	parts = append(parts, fmt.Sprintf("k=%d, min_flows=%d, soft_untrusted_pc=%d, iteration_budget=%d",
		m.Thresholds.K, m.Thresholds.MinFlows, m.Thresholds.SoftUntrustedPC, m.Thresholds.IterationBudget))
	return strings.Join(parts, "; ")
}

// LatencyTable reports p50 and p95 end to end and split into planner,
// processor, and the Go runtime and handoff (the remainder), per
// configuration.
func LatencyTable(recs []*RunRecord) string {
	byCfg := map[string][]*RunRecord{}
	for _, r := range recs {
		byCfg[r.Config] = append(byCfg[r.Config], r)
	}
	var b strings.Builder
	b.WriteString("| Config | n | End to end p50 / p95 (ms) | Planner p50 (ms) | Processor p50 (ms) | Runtime and handoff p50 (ms) |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, cfg := range append(Configs(), sortedKeys(byCfg)...) {
		rs, ok := byCfg[cfg]
		if !ok {
			continue
		}
		delete(byCfg, cfg)
		var e2e, pl, pr, rt []float64
		for _, r := range rs {
			e2e = append(e2e, r.Metrics.LatencyMs)
			pl = append(pl, r.Metrics.PlannerMs)
			pr = append(pr, r.Metrics.ProcessorMs)
			rt = append(rt, max(0, r.Metrics.LatencyMs-r.Metrics.PlannerMs-r.Metrics.ProcessorMs))
		}
		for _, s := range [][]float64{e2e, pl, pr, rt} {
			slices.Sort(s)
		}
		fmt.Fprintf(&b, "| %s | %d | %.2f / %.2f | %.2f | %.2f | %.2f |\n", cfg, len(rs), percentile(e2e, .5), percentile(e2e, .95), percentile(pl, .5), percentile(pr, .5), percentile(rt, .5))
	}
	return b.String() + "\n"
}
