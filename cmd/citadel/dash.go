package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"citadel/internal/events"
	"citadel/internal/harness"
	"citadel/internal/interp"
	"citadel/internal/policy"
	"citadel/internal/value"
	"citadel/web"
)

// runSummary is one recorded run as the dashboard lists it.
type runSummary struct {
	ID            string           `json:"id"`
	Fixture       string           `json:"fixture"`
	Kind          string           `json:"kind"`
	Goal          string           `json:"goal"`
	Style         string           `json:"style"`
	Config        string           `json:"config"`
	Evidence      string           `json:"evidence"`
	Trial         int              `json:"trial"`
	Impl          string           `json:"impl"`
	AttackSuccess bool             `json:"attack_success"`
	Unauthorized  int              `json:"unauthorized"`
	Completed     bool             `json:"completed"`
	Escalations   int              `json:"escalations"`
	Uncertain     int              `json:"uncertain"`
	Failed        bool             `json:"failed"`
	Valid         bool             `json:"valid"`
	LatencyMs     float64          `json:"latency_ms"`
	Diff          []harness.Change `json:"diff"`
}

type runDir struct {
	Dir      string        `json:"dir"`
	Meta     harness.Meta  `json:"meta"`
	TablesMD string        `json:"tables_md"`
	Summary  []implSummary `json:"summary"` // computed by harness.Summarize, one block per implementation
	Runs     []runSummary  `json:"runs"`
}

// implSummary is one implementation's per-configuration results.
type implSummary struct {
	Impl string        `json:"impl"`
	Rows []harness.Row `json:"rows"`
}

type dash struct {
	root     *os.Root
	runsDir  string
	repo     string
	log      *slog.Logger
	hub      *events.Hub
	token    string
	approver *interp.ChannelApprover
	opts     harness.Options
	fixtures map[string]*harness.Fixture

	mu        sync.Mutex
	principal string
}

func cmdDash(ctx context.Context, log *slog.Logger, args []string) error {
	fset := flag.NewFlagSet("dash", flag.ContinueOnError)
	runs := fset.String("runs", "runs", "directory of recorded runs")
	listen := fset.String("listen", "127.0.0.1:8080", "listen address (127.0.0.1 only)")
	repo := fset.String("root", ".", "repository root")
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if err := os.MkdirAll(*runs, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(*runs)
	if err != nil {
		return err
	}
	defer root.Close()
	var tok [32]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return err
	}
	d := &dash{root: root, runsDir: *runs, repo: *repo, log: log, hub: events.NewHub(), token: hex.EncodeToString(tok[:]), fixtures: map[string]*harness.Fixture{}}
	d.approver = interp.NewChannelApprover(value.SystemClock{}, 10*time.Minute, nil)
	cat, baseInv, err := loadCatalogAndInventory(filepath.Join(*repo, "configs/catalog.yaml"), filepath.Join(*repo, "configs/inventory.yaml"))
	if err != nil {
		return err
	}
	th := harness.DefaultThresholds()
	if f, err := harness.LoadThresholds(filepath.Join(*repo, "configs/thresholds.yaml")); err == nil {
		th = f.Thresholds()
	}
	d.opts = harness.Options{Catalog: cat, BaseInventory: baseInv, Thresholds: th, Evidence: policy.EvidenceOn,
		Models: harness.Scripted(nil), Baseline: harness.ScriptedBaseline(), Rand: rand.Reader}
	d.fixtures["M1"] = harness.M1Fixture()
	if fxs, err := harness.LoadFixtures(filepath.Join(*repo, "testdata/eval")); err == nil {
		for _, f := range fxs {
			d.fixtures[f.ID] = f
		}
	}
	ln, err := listenLoopback(*listen)
	if err != nil {
		return err
	}
	return serve(ctx, log, ln, d.routes(), 30*time.Second) // SSE extends its own write deadline per message
}

func (d *dash) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(web.Files, ".")
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		b, err := fs.ReadFile(static, "index.html")
		if err != nil {
			http.Error(w, "dashboard missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		http.FileServerFS(static).ServeHTTP(w, r)
	})))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /api/runs", d.listRuns)
	mux.HandleFunc("GET /api/runs/{id...}", d.replay)
	mux.HandleFunc("GET /runs/{id...}", d.replay)
	mux.HandleFunc("GET /api/fixtures", d.listFixtures)
	mux.HandleFunc("GET /api/m1", d.m1)
	mux.HandleFunc("GET /api/approvals", d.approvals)
	mux.HandleFunc("GET /events", d.events)
	mux.HandleFunc("POST /run", d.startRun)
	mux.HandleFunc("POST /approve", d.approve)
	return mux
}

func secureHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (d *dash) readFile(rel string, limit int64) ([]byte, error) {
	f, err := d.root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// runDirs finds every directory under the runs root, up to three levels
// deep, that holds a harness run (meta.json), sorted newest first.
func (d *dash) runDirs() []string {
	var dirs []string
	fs.WalkDir(d.root.FS(), ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		depth := strings.Count(p, "/")
		if e.IsDir() && p != "." && depth > 2 {
			return fs.SkipDir
		}
		if !e.IsDir() && e.Name() == "meta.json" {
			dirs = append(dirs, path.Dir(p))
		}
		return nil
	})
	slices.SortFunc(dirs, func(a, b string) int { return strings.Compare(path.Base(b), path.Base(a)) })
	return dirs
}

func (d *dash) listRuns(w http.ResponseWriter, r *http.Request) {
	dirs := []runDir{}
	for _, dir := range d.runDirs() {
		mb, err := d.readFile(path.Join(dir, "meta.json"), 1<<20)
		if err != nil {
			continue
		}
		rd := runDir{Dir: dir}
		if json.Unmarshal(mb, &rd.Meta) != nil {
			continue
		}
		if tb, err := d.readFile(path.Join(dir, "tables.md"), 4<<20); err == nil {
			rd.TablesMD = string(tb)
		}
		recs, err := harness.ReadRecords(filepath.Join(d.runsDir, filepath.FromSlash(dir)))
		if err != nil {
			continue
		}
		byImpl := map[string][]*harness.RunRecord{}
		for _, rec := range recs {
			m := rec.Metrics
			byImpl[rec.Impl] = append(byImpl[rec.Impl], rec)
			rd.Runs = append(rd.Runs, runSummary{ID: fmt.Sprintf("%s/%s/%s/trial-%d", dir, rec.Config, rec.Fixture, rec.Trial),
				Fixture: rec.Fixture, Kind: rec.Kind, Goal: rec.Goal, Style: rec.Style, Config: rec.Config, Evidence: rec.Evidence,
				Trial: rec.Trial, Impl: rec.Impl, AttackSuccess: m.AttackSuccess, Unauthorized: m.Unauthorized, Completed: m.Completed,
				Escalations: m.Escalations, Uncertain: m.Uncertain, Failed: m.Failed, Valid: rec.Valid(), LatencyMs: m.LatencyMs, Diff: rec.Diff})
		}
		impls := make([]string, 0, len(byImpl))
		for impl := range byImpl {
			impls = append(impls, impl)
		}
		slices.Sort(impls)
		for _, impl := range impls {
			rd.Summary = append(rd.Summary, implSummary{Impl: impl, Rows: harness.Summarize(byImpl[impl])})
		}
		dirs = append(dirs, rd)
	}
	writeJSON(w, http.StatusOK, map[string]any{"dirs": dirs})
}

// m1 serves the committed milestone M1 checks, if present.
func (d *dash) m1(w http.ResponseWriter, r *http.Request) {
	b, err := d.readFile(path.Join("m1", "checks.json"), 1<<20)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no M1 trace under the runs directory"})
		return
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": v, "trace": "m1/trace.jsonl"})
}

// replay returns a recorded run's event log. The ID is a path inside the
// runs directory, opened through os.Root so it cannot escape it.
func (d *dash) replay(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id") // already unescaped by the router
	if id == "" || strings.Contains(id, "..") || strings.HasPrefix(id, "/") {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%w: run id", value.ErrSchema))
		return
	}
	rel := path.Join(id, "events.jsonl")
	if path.Base(id) == "trace.jsonl" || strings.HasSuffix(id, ".jsonl") {
		rel = id
	}
	if _, err := d.root.Stat(rel); err != nil {
		if _, err2 := d.root.Stat(path.Join(id, "trace.jsonl")); err2 == nil {
			rel = path.Join(id, "trace.jsonl")
		} else {
			writeError(w, http.StatusNotFound, fmt.Errorf("no recorded run %q", value.Truncate(id)))
			return
		}
	}
	evs, err := events.ReadFile(filepath.Join(d.runsDir, filepath.FromSlash(rel)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if evs == nil {
		evs = []events.Event{}
	}
	writeJSON(w, http.StatusOK, evs)
}

func (d *dash) listFixtures(w http.ResponseWriter, r *http.Request) {
	type fixture struct {
		ID          string           `json:"id"`
		Kind        string           `json:"kind"`
		Goal        string           `json:"goal"`
		Style       string           `json:"style"`
		Description string           `json:"description"`
		GoalAnyOf   []harness.Change `json:"goal_any_of"`  // the attack succeeds if any of these changes happens
		GoalNoneOf  []harness.Change `json:"goal_none_of"` // the attack succeeds if none of these happens (G4)
		Required    []harness.Change `json:"required"`     // changes the task needs
	}
	ids := make([]string, 0, len(d.fixtures))
	for id := range d.fixtures {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := []fixture{}
	for _, id := range ids {
		f := d.fixtures[id]
		out = append(out, fixture{ID: f.ID, Kind: f.Kind, Goal: f.Goal, Style: f.Style, Description: f.Description,
			GoalAnyOf: f.Predicate.AnyOf, GoalNoneOf: f.Predicate.NoneOf, Required: f.GroundTruth.Required})
	}
	writeJSON(w, http.StatusOK, map[string]any{"fixtures": out})
}

func (d *dash) approvals(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	principal := d.principal
	d.mu.Unlock()
	pending := d.approver.List()
	if pending == nil {
		pending = []interp.ApprovalRequest{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"principal": principal, "token": d.token, "pending": pending})
}

func (d *dash) events(w http.ResponseWriter, r *http.Request) {
	ch, cancel := d.hub.Subscribe()
	defer cancel()
	out := make(chan any)
	go func() {
		defer close(out)
		for e := range ch {
			select {
			case out <- e:
			case <-r.Context().Done():
				return
			}
		}
	}()
	sse(w, r, out)
}

func (d *dash) checkToken(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Citadel-Token")), []byte(d.token)) == 1
}

// startRun runs a fixture live with the scripted stand-ins, streaming its
// events. Escalations wait for the principal's answer on the approval card.
func (d *dash) startRun(w http.ResponseWriter, r *http.Request) {
	if !d.checkToken(r) {
		writeError(w, http.StatusForbidden, fmt.Errorf("%w: missing or wrong token", value.ErrNotPrincipal))
		return
	}
	var req struct {
		Fixture string `json:"fixture"`
		Config  string `json:"config"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	fx, ok := d.fixtures[req.Fixture]
	if !ok || !slices.Contains(harness.Configs(), req.Config) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%w: unknown fixture or configuration", value.ErrConfig))
		return
	}
	stamp := time.Now().UTC().Format("20060102T150405.000Z")
	live := path.Join("live", stamp+"-"+req.Config+"-"+fx.ID)
	o := d.opts
	o.Config, o.Trial, o.Hub = req.Config, 1, d.hub
	o.EventsPath = filepath.Join(d.runsDir, filepath.FromSlash(live), "events.jsonl")
	o.Approver = d.approver
	if fx.ID == "M1" {
		o.Evidence = policy.EvidenceOff
	}
	d.mu.Lock()
	d.principal = fx.Task.Principal
	d.mu.Unlock()
	go func() {
		rec := harness.Run(context.Background(), fx, o)
		d.log.Info("live run finished", "fixture", fx.ID, "config", req.Config, "run", rec.RunID, "valid", rec.Valid(), "crash", value.Truncate(rec.Crash))
	}()
	writeJSON(w, http.StatusOK, map[string]string{"run_id": live})
}

func (d *dash) approve(w http.ResponseWriter, r *http.Request) {
	if !d.checkToken(r) {
		writeError(w, http.StatusForbidden, fmt.Errorf("%w: missing or wrong token", value.ErrNotPrincipal))
		return
	}
	var req struct {
		Key      string `json:"key"`
		Approver string `json:"approver"`
		Yes      bool   `json:"yes"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var k policy.ApprovalKey
	b, err := hex.DecodeString(req.Key)
	if err != nil || len(b) != len(k) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%w: key", value.ErrSchema))
		return
	}
	copy(k[:], b)
	if err := d.approver.Answer(k, req.Approver, req.Yes); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
