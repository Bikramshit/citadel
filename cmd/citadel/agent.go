package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"citadel/internal/events"
	"citadel/internal/handoff"
	"citadel/internal/harness"
	"citadel/internal/interp"
	"citadel/internal/label"
	"citadel/internal/orchestrator"
	"citadel/internal/policy"
	"citadel/internal/signed"
	"citadel/internal/tools"
	"citadel/internal/value"
)

// agentProcess is one running agent and what its HTTP API exposes.
type agentProcess struct {
	agent    *interp.Agent
	env      *tools.Env
	before   tools.State
	approver *interp.ChannelApprover
	hub      *events.Hub
	writer   *events.Writer
	log      *events.Log
	clock    value.Clock
}

func buildAgent(cfg AgentFileConfig, base string, log *slog.Logger) (*agentProcess, error) {
	if cfg.Role != harness.Investigator && cfg.Role != harness.Responder {
		return nil, fmt.Errorf("%w: role %q", value.ErrConfig, cfg.Role)
	}
	ev, err := evidenceMode(cfg.Evidence)
	if err != nil {
		return nil, err
	}
	mode, err := handoffMode(cfg.HandoffMode)
	if err != nil {
		return nil, err
	}
	th, err := thresholdsFor(resolve(base, cfg.Thresholds), ev)
	if err != nil {
		return nil, err
	}
	cat, baseInv, err := loadCatalogAndInventory(resolve(base, cfg.Catalog), resolve(base, cfg.Inventory))
	if err != nil {
		return nil, err
	}
	fx, err := fixtureFor(resolve(base, cfg.Fixture))
	if err != nil {
		return nil, err
	}
	clock, err := clockFor(cfg.Clock, fx)
	if err != nil {
		return nil, err
	}
	spec, err := fx.EnvSpec(baseInv)
	if err != nil {
		return nil, err
	}
	env, err := tools.NewEnv(spec, clock)
	if err != nil {
		return nil, err
	}
	reg, err := signed.LoadRegistry(resolve(base, cfg.Registry))
	if err != nil {
		return nil, err
	}
	signer, err := signed.LoadSigner(resolve(base, cfg.Key))
	if err != nil {
		return nil, err
	}
	if signer.Agent() != cfg.Role {
		return nil, fmt.Errorf("%w: key belongs to %s, not %s", value.ErrConfig, signer.Agent(), cfg.Role)
	}
	models, err := modelsFor(cfg.Models, cfg.Role, mode)
	if err != nil {
		return nil, err
	}
	engine, err := policy.NewEngine(policy.Config{PolicyVersions: []string{cfg.PolicyVersion}, Mode: ev,
		Thresholds: thresholdsEvidence(th), LoginPath: "/login"})
	if err != nil {
		return nil, err
	}
	if cfg.Events == "" {
		return nil, fmt.Errorf("%w: events path is required", value.ErrConfig)
	}
	writer, err := events.NewWriter(resolve(base, cfg.Events))
	if err != nil {
		return nil, err
	}
	hub := events.NewHub()
	elog := events.NewLog(clock, writer, hub)
	wait := 2 * time.Minute
	if cfg.ApprovalWait != "" {
		if wait, err = time.ParseDuration(cfg.ApprovalWait); err != nil || wait <= 0 {
			return nil, fmt.Errorf("%w: approval_wait %q", value.ErrConfig, cfg.ApprovalWait)
		}
	}
	approver := interp.NewChannelApprover(clock, wait, nil)
	transport := &handoff.HTTPTransport{Client: &http.Client{Timeout: 15 * time.Second}, Peers: cfg.Peers}
	a, err := interp.NewAgent(interp.AgentConfig{Name: cfg.Role, ConfigName: mode, HandoffMode: mode, Static: harness.StaticCaps(cfg.Role),
		Catalog: cat, Registry: reg, PolicyVersions: []string{cfg.PolicyVersion}, Engine: engine, Env: env, Models: models,
		Approver: approver, Signer: signer, Transport: transport, Events: elog, Clock: clock, Rand: rand.Reader,
		StartedAt: clock.Now(), IterationBudget: th.IterationBudget, ToolTimeout: 10 * time.Second,
		HandoffLifetime: 2 * time.Minute, Trust: label.DefaultTrust()})
	if err != nil {
		return nil, err
	}
	log.Info("agent ready", "role", cfg.Role, "mode", mode, "evidence", cfg.Evidence, "models", models.Impl, "fixture", fx.ID)
	return &agentProcess{agent: a, env: env, before: env.Snapshot(), approver: approver, hub: hub, writer: writer, log: elog, clock: clock}, nil
}

// envReport is the mock environment's observable state after runs.
type envReport struct {
	Diff     []tools.Change      `json:"diff"`
	ApplyLog []tools.ApplyRecord `json:"apply_log"`
	State    tools.State         `json:"state"`
}

func (p *agentProcess) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/start", func(w http.ResponseWriter, r *http.Request) {
		var wire signed.Wire
		if err := readJSON(w, r, &wire); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		res := p.agent.StartRun(context.WithoutCancel(r.Context()), wire)
		writeJSON(w, http.StatusOK, res)
	})
	mux.Handle("POST /v1/handoff", handoff.HTTPHandler(p.agent.HandleHandoff))
	mux.HandleFunc("POST /v1/approve", func(w http.ResponseWriter, r *http.Request) {
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
		if b, err := hex.DecodeString(req.Key); err != nil || len(b) != len(k) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("%w: key", value.ErrSchema))
			return
		} else {
			copy(k[:], b)
		}
		if err := p.approver.Answer(k, req.Approver, req.Yes); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, p.approver.List())
	})
	mux.HandleFunc("GET /v1/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		defer cancel()
		res, err := p.agent.Wait(ctx, r.PathValue("id"))
		if err != nil {
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "running or unknown"})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /v1/env", func(w http.ResponseWriter, r *http.Request) {
		after := p.env.Snapshot()
		writeJSON(w, http.StatusOK, envReport{Diff: tools.Diff(p.before, after), ApplyLog: p.env.ApplyLog(), State: after})
	})
	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) {
		ch, cancel := p.hub.Subscribe()
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
	})
	return mux
}

func cmdAgent(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	role := fs.String("role", "", "investigator or responder")
	cfgPath := fs.String("config", "", "agent configuration file")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *cfgPath == "" {
		fs.Usage()
		return errUsage
	}
	var cfg AgentFileConfig
	if err := loadYAML(*cfgPath, &cfg); err != nil {
		return err
	}
	if *role != "" && *role != cfg.Role {
		return fmt.Errorf("%w: --role %s but the configuration is for %s", value.ErrConfig, *role, cfg.Role)
	}
	p, err := buildAgent(cfg, configBase(*cfgPath), log.With("agent", cfg.Role))
	if err != nil {
		return err
	}
	ln, err := listenLoopback(cfg.Listen)
	if err != nil {
		return err
	}
	// Announce the bound address on stdout for supervisors (citadel demo).
	fmt.Fprintf(os.Stdout, "{\"listening\":%q}\n", ln.Addr().String())
	err = serve(ctx, log, ln, p.handler(), 3*time.Minute)
	p.agent.Drain()
	if cerr := p.writer.Close(); err == nil {
		err = cerr
	}
	return err
}

func cmdOrchestrator(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("orchestrator", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "orchestrator configuration file")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *cfgPath == "" {
		fs.Usage()
		return errUsage
	}
	var cfg OrchestratorFileConfig
	if err := loadYAML(*cfgPath, &cfg); err != nil {
		return err
	}
	base := configBase(*cfgPath)
	o, err := buildOrchestrator(cfg, base)
	if err != nil {
		return err
	}
	if cfg.Investigator == "" {
		return fmt.Errorf("%w: investigator URL is required", value.ErrConfig)
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/runs", func(w http.ResponseWriter, r *http.Request) {
		var req orchestrator.TaskRequest
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		m, err := o.Mint(req)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		log.Info("context minted", "run", m.Context.RunID, "task", m.Context.Task, "principal", m.Context.Principal)
		res, err := postJSON(r.Context(), client, cfg.Investigator+"/v1/start", signed.EncodeWire(m.Wire))
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"run_id": m.Context.RunID, "investigator": res})
	})
	ln, err := listenLoopback(cfg.Listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "{\"listening\":%q}\n", ln.Addr().String())
	return serve(ctx, log, ln, mux, 3*time.Minute)
}

func buildOrchestrator(cfg OrchestratorFileConfig, base string) (*orchestrator.Orchestrator, error) {
	cat, baseInv, err := loadCatalogAndInventory(resolve(base, cfg.Catalog), resolve(base, cfg.Inventory))
	if err != nil {
		return nil, err
	}
	fx, err := fixtureFor(resolve(base, cfg.Fixture))
	if err != nil {
		return nil, err
	}
	spec, err := fx.EnvSpec(baseInv)
	if err != nil {
		return nil, err
	}
	inv, err := tools.NewInventory(spec.Inventory)
	if err != nil {
		return nil, err
	}
	signer, err := signed.LoadSigner(resolve(base, cfg.Key))
	if err != nil {
		return nil, err
	}
	clock, err := clockFor(cfg.Clock, fx)
	if err != nil {
		return nil, err
	}
	soft := harness.DefaultThresholds().SoftUntrustedPC
	if cfg.Thresholds != "" {
		f, err := harness.LoadThresholds(resolve(base, cfg.Thresholds))
		if err != nil {
			return nil, err
		}
		soft = f.SoftUntrustedPC
	}
	return orchestrator.New(orchestrator.Config{Catalog: cat, Inventory: inv, Signer: signer, Clock: clock, Rand: rand.Reader,
		PolicyVersion: cfg.PolicyVersion, SoftUntrustedPC: soft})
}

func configBase(path string) string {
	abs, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return filepath.Dir(path)
	}
	// Paths in configuration files are relative to the repository root when
	// the file lives in configs/; otherwise to the file's directory.
	if filepath.Base(abs) == "configs" {
		return filepath.Dir(abs)
	}
	return abs
}
