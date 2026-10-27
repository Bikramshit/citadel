package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"citadel/internal/events"
	"citadel/internal/harness"
	"citadel/internal/interp"
	"citadel/internal/orchestrator"
	"citadel/internal/signed"
	"citadel/internal/tools"
	"citadel/internal/value"
	"go.yaml.in/yaml/v3"
)

func cmdDemo(ctx context.Context, log *slog.Logger, args []string) error {
	if len(args) < 1 || args[0] != "m1" {
		fmt.Fprintln(os.Stderr, "usage: citadel demo m1 [--out runs/m1] [--root .]")
		return errUsage
	}
	fs := flag.NewFlagSet("demo m1", flag.ContinueOnError)
	out := fs.String("out", "runs/m1", "output directory for the trace")
	root := fs.String("root", ".", "repository root (for configs/)")
	if err := fs.Parse(args[1:]); err != nil {
		return errUsage
	}
	return demoM1(ctx, log, *root, *out)
}

// demoM1 runs milestone M1 across two OS processes: this process runs the
// orchestrator and the Investigator; a child `citadel agent` process runs the
// Responder. The handoff crosses real HTTP on 127.0.0.1, signed and verified.
func demoM1(ctx context.Context, log *slog.Logger, rootDir, out string) error {
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return err
	}
	out, err = filepath.Abs(out)
	if err != nil {
		return err
	}
	keys, err := os.MkdirTemp("", "citadel-m1-keys-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(keys)
	now := time.Now().UTC()
	reg := filepath.Join(keys, "registry.json")
	keyPaths := map[string]string{}
	for _, a := range []string{"orchestrator", harness.Investigator, harness.Responder} {
		role := signed.RoleAgent
		if a == "orchestrator" {
			role = signed.RoleOrchestrator
		}
		kid, err := signed.Keygen(signed.KeygenOptions{Dir: keys, Registry: reg, Agent: a, Role: role,
			NotBefore: now.Add(-30 * 24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), Rand: rand.Reader})
		if err != nil {
			return err
		}
		keyPaths[a] = filepath.Join(keys, kid+".key")
	}
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o750); err != nil {
		return err
	}
	epoch := time.Now().UTC()
	clock := ClockConfig{Mode: "fixture", Epoch: epoch}
	agentCfg := func(role string, peers map[string]string) AgentFileConfig {
		return AgentFileConfig{Role: role, Listen: "127.0.0.1:0", Catalog: filepath.Join(root, "configs/catalog.yaml"),
			Inventory: filepath.Join(root, "configs/inventory.yaml"), Fixture: "builtin:M1", Registry: reg, Key: keyPaths[role],
			PolicyVersion: harness.PolicyVersion, HandoffMode: "C2", Evidence: "off", Peers: peers,
			Events: filepath.Join(out, role+".jsonl"), Models: ModelConfig{Impl: "scripted"}, Clock: clock}
	}
	respPath := filepath.Join(keys, "responder.yaml")
	b, err := yaml.Marshal(agentCfg(harness.Responder, nil))
	if err != nil {
		return err
	}
	if err := os.WriteFile(respPath, b, 0o600); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cctx, cancelChild := context.WithCancel(ctx)
	defer cancelChild()
	child := exec.CommandContext(cctx, self, "agent", "--role", harness.Responder, "--config", respPath)
	child.Cancel = func() error { return child.Process.Signal(syscall.SIGTERM) }
	child.WaitDelay = 10 * time.Second
	childLog, err := os.Create(filepath.Join(out, "responder.log"))
	if err != nil {
		return err
	}
	defer childLog.Close()
	child.Stderr = childLog
	stdout, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("start responder: %w", err)
	}
	log.Info("responder process started", "pid", child.Process.Pid)
	addr, err := readListening(stdout, 15*time.Second)
	if err != nil {
		cancelChild()
		child.Wait()
		return fmt.Errorf("responder did not start: %w (see %s)", err, filepath.Join(out, "responder.log"))
	}
	respURL := "http://" + addr
	inv, err := buildAgent(agentCfg(harness.Investigator, map[string]string{harness.Responder: respURL}), root, log.With("agent", "investigator"))
	if err != nil {
		cancelChild()
		child.Wait()
		return err
	}
	orch, err := buildOrchestrator(OrchestratorFileConfig{Catalog: filepath.Join(root, "configs/catalog.yaml"),
		Inventory: filepath.Join(root, "configs/inventory.yaml"), Fixture: "builtin:M1", Key: keyPaths["orchestrator"],
		PolicyVersion: harness.PolicyVersion, Clock: clock}, root)
	if err != nil {
		cancelChild()
		child.Wait()
		return err
	}
	fx := harness.M1Fixture()
	params, err := fx.ParamsJSON()
	if err != nil {
		return err
	}
	minted, err := orch.Mint(orchestrator.TaskRequest{Principal: fx.Task.Principal, Role: fx.Task.Role, Task: fx.Task.Task,
		Version: fx.Task.Version, Params: params, Note: fx.Task.Note})
	if err != nil {
		cancelChild()
		child.Wait()
		return err
	}
	log.Info("context minted", "run", minted.Context.RunID)
	ir := inv.agent.StartRun(ctx, minted.Wire)
	client := &http.Client{Timeout: 5 * time.Second}
	var rr interp.RunResult
	deadline := time.Now().Add(30 * time.Second)
	for {
		code, err := getJSON(ctx, client, respURL+"/v1/runs/"+minted.Context.RunID, &rr)
		if err == nil && code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			cancelChild()
			child.Wait()
			return fmt.Errorf("responder run did not finish")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var env envReport
	if _, err := getJSON(ctx, client, respURL+"/v1/env", &env); err != nil {
		return err
	}
	cancelChild()
	if err := child.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() > 0 {
			log.Warn("responder exit", "error", err.Error())
		}
	}
	inv.agent.Drain()
	if err := inv.writer.Close(); err != nil {
		return err
	}
	trace, err := mergeTraces(filepath.Join(out, "trace.jsonl"), filepath.Join(out, "investigator.jsonl"), filepath.Join(out, "responder.jsonl"))
	if err != nil {
		return err
	}
	rec := &harness.RunRecord{Fixture: fx.ID, Kind: fx.Kind, Goal: fx.Goal, Config: harness.C2, Impl: "scripted", RunID: minted.Context.RunID,
		Investigator: &ir, Responder: &rr, ApplyLog: env.ApplyLog, Events: trace}
	for _, c := range env.Diff {
		rec.Diff = append(rec.Diff, harness.Change{Tool: c.Tool, Action: c.Action, Target: c.Target})
	}
	spec, err := fx.EnvSpec(mustInventory(root))
	if err != nil {
		return err
	}
	invData, err := tools.NewInventory(spec.Inventory)
	if err != nil {
		return err
	}
	rec.Violations, rec.Measured = harness.CheckInvariants(fx, rec, invData)
	checks := harness.CheckM1(rec)
	if err := writeFileJSON(filepath.Join(out, "checks.json"), map[string]any{"run_id": rec.RunID, "processes": 2,
		"responder_url": respURL, "checks": checks, "violations": rec.Violations, "diff": rec.Diff}); err != nil {
		return err
	}
	os.Remove(filepath.Join(out, "investigator.jsonl"))
	os.Remove(filepath.Join(out, "responder.jsonl"))
	failed := 0
	fmt.Printf("Milestone M1: run %s, Investigator (pid %d) and Responder (pid %d) over HTTP\n", rec.RunID, os.Getpid(), child.Process.Pid)
	for _, c := range checks {
		mark := "PASS"
		if !c.OK {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("  %s  %d. %s: %s\n", mark, c.Element, c.Name, c.Detail)
	}
	fmt.Printf("Trace: %s (%d events)\n", filepath.Join(out, "trace.jsonl"), len(trace))
	if failed > 0 {
		return fmt.Errorf("M1: %d of %d elements failed", failed, len(checks))
	}
	return nil
}

func mustInventory(root string) tools.InventoryData {
	d, err := harness.LoadBaseInventory(filepath.Join(root, "configs/inventory.yaml"))
	if err != nil {
		return tools.InventoryData{}
	}
	return d
}

func readListening(r interface{ Read([]byte) (int, error) }, timeout time.Duration) (string, error) {
	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(r)
		if sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	select {
	case line, ok := <-lines:
		if !ok {
			return "", fmt.Errorf("no output")
		}
		var v struct {
			Listening string `json:"listening"`
		}
		if err := value.DecodeStrict([]byte(line), &v, value.Limits{MaxBytes: 256}); err != nil || v.Listening == "" {
			return "", fmt.Errorf("unexpected first line %q", value.Truncate(line))
		}
		return v.Listening, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out")
	}
}

// mergeTraces merges per-process event logs into one trace ordered by time,
// then agent, then each process's own sequence number.
func mergeTraces(out string, paths ...string) ([]events.Event, error) {
	var all []events.Event
	for _, p := range paths {
		evs, err := events.ReadFile(p)
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
	}
	slices.SortStableFunc(all, func(a, b events.Event) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		if c := strings.Compare(a.Agent, b.Agent); c != 0 {
			return c
		}
		return int(a.Seq - b.Seq)
	})
	w, err := events.NewWriter(out)
	if err != nil {
		return nil, err
	}
	for _, e := range all {
		w.Emit(e)
	}
	return all, w.Close()
}

func writeFileJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
