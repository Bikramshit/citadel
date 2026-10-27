// Command citadel is Citadel's single binary: keygen, orchestrator, agent,
// demo, harness, tune, and dash.
//
//	citadel keygen --agent <id> [--role agent|orchestrator]
//	citadel orchestrator --config configs/orchestrator.yaml
//	citadel agent --role investigator|responder --config <file>
//	citadel demo m1
//	citadel tune --fixtures testdata/dev
//	citadel harness --configs C0,C1-instr,C1-data,C2 --trials 5 --fixtures testdata/eval
//	citadel dash --runs runs/
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"citadel/internal/value"
)

const usage = `usage: citadel <command> [flags]

commands:
  keygen        generate a signing key and add it to the registry
  orchestrator  run the model-free orchestrator
  agent         run the investigator or responder agent
  demo          run a demonstration (m1)
  tune          tune thresholds on development fixtures
  harness       run the evaluation and generate tables
  dash          serve the dashboard

Run "citadel <command> -h" for a command's flags.
`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmds := map[string]func(context.Context, *slog.Logger, []string) error{
		"keygen": cmdKeygen, "orchestrator": cmdOrchestrator, "agent": cmdAgent, "demo": cmdDemo,
		"tune": cmdTune, "harness": cmdHarness, "dash": cmdDash,
	}
	run, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(ctx, log, os.Args[2:]); err != nil {
		code := value.CodeOf(err)
		log.Error(os.Args[1]+" failed", "code", code, "error", value.Truncate(err.Error()))
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")
