# Progress

## Plan

Citadel is built in the order the specification's ten-day plan sets: the deterministic security core first, then the two agents and the signed handoff (milestone M1), then evidence, then the evaluation harness, then the dashboard. Every phase ends with `make check` and its exit tests.

| Phase | Scope | Packages |
| --- | --- | --- |
| 0 | Repository, Makefile, CI, docs, catalog, gate | `configs/`, `docs/` |
| 1 | Labels, values, strict decoding | `label`, `value` |
| 2 | Plan and static check, interpreter, catalog, authorization, policy, run state, mock environment | `plan`, `interp`, `catalog`, `authz`, `policy`, `runstate`, `tools` |
| 3 | Scripted adversaries, approvals, attempts, invariant checker | `llm/scripted`, `runstate`, `harness` |
| 4 | Orchestrator, two agents, model adapters if the gate allows | `orchestrator`, `interp`, `llm` |
| 5 | Signed handoff, HTTP between two processes, milestone M1 | `signed`, `handoff`, `cmd/citadel` |
| 6 | Evidence, thresholds, B1 to B12 with scripted models | `evidence`, `citadel tune` |
| 7 | Evaluation harness, fixtures, metrics, tables | `harness`, `citadel harness` |
| 8 | Dashboard | `web/`, `citadel dash` |
| 9 | Full measurement and documentation | README |

## Layout decisions

These follow from the specification's package list being exact. None of them is security-relevant.

- The strict JSON and YAML decoders, the `Clock`, and the specification's error codes live in `internal/value`. Every component that parses input already imports it, and the package list has no separate errors package.
- The tool-signature table (arguments, target argument, state-changing flag, sink) lives in `internal/authz`, beside the capability types it is checked against.
- The replay table lives in `internal/runstate`, which the package list names for it. `internal/signed` holds the exact-bytes tokens and the key registry.
- The agent runtime (verify, plan, execute, receive) lives in `internal/interp`, beside the interpreter it drives.
- Milestone M1's scenario is defined in Go (`harness.M1Fixture`), so `TestM1` and `citadel demo m1` share it.

## Gate status

All four gate items are **unconfirmed** (see [GATE.md](GATE.md)). This is a recorded dependency, not a placeholder:

- **Built and tested:** the model-call discipline, independent of any provider, in `internal/llm/model.go`. It covers per-call timeouts, an in-process rate limiter, backoff on rate-limit and server errors only, at most two retries for invalid plan JSON (each logged), a running count of calls and tokens, and no tool definitions for the processor.
- **Missing:** the provider client that sends a request to a Meta model endpoint. It needs the gate's model IDs and request format.
- **Until then:** `--impl model` fails with a message that points to GATE.md, and every run records `impl: scripted`.

Phase 4's "B1 completes with a real model" and Phase 9's full model measurement are blocked on the gate. If it stays closed, the specification's fallback applies: the deliverable is deterministic evidence only (Experiments 1, 3, and 4), and the README says so.

## Status

| Phase | Status | Evidence |
| --- | --- | --- |
| 0 | Done | `make check` targets exist and pass; GATE.md lists all four items, all unconfirmed |
| 1 | Done | L1 and L2 pass; fuzz targets for the IPv4, account-ID, and host-name parsers and the strict decoder |
| 2 | Done | Every rule (A0 to A5, I1 to I3, F0, F1, F3, E1, E2, C1, D0) passes a positive and a negative test; L3, L4, and CT3 pass under `-race` |
| 3 | Done | T-A1 to T-A5, T-A7, L5, L7, CT4, CT5, and X1 to X3 pass with the invariant checker active; `TestInvariantCheckerDetectsEachInvariant` shows the checker catches each of the 13 invariants |
| 4 | Done, except model adapters (gate) | D1, D2, D3, and D5 pass with scripted models; the gate status is recorded |
| 5 | Done | P1 to P18, D4, T-A6, L6, CT1, CT2, CT6, and CT7 pass; `TestM1` passes; `citadel demo m1` passes all seven elements across two OS processes over HTTP; the trace is committed in `runs/m1/` |
| 6 | Done | E-T1 to E-T13 pass; `configs/thresholds.yaml` was committed (9f7185e) before any evaluation run; scripted B1 to B12 match their expected outcomes, B12's unwarranted block included |
| 7 | Done (scripted) | 21 attack and 12 benign fixtures with goal predicates; a one-trial run across all four configurations generated a complete table with 0 crashes and 0 invariant violations |
| 8 | Done | The dashboard replays recorded runs, streams live scripted runs, and serves an approval card for the principal |
| 9 | Partial | README written; benchmarks exist for Experiment 4; model measurement is blocked on the gate |

### Fuzzing

`make fuzz` runs every target for FUZZTIME (default 10 minutes); CI runs each for 30 seconds. Local results for this commit are recorded under "Verification log" below. The specification asks for 10 minutes per target in Phase 5. Any target not yet run for that long is listed there as outstanding.

## Verification log

Commands run on this machine (darwin/arm64, go1.27.3) before each commit; the newest first.

- `go test -race ./...`: every package passes.
- `go test -race -count=50` on the CT and L7 tests (`make concurrency`): pass.
- `staticcheck` 2026.2.2 and `govulncheck` v1.9.0: clean ("No vulnerabilities found").
- `make check` (gofmt, vet, staticcheck, govulncheck, `go test -race ./...`, concurrency tests ×50, traceability, coverage): passes. Coverage of the seven required packages: label 100.0%, evidence 96.8%, authz 95.1%, runstate 93.9%, handoff 93.5%, signed 92.4%, policy 92.2%.
- `citadel demo m1`: seven of seven elements pass. The Investigator and the Responder ran as two processes, with the handoff over HTTP on 127.0.0.1.
- `citadel tune --fixtures testdata/dev`: k = 5. The other thresholds keep their starting values, verified on DEV-1, DEV-3, and DEV-6.
- `citadel harness --impl scripted --trials 1` across all four configurations: 132 runs, 0 crashed, 0 with invariant violations (runs/results/20261027T130002Z-scripted).
- Experiment 3, deterministic: C2 with E1 and E2 and with the old rule on G3b, G5, and B1 to B12, 18 runs each, 0 crashed, 0 invalid (runs/results/experiment3/20261027T130030Z-scripted, runs/results/experiment3/20261027T130031Z-evidence-legacy-scripted).
- `make bench`: Experiment 4 benchmarks in runs/results/bench.txt.
- Mutation checks:
  - Disabling A3's protected-asset branch fails `TestA3_ProtectedPublicAsset`.
  - Disabling the iteration pre-check fails L4.
  - Leaking data values into the planner input fails `TestPlannerPromptsContainNoUntrustedValues`.
  - Removing a traced test ID fails `TestTraceability`.

## Final implementation checklist

Deterministic core, before any model run:

- [x] Labels: L1 and L2 pass; no exported function removes a source
- [x] Interpreter and static check: L3, L4, T-A1 to T-A5, T-A7
- [x] Authorization and delegation: every A, I, F, and D rule's positive and negative test; D1 to D5
- [x] Run state: CT1 to CT7 pass under `go test -race -count=50`
- [x] Tool outcomes: X1 to X3 pass; invariants 8 to 11 hold
- [x] Handoff: P1 to P18, T-A6, and L6 pass
- [ ] Each fuzz target ran 10 minutes without a failure (see Fuzzing)
- [x] Milestone M1: `TestM1` passes and the `citadel demo m1` trace is committed
- [x] Evidence: E-T1 to E-T13 pass; `thresholds.yaml` committed from development fixtures only
- [x] The invariant checker runs in every harness test, and all 13 invariants hold

Before reporting any number:

- [ ] GATE.md is complete, and every model used is allowed by the rules (blocked: no answers yet)
- [x] The thresholds commit predates the first evaluation run; no evaluation fixture was used for tuning
- [x] All four configurations ran on identical fixtures; crashes and aborts count as failures
- [x] Tables generated from `runs/`, with sample sizes, Wilson intervals, model IDs, and dates
- [x] Uncertain outcomes reported on their own; the B12 limitation reported

Before submitting:

- [x] README states the threat model, guarantees 1 to 9, and the limits
- [ ] The video shows only real runs and real event logs (not part of this repository)
- [x] Every claim checked against the claim tiers; no unmeasured number stated as a result
- [ ] Preprint, FIDES, and design-patterns citations verified, or marked unverified (marked unverified in ARCHITECTURE.md; not re-checked)

Open questions are in [QUESTIONS.md](QUESTIONS.md).
