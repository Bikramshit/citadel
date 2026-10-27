# Progress

## Plan

Citadel is built in the order the specification's ten-day plan sets: deterministic security core first, then the two agents and the signed handoff (milestone M1), then evidence, then the evaluation harness, then the dashboard. Every phase ends with `make check` and its exit tests.

| Phase | Scope | Packages |
| --- | --- | --- |
| 0 | Repository, Makefile, CI, docs, catalog, gate | `configs/`, `docs/` |
| 1 | Labels, values, strict decoding | `label`, `value` |
| 2 | Plan and static check, interpreter, catalog, authorization, policy, run state, mock environment | `plan`, `interp`, `catalog`, `authz`, `policy`, `runstate`, `tools` |
| 3 | Scripted adversaries, approvals, attempts, invariant checker | `llm/scripted`, `runstate`, `harness` |
| 4 | Orchestrator, two agents in one process, model adapters if the gate allows | `orchestrator`, `llm` |
| 5 | Signed handoff, HTTP between two processes, milestone M1 | `signed`, `handoff`, `cmd/citadel` |
| 6 | Evidence, thresholds, B1 to B12 with scripted models | `evidence`, `cmd/citadel tune` |
| 7 | Evaluation harness, fixtures, metrics, tables | `harness` |
| 8 | Dashboard | `web/`, `cmd/citadel dash` |
| 9 | Full measurement and documentation | README |

## Layout decisions

These follow from the specification's package list being exact. None of them is security-relevant.

- The strict JSON and YAML decoders, the `Clock`, and the specification's error codes live in `internal/value`. Every component that parses input already imports it, and the package list has no separate errors package.
- The tool-signature table (arguments, target argument, state-changing flag, sink) lives in `internal/authz`, beside the capability types it is checked against.
- The replay table lives in `internal/runstate`, which the specification's package list names for it. `internal/signed` holds the exact-bytes tokens and the key registry.

## Gate status

All four gate items are **unconfirmed** (see [GATE.md](GATE.md)). Model adapters are a recorded dependency on the gate, not a placeholder: everything else is built and tested against `internal/llm/scripted`.

## Status

| Phase | Status | Evidence |
| --- | --- | --- |
| 0 | Done | `make check` passes on the skeleton; GATE.md lists all four items as unconfirmed |
| 1 | Done | L1 and L2 pass; fuzz targets exist for the IPv4, account-ID, and host-name parsers and the strict decoder |
| 2 | In progress | Rules A0 to A3, I1 to I3, F0, F1, C1, D0, A4, A5, and F3 each pass a positive and a negative test; CT3 passes with `-race -count=50`; mock environment done |

Open questions are in [QUESTIONS.md](QUESTIONS.md).
