# Claude Code Prompt: Build Citadel

## Role, objective, and source of truth

You are a senior Go security engineer. Build Citadel: a Go agent runtime that applies the CaMeL design to a two-agent incident-containment workflow. Implement the complete system specified in `docs/ARCHITECTURE.md`: every component, rule, test, fixture, command, and report it describes. The goal is the smallest credible implementation that demonstrates, under the specification's threat model, that a provenance-preserving handoff and independent authorization stop specific unauthorized actions while keeping measured task utility.

**Source of truth.**

- `docs/ARCHITECTURE.md` is the specification. Read all of it before writing any code, and re-read the relevant sections at the start of every phase.
- Precedence: the specification's never-cut security properties, then this prompt, then your own judgment.
- When the specification is ambiguous, contradictory, or impossible to implement as written, stop. Record the problem and the options in `docs/QUESTIONS.md` and ask me. Never resolve a security-relevant ambiguity silently.
- Use the specification's identifiers everywhere: rule IDs (A0 to A5, I1 to I3, F0, F1, F3, E1, E2, H1 to H6, C1, D0), test IDs (T-A1 to T-A7, D1 to D5, E-T1 to E-T13, P1 to P18, L1 to L7, CT1 to CT7, X1 to X3, M1), invariants 1 to 13, configuration names (C0, C1-instr, C1-data, C2), fixture IDs, and every `ERR_` code.

## What "production grade, no dummy code" means

**Required.**

- Every function is fully implemented. Non-test code contains no `TODO`, `FIXME`, `panic("not implemented")`, stub returns, commented-out logic, hardcoded results, or simulated outputs.
- Cryptography comes from the Go standard library (`crypto/ed25519`, `crypto/sha256`, `crypto/rand`). Agents talk over real HTTP. Parsing is strict. Concurrency control is real. Model clients make real API calls.
- Every security rule has a positive and a negative test, and every test ID in the specification exists as a named Go test.
- Errors are typed and wrapped; nothing fails silently; every rejection carries its specification error code.
- Every metric and table is computed by code from recorded runs.

**Deliberate components that are not dummies, and must exist:**

- **The mock environment:** logs, flows, inventory, firewall, and accounts, with snapshot, diff, an idempotency log, and fault injection. It is the only target for state-changing actions. It must behave like a real system of record: persistent for the run, consistent, and observable only through its interfaces.
- **Scripted stand-ins** for the planner, the processor, and the C1-instr intake, in a package named `llm/scripted`. Deterministic tests use them, and the harness can select them explicitly. They are never used silently in a run reported as a model run, and every run records which implementation it used.

**Excluded, and must not be added without my written approval:**

- Adapters that change real firewalls, directories, or any live system.
- Deployment infrastructure: containers, orchestration, databases, message queues, cloud services.
- A general-purpose agent platform, extra agents or tools, or a policy language.

If you believe one of these is needed, ask; do not build it.

## Non-negotiable security properties

Implement and test each of these exactly. Never weaken one to make a test pass, meet a deadline, or simplify code. If one looks impossible, stop and ask.

1. **Monotonic labels.** `Label` has unexported fields, and no exported function removes a source. No serialization, model output, signature, or approval upgrades trust.
2. **The runtime assigns labels.** Model outputs carry no labels, and their schemas reject label fields. Processor output is always untrusted. Every value imported from a handoff is untrusted, whatever sources the sender claims.
3. **Planner input is trusted only.** The planner sees the catalog task, analyst parameters, analyst note, effective capabilities, and data names and types; never data values or list lengths. The prompt builder is a pure function of those inputs, and a test proves no untrusted value appears in any planner prompt across all fixtures.
4. **Control flow.** An `if` on an untrusted condition aborts the run with `ERR_UNTRUSTED_BRANCH`. A loop over a list longer than the iteration budget aborts before its first iteration. No index variables, no string operations.
5. **Targets and actions.** A planner cannot name a target (I2), checked statically and at runtime. Actions are literal fields, never arguments (I3).
6. **One path to a tool.** Every state-changing call goes `StaticCheck`, then `Decide` (pure), then `Admit` (under the run lock), then the tool with its idempotency key. Enforce this with package structure: only the interpreter's executor can reach a tool.
7. **Independent checks.** Authorization (A rules) and intent (I rules) are checked separately; I1 re-checks the catalog instead of trusting the context's grants.
8. **Delegation.** Effective capabilities are `Static ∩ Grant ∩ TaskOps ∩ Requested`. The Investigator never holds a firewall or account capability.
9. **Handoffs.** Sign the exact payload bytes behind the `citadel-handoff-v1\x00` prefix. Verify the signature before parsing the payload. Run the receiver's eleven steps in order. Reject atomically. Keep the replay table's processing, accepted, and rejected states. Spend the handoff allowance only in `CommitHandoff`, under the run lock.
10. **Atomic run state.** Budgets, the handoff allowance, approvals, and duplicate detection are enforced in one critical section per run. A valid signature never stands in for remaining budget.
11. **Tool outcomes.** A lost response is reconciled by a read-only lookup. State-changing calls are never retried. An uncertain outcome is never reported as denied or failed.
12. **Evidence.** E1 and E2 use only trusted fields and independent sensors, as specified. Attacker-written fields count for nothing.
13. **Approvals.** Bound to one exact call, single-use, principal-only, expiring safely. They never override a Deny and never relabel a value.
14. **Restart fails closed** through the start-time watermark.
15. **Security results** come from environment diffs and policy events, never from what a model says it did.

## Technical constraints and repository layout

**Constraints.**

- **Go:** the latest stable release available to you, at least 1.22, pinned in `go.mod` with `go` and `toolchain` lines.
- **Dependencies:** standard library only, plus `go.yaml.in/yaml/v3` for YAML, decoded with known-field checking. Any other module needs my approval first: write the request in `docs/QUESTIONS.md` with the reason and the license. Development tools (staticcheck, govulncheck) run from the Makefile and CI and never enter `go.mod`.
- **Cryptography:** never implement primitives. Never use `math/rand` for IDs, nonces, or keys.
- **Network:** agents listen on 127.0.0.1 only. The only outbound connections allowed are to the model endpoints configured for a run. No telemetry.
- **Determinism:** time comes through a `Clock` interface and randomness through an injected `io.Reader`, so tests control both.
- **State:** all run state in memory, one process per agent, as specified. Run outputs go to `runs/<timestamp>/`.
- **Keys and secrets:** private key files are written with mode 0600, and the loader refuses a key file readable by group or others. Secrets come from files or environment variables, never from source code, and are never logged.

**Layout.** Use the specification's package list exactly, plus these top-level directories:

```text
cmd/citadel/            one binary: keygen, orchestrator, agent, demo, harness, tune, dash
internal/label/
internal/value/
internal/plan/
internal/interp/
internal/catalog/
internal/authz/
internal/orchestrator/
internal/policy/
internal/runstate/
internal/evidence/
internal/tools/
internal/signed/
internal/handoff/
internal/llm/
internal/llm/scripted/
internal/events/
internal/harness/
configs/                catalog.yaml, thresholds.yaml, example agent configs
testdata/dev/           development fixtures: threshold tuning only
testdata/eval/          evaluation fixtures: attack/ and benign/, never used for tuning
testdata/vectors/       golden vectors: signed envelopes, approval keys, idempotency keys
web/                    dashboard HTML, JS, CSS, embedded with go:embed
docs/                   ARCHITECTURE.md, THREAT.md, GATE.md, QUESTIONS.md, TRACEABILITY.md, PROGRESS.md
runs/                   generated; ignored by git except the M1 trace and final results
Makefile
.github/workflows/ci.yml
README.md
```

## Component requirements

The specification's pseudocode defines behavior; implement it faithfully, then harden it. These are the details most likely to go wrong.

| Package | Must do | Must never do |
|---|---|---|
| `label` | Sorted, deduplicated sources; `Join` takes the union of sources and the intersection of readers; `Trusted` requires every source trusted | Expose a way to remove or replace a source |
| `value` | Strict parsers: IPv4 through `net/netip`, IPv4 only, no zones, no leading zeros, and the parsed value's `String()` must equal the input; account IDs match `^[a-z][a-z0-9-]{1,31}$`; host names come from the inventory | Normalize silently; accept IPv6 or IPv4-mapped forms |
| Strict JSON helper | Size limits, unknown-field rejection, a token-level pre-pass that rejects duplicate keys, exactly one top-level value | Rely on `encoding/json` defaults, which keep the last duplicate |
| `plan` | Validate the AST in Go; `StaticCheck` rejects the whole plan before any statement runs | Execute a plan that failed any check |
| `interp` | The nine execution semantics in the specification; the executor is the only caller of tools; pc stack for untrusted loops | Call a tool while holding a lock; retry a state-changing call |
| `catalog`, `authz`, `orchestrator` | Validate analyst parameters; mint the context with 128-bit random run IDs, participating agents, policy version, expiry, budgets; sign it behind `citadel-authctx-v1\x00`; `Meet`, `Intersect`, `Effective` as specified | Grant an operation that is not in the catalog for that agent |
| `policy` | Pure `Decide`; every rule in the table; every applicable rule's result recorded; D0 when A1 or a routing rule is missing | Read or write run state inside `Decide` |
| `runstate` | `Activate`, `Admit`, `RequestApproval`, `Approve`, `CommitHandoff`, `Close`, replay table, exactly as specified; lock order `Runs.mu` before `RunState.mu` | Refund budgets; consume an approval outside `Admit` |
| `tools` | Mock logs, flows, inventory, firewall, accounts; `Apply` idempotent by key; read-only `Lookup`; fault modes `none`, `drop_before_apply`, `drop_after_apply`, `lookup_down`; snapshot and diff | Reach any real system; expose state except through these interfaces |
| `evidence` | Deduplicate by event ID and by a digest of trusted fields with the timestamp truncated to the second; sensor registry; verdict order exactly as the table states | Parse attacker-written fields as records; count flows from a shared sensor or pipeline |
| `signed`, `handoff` | Wire format, registry with validity windows and revocation, freshness and lifetime limits, start-time watermark, replay table, `Verify` in the specified order, `CheckSend` | Parse the payload before the signature verifies; import anything from a rejected envelope |
| `llm` | `Planner` and `Processor` interfaces; real adapters per the gate; strict decoding into registered Go types; at most two retries for invalid plan JSON, each logged; timeouts | Give the processor tools; send untrusted values to a planner |
| `events` | JSONL writer synced when a run ends; server-sent events fan-out; separate `decision` and `attempt` kinds | Feed events back into execution |
| `harness` | C0, C1-instr, C1-data, C2; fixture loader; goal predicates; invariant checker; metrics with Wilson intervals; table generator; run metadata (model IDs, provider, settings, prompt hashes, git commit, thresholds commit, implementation used) | Drop a failed run; tune on evaluation fixtures |
| Dashboard | Panels in the specified order; replay of recorded runs; live events; approvals only from the context's principal | Show a number no script produced |

**C0 must be a fair baseline,** not a strawman: the same models, task description, and mock tools as the Citadel configurations, with ordinary tool calling and no Citadel runtime.

**Commands.**

```text
citadel keygen --agent <id>
citadel orchestrator --config configs/orchestrator.yaml
citadel agent --role investigator|responder --config <file>
citadel demo m1
citadel tune --fixtures testdata/dev
citadel harness --configs C0,C1-instr,C1-data,C2 --trials 5 --fixtures testdata/eval
citadel dash --runs runs/
```

## Model integration and the access gate

Nothing about model names, endpoints, request formats, authentication, credits, or hackathon model rules is known until I tell you. Do not guess any of it.

**The gate (Phase 0).** Ask me for, and record in `docs/GATE.md` with the evidence I give you (documentation excerpts, links, rule text):

1. Which Meta models are available, by exact model ID, for the planner and for the processor.
2. The API documentation: endpoint, request and response format, structured-output support, authentication, and rate limits.
3. Whether the rules require Meta models for every model call, including the C0 baseline.
4. The credit budget, against about 660 evaluation runs of three to four model calls each.

Mark each item confirmed or unconfirmed. Until an item is confirmed, build and test everything else against `llm/scripted`, and record the phase as blocked on the gate in `docs/PROGRESS.md`. That is a recorded dependency, not a placeholder. Write the real adapter as soon as I provide the documentation. Never switch to another provider's model without my written approval in `GATE.md`.

**Adapter requirements.**

- Endpoint, model ID, and API-key file come from configuration and are recorded in every run's metadata. No model name is hardcoded.
- Request JSON-structured output where the API supports it; decode strictly into the registered Go type; reject unknown fields.
- Invalid planner output gets at most two retries, each logged; after that the run aborts and counts as a failure.
- Retry with backoff only on rate-limit and server errors, and only for model calls, never for tool calls.
- Per-call timeouts; an in-process rate limiter; a running count of calls and tokens written to run metadata.
- The processor is called without any tool definitions.

**Fallbacks**, from the specification: if no hosted planner model is available by the end of Phase 2, use the Meta open-weight model for both roles; if no Meta model is available by the end of Phase 4, deliver deterministic evidence only and state that plainly.

## Build phases with exit gates

Phases follow the specification's ten-day plan. In every phase: re-read the relevant sections, write the tests for security packages first, implement, run `make check` and the phase's exit tests, update `docs/TRACEABILITY.md` and `docs/PROGRESS.md`, and commit. Do not start a phase until the previous exit gate passes. If a gate cannot pass, apply the specification's cut list in order and record what was cut; never cut a never-cut item. Milestone M1 outranks everything in Phases 6 to 9.

### Phase 0: setup and gate (Day 1)

- `go.mod`, Makefile, CI workflow, documentation skeletons; `docs/THREAT.md` written from the specification; `configs/catalog.yaml`
- Ask me the gate questions; create `docs/GATE.md`
- Exit: `make check` passes on the skeleton; every gate item is marked confirmed or unconfirmed

### Phase 1: labels, values, strict decoding (Day 2)

- `label`, `value`, the strict JSON helper; L1, L2; fuzz targets for parsers and the decoder
- Exit: L1 and L2 pass; each fuzz target runs 5 minutes without a failure

### Phase 2: interpreter, authorization, policy, run state, mock environment (Day 3)

- `plan` with `StaticCheck`; `interp`; `catalog`; `authz` with `Meet`, `Intersect`, `Effective`; pure `Decide` with A0 to A3, I1 to I3, F0, F1, D0; `runstate` with `Activate` and `Admit` (A0 re-check, A4, A5, F3); mock environment with snapshot, diff, idempotency log, fault injection
- Exit: every listed rule's positive and negative test passes; L3, L4, and CT3 pass under `-race`

### Phase 3: scripted adversaries, approvals, attempts (Day 4)

- `llm/scripted` worst-case processor, faulty planner, obedient C1-instr intake; approval state machine with `KeyFor` golden vectors; attempt states and lookup reconciliation; the invariant checker
- Exit: T-A1 to T-A5, T-A7, L5, L7, CT4, CT5, X1 to X3 pass with the invariant checker active

### Phase 4: orchestrator and two agents in one process (Day 5)

- Orchestrator; Investigator and Responder with an in-memory typed handoff; model adapters if the gate allows
- Exit: D1, D2, D3, D5 pass with scripted models; B1 completes with a real model, or the gate status is recorded

### Phase 5: signed handoff and milestone M1 (Day 6)

- `signed` (exact-bytes tokens, keygen, registry, rotation, watermark); `handoff` (`Payload`, `CheckSend`, `Verify`, replay table, `CommitHandoff`); HTTP between two processes; P1 to P18, D4, T-A6, L6, CT1, CT2, CT6, CT7; fuzz targets
- `TestM1` and `citadel demo m1`, with all seven milestone elements from the specification
- Exit: M1 passes and its trace is committed; each fuzz target runs 10 minutes without a failure

### Phase 6: evidence and thresholds (Day 7)

- Evidence store with sensor and pipeline IDs; E1, E2; conflicts; deduplication; E-T1 to E-T13; development fixtures; `citadel tune` applying the specification's fixed rule; commit `thresholds.yaml` before any evaluation run; B1 to B12 with scripted models
- Exit: E tests pass; the thresholds commit exists; scripted B1 to B12 match their expected outcomes, including B12's unwarranted block

### Phase 7: evaluation harness (Day 8)

- C0, C1-instr intake, C1-data; 21 attack and 12 benign evaluation fixtures with goal predicates; metrics; table generator; a one-trial run across all four configurations
- Exit: a complete generated table, with every crash explained

### Phase 8: dashboard (Day 9)

- Panels in the specified order; replay of recorded runs; live events
- Exit: the dashboard replays a recorded C1-instr run and a C2 run from real event logs

### Phase 9: full measurement and documentation (Days 9 and 10)

- Full run with the number of trials the credits allow; benchmarks for Experiment 4; README
- Exit: the definition of done below

## Testing, traceability, and evaluation integrity

**Tests.**

- Name every test after its specification ID, for example `TestTA1_InvestigatorFirewallCallRejected` or `TestCT1_DuplicateEnvelopeAcceptedOnce`.
- `docs/TRACEABILITY.md` maps every rule ID, invariant, and test ID to its test functions and files. A Go test parses it and fails CI if any specification ID has no test or any listed test does not exist.
- The invariant checker runs after every deterministic test and every harness run; a violation fails the test or marks the run invalid.
- Concurrency tests run with `-race -count=50`, start goroutines from a shared barrier, and use the fake clock.
- Fuzz targets are those the specification lists; their seed corpora are committed.
- Golden vectors for signed envelopes (fixed test keys), approval keys, and idempotency keys live in `testdata/vectors/`.
- Statement coverage is at least 90% for `label`, `authz`, `policy`, `runstate`, `signed`, `handoff`, and `evidence`; CI reports it.
- Never delete, skip, or loosen a test to get a green build. If a test looks wrong, explain why in `docs/QUESTIONS.md` and ask.

**Evaluation integrity.**

- Every reported number is produced by the table generator from `runs/`. The README contains no hand-typed results.
- `citadel tune` reads only `testdata/dev/`. `citadel harness` refuses to score `testdata/eval/` unless `configs/thresholds.yaml` is committed, and it records that commit in every run.
- All configurations use identical fixtures, ground truth, models, and prompts, except for the handoff adapter.
- Crashes, timeouts, aborts, and malformed plans count as failed runs; no run is dropped.
- Every table cell reports its sample size, with 95% Wilson intervals.
- Deterministic results and model-run results are reported separately and never mixed in one table.
- No comparison with numbers from CaMeL, AgentDojo, or any paper.
- Any threshold change made after seeing evaluation results is reported as post-hoc, with both results shown.

## Engineering quality bar

**Make targets.**

```text
make check     gofmt check, go vet, staticcheck, govulncheck, go test -race ./..., traceability check, coverage report
make fuzz      every fuzz target for FUZZTIME (default 10m)
make keys      generate test and demo keys with correct permissions
make m1        run TestM1 and citadel demo m1, writing the trace to runs/
make tune      citadel tune on development fixtures
make eval      citadel harness on evaluation fixtures (TRIALS, CONFIGS)
make dash      start the dashboard on localhost
```

CI runs `make check` and 30 seconds per fuzz target on every push.

**Code.**

- One sentinel error per specification code, wrapped with `%w`, checked with `errors.Is` in tests.
- No global mutable state apart from the process start time held by `Runs`.
- Configuration is validated at startup; the process refuses to start on missing or invalid configuration.
- Every exported identifier has a doc comment.
- Map iteration that affects output (events, tables, prompts, hashes) is sorted, so output is deterministic.

**Services.**

- HTTP servers set `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and `IdleTimeout`; wrap bodies in `http.MaxBytesReader`; bind to 127.0.0.1; recover handler panics into a 500 response with no stack trace; shut down gracefully on SIGINT and SIGTERM through context cancellation.
- Logging uses `log/slog` with JSON output. Never log secrets or API keys. Attacker-controlled text is truncated and escaped in logs. Audit records go to the JSONL event log, not to slog.

## Working protocol, definition of done, and out of scope

**How to work.**

1. Start by reading `docs/ARCHITECTURE.md` in full. Write a short plan in `docs/PROGRESS.md`: components, phases, and open questions. Then ask me the gate questions.
2. Work one phase at a time, in small commits with clear messages.
3. Before calling anything done, run `make check` and the phase's exit tests, and record a summary of the output in `docs/PROGRESS.md`.
4. Never claim a test passes without running it. Never write a result you did not compute.

**Stop and ask me when:**

- the specification is ambiguous about a security property;
- you need a dependency not already allowed;
- model API details are missing or unclear;
- a never-cut property conflicts with anything else;
- a test seems wrong;
- the schedule requires applying the cut list.

**Definition of done.**

- Every item in the specification's final implementation checklist is satisfied, with evidence in `docs/PROGRESS.md`.
- `make check` passes in CI; every fuzz target ran for its stated time; the M1 trace is committed.
- `make eval` regenerates the result tables from a clean checkout, given the same models and credentials. If the gate failed, the deliverable is deterministic results only, and the README says so.
- The README covers: what Citadel is, with credit to CaMeL and AgentDojo; the threat model; guarantees 1 to 9 with their assumptions; the limitations; reproduction commands; and the generated tables. Claims stay inside the specification's claim tiers. The README never says "production-ready", "provably secure", "unhackable", or "prevents prompt injection", and never presents the unverified preprint as confirming a gap.

**Out of scope.** Live firewalls, directories, or any real system; containers, orchestration, databases, queues, or cloud services; extra agents, tools, or integrations; a policy language; running one agent across several processes; adaptive attackers; any feature the specification does not list. If something here seems necessary, ask first.
