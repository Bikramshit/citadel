# Citadel threat model

Frozen on Day 1 from [ARCHITECTURE.md](ARCHITECTURE.md), section "Threat model". If this file and the specification disagree, the specification wins and this file is corrected.

The attacker writes text into logs, tampers with traffic between agents, and may control one authorized agent runtime. The orchestrator, policy code, key registry, inventory, and the trusted fields of the log store are assumed correct. The guarantees below hold only under these assumptions. Code enforces them and tests check them; nothing here is proven.

## Trusted computing base (assumptions)

1. The orchestrator, interpreter, policy engine, verifier, and tool adapters behave as specified. A bug in any of them breaks the guarantees.
2. The key registry is provisioned out of band, and private keys are not stolen, except in the signer-compromise case (Peer) below.
3. The inventory is a correct system of record for protected assets, protected accounts, internal ranges, the account directory, known partner and shared addresses, and the sensor registry that says which log sensors and pipelines are distinct.
4. In the log store, `client_ip`, `ts`, `host`, `status`, and `auth_result` are written by our server and auth service, not by the client. Flow records are written by network equipment. This is an assumption about the deployment; the mock store enforces it by construction (`internal/evidence`, `internal/tools`).
5. The analyst is honest and picks the task deliberately.

## Assets

Firewall rules (integrity and availability of traffic), account availability, the integrity of the containment outcome, and analyst attention (approval requests are a cost).

## Adversaries and faults

| ID | Capability | In scope |
| --- | --- | --- |
| Ext | Writes arbitrary text into request fields that reach logs: path, User-Agent, `X-Forwarded-For`, attempted usernames. Controls the IP addresses it sends from and can generate real traffic from them. Knows the design and tool names. | Yes |
| Net | Reads, modifies, replays, reorders, duplicates, and forges messages between agent processes, including many concurrent copies. | Yes |
| Peer | Controls the Investigator runtime and its signing key, so it can send any well-formed, validly signed envelope. | Yes, for receiver-side checks only |
| Fault | A planner that sees only trusted input still writes a wrong plan: wrong tool, more privileged action, out-of-scope or invented target. | Yes, not adversarial |
| Race | Concurrent or repeated approvals, lost tool responses, and agent restarts mid-run. | Yes, not adversarial |

## Trust assignments

| Component | Trust | Notes |
| --- | --- | --- |
| Analyst's structured task choice | Trusted, and the only source of authority | Typed parameters, validated by the orchestrator |
| Analyst's free-text note | Trusted integrity, no authority | Planner context only |
| Orchestrator, task catalog, authorization context | Trusted | No model runs in the orchestrator |
| Planner model | Not adversarial, fallible | Sees only trusted input; every output is checked |
| Processor model | Untrusted output | Reads attacker text |
| Log record fields written by the client | Untrusted | Path, User-Agent, forwarded-for, attempted usernames |
| Log record fields written by our infrastructure, flow records | Trusted for evidence | See assumptions |
| Values arriving from another agent | Untrusted, always | Even with a valid signature |
| Network between agents | Untrusted | |

## Attacker goals

| ID | Goal | Primary check expected to stop it |
| --- | --- | --- |
| G1 | Allowlist the attacker's IP | Authorization: no task grants `firewall.allow` |
| G2a | Disable a protected admin account | Authorization: protected resource |
| G2b | Disable an ordinary employee account | Evidence: no trusted successful login, unless laundering turns the name into an analyst parameter |
| G3a | Block a protected internal address | Authorization: protected or internal resource |
| G3b | Block an innocent external address (fabricated indicator) | Evidence: no trusted observation, unless laundered |
| G4 | Suppress containment of the attacker's own IP | Partly: the typed handoff removes the instruction channel; the processor can still omit values (residual) |
| G5 | Flood the block list with fabricated IPs | Evidence, then soft and hard budgets |
| G6 | Forge, tamper with, or replay a handoff | Signature, registry, freshness, replay cache |
| G7 | Widen privileges through a handoff | Delegation rules H2 and H5 |
| G8 | Planner over-reach (fault, not attack) | Authorization and intent rules, static plan check |

## Guarantees, conditional on the assumptions

1. No state-changing call runs unless its exact tool and action are in the agent's effective capabilities, its target is inside the granted scope and not protected, and the run's budgets allow it, whatever any model outputs.
2. Labels only grow. No serialization, model output, signature, or approval turns an untrusted value into a trusted one.
3. A planner cannot name a target. Targets come from the analyst's typed parameters or from untrusted data that must pass evidence rules or approval.
4. A handoff cannot give the receiver any permission absent from the signed authorization context, and the sender never needs the receiver's permissions.
5. An invalid envelope is rejected whole, with nothing imported.
6. An approval authorizes one exact call once, and never overrides a Deny.
7. Within one agent process, budgets, the handoff allowance, and approvals are spent atomically: concurrent or repeated requests cannot exceed them, and a valid signature is never taken as proof that any remains.
8. Each state-changing call is applied at most once per idempotency key, and no report labels an unknown outcome as denied or failed.
9. After an agent restart, no context issued before the restart is accepted, so no run resumes with lost counters.

## Not guaranteed, or out of scope

- Correctness of an indicator beyond the configured evidence conditions. Corroboration does not establish malicious intent; traffic from an unlisted shared address (a partner's proxy, a carrier NAT) can produce real observations and get blocked (E-T11, B12).
- Omission. The processor can drop a real indicator because of injected text, and nothing detects it (G4 residual).
- Availability. An attacker who triggers a processor or tool error aborts the run, an attacker can generate approval requests, and a restart ends in-flight runs.
- Running one agent as several processes. Run state is in memory; a transactional store would be needed and is future work.
- Real tools without idempotency keys. The mock tools provide them; reconciling real systems by state queries is future work.
- A compromised orchestrator, policy code, or registry; stolen orchestrator or Responder keys.
- A Peer compromise defeats the Investigator's own processing, but not the Responder's checks.
- Side channels, deception of the human approver beyond showing evidence, and cost attacks on model providers.

## Where each guarantee is enforced

| Guarantee | Enforced in | Checked by |
| --- | --- | --- |
| 1 | `policy.Engine.Decide` (A1, A2, A3, I1), `runstate.RunState.Admit` (A0, A4, A5, F3), `plan.StaticCheck` | Rule tests, T-A1 to T-A7, CT3, invariants 2, 7, 8 |
| 2 | `label` (unexported fields, Join only), `value.Value.Joined`, handoff import (`Peer` + `Claimed`), processor decoding (`QLLM`) | L1, L2, L5, L6, P4, invariant 3 |
| 3 | I2 in `policy` and in `plan.StaticCheck` | T-A4, I2 tests |
| 4 | `authz.ReceiverEffective`, `handoff.CheckSend` (H1 to H3), receiver steps 8 and 9 | D1 to D5, T-A6, P12, invariant 4 |
| 5 | `handoff.Receiver` steps 1 to 11, staged import, `runstate.CommitHandoff` | P1 to P18, H6 tests, invariant 5 |
| 6 | `runstate.Admit` consumption, `policy.KeyFor` binding | L7, CT4, invariant 6 |
| 7 | One mutex per run in `runstate` | CT1 to CT6, invariant 12 |
| 8 | Idempotency keys, A5, `interp` lookup reconciliation, attempt events | X1 to X3, invariants 8 to 11 |
| 9 | Start-time watermark in `runstate.Runs.Activate` and receiver step 6 | P16, CT7, invariant 13 |
