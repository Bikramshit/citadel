# Open questions

Places where the specification is ambiguous, contradictory, or silent. Each entry gives the options and the interim choice the code makes. Security-relevant entries are marked **[security]**. Every interim choice is the stricter option, so none of them weakens a never-cut property. Each still needs the project owner's answer, and none is final until then.

## Q1. Invariant 1 versus side effects the evaluation is designed to measure [security]

Invariant 1 says "no state change outside the fixture's allowed set, unless it came from an approved Escalate", and the invariant checker must fail the test or mark the run invalid. But some state changes outside the allowed set are expected and must be counted, not dropped:

- C0 has no runtime checks, and C1-instr launders attacker names into analyst parameters on purpose.
- E-T11 and B12 block an unlisted shared address. The spec calls this an expected, documented limitation and counts it as an unauthorized side effect.

If these runs counted as invalid, the attack-success and side-effect metrics would lose exactly the runs they exist to measure, contradicting "no run is dropped".

**Options.** (a) Invariant 1 invalidates every configuration. (b) Invariant 1 is enforced in deterministic tests and in C1-data and C2 runs. A fixture may declare effects as `known_limitation`; the checker tolerates those, while the metrics still count them as unauthorized side effects. In C0 and C1-instr runs, invariant 1 is measured, not enforced. (c) Invariant 1 is never enforced in harness runs.

**Interim: (b).** Invariants 2 to 13 are runtime properties and are enforced in every Citadel configuration. C0 has no runtime, so only invariant 9 (the tool's own apply log) is checked there.

## Q2. P5 "replay of an accepted envelope → ERR_REPLAY" versus receiver step 7 [security]

Step 7 says that identical bytes already decided "get the recorded result and import nothing", and ERR_REPLAY means "the same ID with different bytes". P5 expects ERR_REPLAY for a replay of an accepted envelope.

**Interim:** an identical retransmission of an accepted envelope is answered with code ERR_REPLAY plus the recorded result ("accepted; nothing imported"). A retransmission of a rejected envelope gets its recorded reject code. Both P5 and the H4 positive test hold, and nothing is imported in either case.

## Q3. Window in the capability scope [security]

The catalog scopes `logs.read` with `{hosts: $hosts, window: $window}`, but the pseudocode's `Scope` struct has no window field.

**Interim:** `Scope` gains a `Window` field. `Meet` takes the minimum non-zero value, `Within` requires a window no longer than the granted one, and A2 denies a `logs.read` whose window exceeds the scope.

## Q4. Which rule a test names when A2 and A3 both deny

10.1.2.3 is outside the public-external scope (A2) and is also an internal address (A3). T-A3 expects "Deny (A2)" for it and "Deny (A3)" for 10.0.0.53, which also fails both checks.

**Interim:** every applicable rule is recorded, and tests assert that the named rule is among the denying decisions and that the final verdict is Deny. The reported rule follows a fixed precedence: A0, A1, A3, A2, I1, I2, I3, C1, E1, E2, A4, A5, F3, then the routes, then D0.

## Q5. Tuning rule for thresholds other than k

The fixed tuning rule is stated only for k. F3's soft budget, the iteration budget, the flow requirement, and the call limits are also "chosen only on development fixtures", with no rule given.

**Interim:** `citadel tune` applies the stated rule to k. The other thresholds keep the specification's starting defaults (soft budget 20, iteration budget 64, flow requirement 1, block limit 50, disable limit 5, run limit 60). Tune checks them on the development fixtures and fails if a benign development task cannot complete within them. The results and the rule are written to `thresholds.yaml`.

## Q6. Evidence for protected targets

E-T5 expects "Deny (A3); evidence not reached", while Decide "evaluates every applicable rule".

**Interim:** E1 and E2 do not apply to a target that A3 removes, so no evidence decision is recorded for it. This matches "after authorization has already removed protected and internal addresses" in the evidence section.

## Q7. M1 element 4 after evidence rules exist

M1 expects 192.0.2.44 to be denied by D0, "because evidence rules arrive on Day 7".

**Interim:** the policy engine has an evidence mode. `TestM1` and `citadel demo m1` run with evidence rules off, exactly as the milestone specifies, so the untrusted target has no route and D0 denies it. Every other test and every harness run uses E1 and E2. Turning evidence off only removes routes, so it can only add denials.

## Q8. The C0 baseline's path to the tools [security]

"Only the interpreter's executor can reach a tool", but C0 is by definition ordinary tool calling with no Citadel runtime.

**Interim:** the mock tools' `Apply` accepts only an attempt issued by `runstate.Admit`; the attempt's issuer field is unexported. C0 uses a separate, documented method, `tools.Env.BaselineCall`. A test checks the import graph: outside tests, only `internal/interp` calls `Apply` and only the harness's C0 driver calls `BaselineCall`.

## Q9. Account evidence: Absent versus Insufficient

E2 defines Corroborated (a trusted successful login from a corroborated IP) and Absent (deny), but does not say what a successful login from an uncorroborated IP is.

**Interim:** Absent means no trusted successful login for the account in scope. Insufficient means logins exist, but none came from a corroborated IP. Both Insufficient and Corroborated escalate, as specified.

## Q10. Fields in the deduplication digest

"A digest of the trusted fields with the timestamp truncated to the second" does not list the fields.

**Interim:** timestamp (to the second), host, client IP, status, auth result, auth principal. Event ID, sensor, and pipeline are left out, so a record delivered twice through different pipelines also collapses. This can undercount observations; it cannot overcount them.

## Q11. The 256-byte string limit and the embedded context

"Strings at most 256 bytes" cannot hold the embedded authorization context token, whose base64 payload is longer.

**Interim:** the generic decoder bounds every string at 16 KiB. After decoding, every payload string except `authctx.payload` and `authctx.sig` must be at most 256 bytes. The embedded context is then verified as its own signed token, with its own size limit.

## Q12. `logs.read` with several hosts

The task allows 1 to 3 hosts, but `logs.read(host, window)` takes one host. The plan language has no way to collect values out of a loop, and the run allows only one handoff.

**Interim:** the `host` argument accepts a hostname or a `list<hostname>`. A2 checks every element against the scope.

## Q13. Read-only calls and Admit

**Interim:** read-only calls also go through `Admit`, which re-checks A0 and records an attempt, so invariant 8 ("every tool call has an attempt") holds for reads. A4, A5, and F3 apply only to state-changing calls, as the rule table says.

## Q14. A later statement that refers to a denied call's result

"Deny skips that call and continues", but a later statement may refer to the variable the denied call would have bound.

**Interim:** that reference aborts the run with ERR_UNDEFINED_VALUE. No value is invented.

## Q15. The text report in C1-instr and C1-data

The catalog's data schema has only `ips` and `accounts`.

**Interim:** the C1 handoff adapters carry one data item, `report` of type `text` (at most 8 KiB), only when the receiver runs in that comparison mode. C2 receivers refuse it with ERR_TYPE.

## Q16. Requested operations

`Payload.RequestedOps` is `[]authz.Op` (tool and action, no scope), but `CheckSend` compares capabilities.

**Interim:** requested operations narrow by tool and action only. H2 and H5 check that each one appears in the receiver's run grant ∩ task operations. The receiver keeps the granted scope for the operations that remain.

## Q17. Anchor of the task window

**Interim:** the window ends at the context's issue time. Evidence uses [issued − window, issued]; `logs.read` uses the same window, read from the environment's clock, which harness and fixture runs set to the context's issue time.
