// Types mirroring the JSON that `citadel dash` serves. Field names follow
// the Go structs' JSON tags exactly; nothing here is invented client-side.

export type Verdict = "allow" | "escalate" | "deny";
export type AttemptState = "attempted" | "succeeded" | "failed" | "uncertain";
export type ConfigName = "C0" | "C1-instr" | "C1-data" | "C2";

export const CONFIGS: ConfigName[] = ["C0", "C1-instr", "C1-data", "C2"];

export interface Op {
  tool: string;
  action: string;
}

export interface EvidenceCounts {
  verdict: "absent" | "insufficient" | "corroborated" | "conflict";
  observations: number;
  flows: number;
  success_logins: number;
  sensors: string[] | null;
  conflict?: string;
  k: number;
  min_flows: number;
}

export interface Decision {
  verdict: Verdict;
  rule: string;
  group: string;
  reason: string;
  evidence?: EvidenceCounts | null;
}

export interface Attempt {
  key: string;
  run_id: string;
  op: Op;
  target: string;
  sensitive: boolean;
  state: AttemptState;
  reconciled: boolean;
  started: string;
  settled: string;
  detail: string;
}

export interface ApprovalInfo {
  key: string;
  state: string;
  approver?: string;
  expires_at: string;
  args?: Record<string, string> | null;
  sources?: Record<string, string[]> | null;
  rule?: string;
  reason?: string;
}

export interface EnvChange {
  tool: string;
  action: string;
  target: string;
  outcome: string;
}

export interface HandoffInfo {
  id: string;
  from: string;
  to: string;
  task: string;
  data?: string[] | null;
  bytes: number;
  status?: string;
}

export type EventKind =
  | "run_start"
  | "plan_rejected"
  | "value"
  | "call"
  | "decision"
  | "approval_request"
  | "approval"
  | "attempt"
  | "handoff_send"
  | "handoff_accept"
  | "handoff_reject"
  | "env_change"
  | "run_abort"
  | "run_end";

export interface CitadelEvent {
  seq: number;
  at: string;
  run: string;
  config: string;
  agent: string;
  kind: EventKind;
  value_id?: string;
  value_type?: string;
  deps?: string[] | null;
  op?: Op | null;
  target?: string;
  sources?: string[] | null;
  trusted: boolean;
  pc_trusted: boolean;
  decisions?: Decision[] | null;
  evidence?: EvidenceCounts | null;
  attempt?: Attempt | null;
  approval?: ApprovalInfo | null;
  change?: EnvChange | null;
  code?: string;
  detail?: string;
  handoff?: HandoffInfo | null;
  extra?: Record<string, number> | null;
}

export interface Change {
  tool: string;
  action: string;
  target: string;
}

export interface RunSummary {
  id: string;
  fixture: string;
  kind: "attack" | "benign" | "dev";
  goal: string;
  style: string;
  config: ConfigName;
  evidence: string;
  trial: number;
  impl: string;
  attack_success: boolean;
  unauthorized: number;
  completed: boolean;
  escalations: number;
  uncertain: number;
  failed: boolean;
  valid: boolean;
  latency_ms: number;
  diff: Change[] | null;
}

export interface Rate {
  k: number;
  n: number;
  lo: number;
  hi: number;
}

export interface Mean {
  sum: number;
  n: number;
}

export interface Row {
  config: ConfigName;
  attack_success: Rate;
  unauthorized: Mean;
  runs_with_unauthorized: Rate;
  completion_benign: Rate;
  completion_attack: Rate;
  false_blocks: Rate;
  escalations_benign: Mean;
  attacker_escalations: Mean;
  uncertain: Mean;
  laundered: Rate;
  p50_ms: number;
  p95_ms: number;
  latency_n: number;
  failed: Rate;
}

export interface ModelInfo {
  role: string;
  model: string;
  provider: string;
  endpoint?: string;
  settings?: string;
}

export interface Meta {
  started: string;
  finished: string;
  git_commit: string;
  git_dirty: boolean;
  thresholds_commit: string;
  thresholds: { k: number; min_flows: number; soft_untrusted_pc: number; iteration_budget: number };
  impl: string;
  models: ModelInfo[] | null;
  prompt_hashes: string[] | null;
  configs: string[] | null;
  evidence: string;
  trials: number;
  fixtures_dir: string;
  fixtures: { id: string; sha256: string }[] | null;
  go_version: string;
  runs: number;
  crashes: number;
  invalid: number;
}

export interface RunDir {
  dir: string;
  meta: Meta;
  tables_md: string;
  summary: { impl: string; rows: Row[] }[] | null;
  runs: RunSummary[] | null;
}

export interface Fixture {
  id: string;
  kind: "attack" | "benign" | "dev";
  goal: string;
  style: string;
  description: string;
  goal_any_of: Change[] | null;
  goal_none_of: Change[] | null;
  required: Change[] | null;
}

export interface ApprovalRequest {
  RunID: string;
  Agent: string;
  Key: string;
  Op: Op;
  Target: string;
  Args: Record<string, string> | null;
  Sources: Record<string, string[]> | null;
  Evidence: EvidenceCounts | null;
  Decision: Decision;
  /** RequestedAt and ExpiresAt are on the run's clock. */
  RequestedAt: string;
  ExpiresAt: string;
}

export interface Approvals {
  principal: string;
  token: string;
  pending: ApprovalRequest[] | null;
}

export interface M1Check {
  element: number;
  name: string;
  ok: boolean;
  detail: string;
}

export interface M1Report {
  checks: {
    run_id: string;
    processes: number;
    responder_url: string;
    checks: M1Check[];
    violations: { invariant: number; detail: string }[] | null;
    diff: Change[] | null;
  };
  trace: string;
}
