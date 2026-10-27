// Pure functions that turn the runtime's event log into view models. They
// only regroup what the runtime recorded; they never compute a verdict.

import type { AttemptState, Change, CitadelEvent, Decision, Fixture, Mean, Rate, Verdict } from "./types";

export function finalDecision(e: CitadelEvent): Decision | undefined {
  const ds = e.decisions ?? [];
  return ds[ds.length - 1];
}

/** The rule results before the final verdict (the last element repeats one). */
export function ruleDecisions(e: CitadelEvent): Decision[] {
  const ds = e.decisions ?? [];
  return ds.slice(0, Math.max(0, ds.length - 1));
}

/** Trusted under the default trust table: analyst parameters, the note, planner literals, runtime values, and inventory reads. */
export function sourceTrusted(s: string): boolean {
  return (
    s === "user_note" ||
    s === "runtime" ||
    s === "tool:inventory.read" ||
    s.startsWith("task_param:") ||
    s.startsWith("planner_literal:")
  );
}

export function sourceKind(s: string): string {
  if (s.startsWith("peer:")) return "peer";
  if (s.startsWith("claimed:")) return "claimed";
  return s.split(":")[0] ?? s;
}

const severity: Record<Verdict, number> = { allow: 0, escalate: 1, deny: 2 };

function strictest(ds: Decision[]): Verdict | undefined {
  let worst: Verdict | undefined;
  for (const d of ds) if (worst === undefined || severity[d.verdict] > severity[worst]) worst = d.verdict;
  return worst;
}

export type CheckState = Verdict | "not reached" | "not applicable";

export interface CheckResult {
  state: CheckState;
  rules: Decision[];
}

export interface FourChecks {
  integrity: { trusted: boolean | undefined; sources: string[] };
  authorization: CheckResult;
  intent: CheckResult;
  evidence: CheckResult;
  routing: Decision[];
  other: Decision[];
}

/** Groups a decision's rule results into the specification's four checks. */
export function fourChecks(e: CitadelEvent): FourChecks {
  const rules = ruleDecisions(e);
  const by = (g: string) => rules.filter((d) => d.group === g);
  const check = (g: string, absent: CheckState): CheckResult => {
    const ds = by(g);
    return { state: strictest(ds) ?? absent, rules: ds };
  };
  const sources = e.sources ?? [];
  return {
    integrity: { trusted: sources.length ? sources.every(sourceTrusted) : undefined, sources },
    authorization: check("A", "not applicable"),
    intent: check("I", "not applicable"),
    evidence: check("E", "not reached"),
    routing: by("F"),
    other: rules.filter((d) => !["A", "I", "E", "F"].includes(d.group)),
  };
}

export interface CallView {
  key: string;
  decision: CitadelEvent;
  final: Decision | undefined;
  attempt?: { state: AttemptState; reconciled: boolean; detail: string };
  approval?: { state: string; approver?: string };
  goal: boolean; // the fixture's attack goal names this exact change
}

function opKey(agent: string, tool?: string, action?: string, target = "") {
  return `${agent}|${tool}.${action}|${target}`;
}

/**
 * Pairs each decision with the outcome of the attempt it admitted. Attempts
 * follow their decision in the log; an A5 duplicate denial never inherits an
 * earlier call's outcome because only allowed decisions take attempts.
 */
export function callViews(events: CitadelEvent[], fixture?: Fixture): CallView[] {
  const goal = new Set((fixture?.goal_any_of ?? []).map((c) => `${c.tool}.${c.action}|${c.target}`));
  const views: CallView[] = [];
  const open = new Map<string, CallView>();
  const openByOp = new Map<string, CallView>();
  const approvals = new Map<string, { state: string; approver?: string }>();
  for (const e of [...events].sort((a, b) => a.seq - b.seq)) {
    if (e.kind === "approval" && e.op && e.approval) {
      approvals.set(opKey(e.agent, e.op.tool, e.op.action, e.target), { state: e.approval.state, approver: e.approval.approver });
    }
    if (e.kind === "decision" && e.op && e.op.tool !== "handoff") {
      const k = opKey(e.agent, e.op.tool, e.op.action, e.target);
      const v: CallView = {
        key: `${e.seq}`,
        decision: e,
        final: finalDecision(e),
        approval: approvals.get(k),
        goal: goal.has(`${e.op.tool}.${e.op.action}|${e.target ?? ""}`),
      };
      views.push(v);
      if (v.final?.verdict === "allow") {
        open.set(k, v);
        openByOp.set(opKey(e.agent, e.op.tool, e.op.action), v);
      }
    }
    if (e.kind === "attempt" && e.attempt) {
      const a = e.attempt;
      const v = a.target
        ? open.get(opKey(e.agent, a.op.tool, a.op.action, a.target))
        : openByOp.get(opKey(e.agent, a.op.tool, a.op.action));
      if (v) v.attempt = { state: a.state, reconciled: a.reconciled, detail: a.detail };
    }
  }
  return views;
}

export interface RunStory {
  start: Map<string, CitadelEvent>;
  end: Map<string, CitadelEvent>;
  aborts: CitadelEvent[];
  rejectedPlans: CitadelEvent[];
  values: CitadelEvent[];
  handoffSend?: CitadelEvent;
  handoffAccept?: CitadelEvent;
  handoffRejects: CitadelEvent[];
  handoffDecision?: CitadelEvent;
  calls: CallView[];
  approvals: CitadelEvent[];
  changes: CitadelEvent[];
  runId?: string;
}

export function story(events: CitadelEvent[], fixture?: Fixture): RunStory {
  const s: RunStory = {
    start: new Map(),
    end: new Map(),
    aborts: [],
    rejectedPlans: [],
    values: [],
    handoffRejects: [],
    calls: callViews(events, fixture),
    approvals: [],
    changes: [],
  };
  for (const e of events) {
    if (e.run && !s.runId && e.run.startsWith("run_")) s.runId = e.run;
    switch (e.kind) {
      case "run_start":
        s.start.set(e.agent, e);
        break;
      case "run_end":
        s.end.set(e.agent, e);
        break;
      case "run_abort":
        s.aborts.push(e);
        break;
      case "plan_rejected":
        s.rejectedPlans.push(e);
        break;
      case "value":
        s.values.push(e);
        break;
      case "handoff_send":
        s.handoffSend = e;
        break;
      case "handoff_accept":
        s.handoffAccept = e;
        break;
      case "handoff_reject":
        s.handoffRejects.push(e);
        break;
      case "decision":
        if (e.op?.tool === "handoff") s.handoffDecision = e;
        break;
      case "approval_request":
      case "approval":
        s.approvals.push(e);
        break;
      case "env_change":
        s.changes.push(e);
        break;
    }
  }
  return s;
}

export const changeKey = (c: Change) => `${c.tool}.${c.action} ${c.target}`;

export function ratePct(r: Rate): number {
  return r.n === 0 ? 0 : (100 * r.k) / r.n;
}

export function fmtRate(r: Rate): string {
  if (r.n === 0) return "n = 0";
  return `${r.k}/${r.n}`;
}

export function fmtCI(r: Rate): string {
  if (r.n === 0) return "";
  return `[${Math.round(100 * r.lo)}, ${Math.round(100 * r.hi)}]`;
}

export function fmtMean(m: Mean, digits = 2): string {
  return m.n === 0 ? "–" : (m.sum / m.n).toFixed(digits);
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(11, 23);
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

export function shortHash(h: string | undefined, n = 7): string {
  return h ? h.slice(0, n) : "–";
}

/** Truncates attacker-controlled text for display; the full text goes in a title. */
export function clip(s: string, n = 96): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/** Shows control and bidirectional-override characters instead of rendering them. */
export function visible(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f\u202A-\u202E\u2066-\u2069]/g, (c) =>
    c === "\n" ? "⏎ " : `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}
