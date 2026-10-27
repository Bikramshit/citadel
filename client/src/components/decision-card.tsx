"use client";

import { useState } from "react";
import { ChevronDown, Fingerprint, KeyRound, Microscope, Target } from "lucide-react";
import { fourChecks, type CallView, type CheckState } from "@/lib/derive";
import type { Decision } from "@/lib/types";
import { OutcomeBadge, Sources, Untrusted, VerdictBadge } from "./badges";
import { cx } from "./ui";

function Light({ icon: Icon, name, state }: { icon: typeof Fingerprint; name: string; state: CheckState | "trusted" | "untrusted" | undefined }) {
  const style =
    state === "allow"
      ? "text-good-ink bg-good/8 ring-good/25"
      : state === "deny"
        ? "text-critical-ink bg-critical/8 ring-critical/30"
        : state === "escalate"
          ? "text-warning-ink bg-warning/12 ring-warning/35"
          : state === "trusted"
            ? "text-accent-ink bg-accent-soft ring-accent/25"
            : state === "untrusted"
              ? "text-untrusted-ink bg-untrusted-soft ring-untrusted/30"
              : "text-muted bg-surface-2 ring-line";
  const label = state ?? "–";
  return (
    <span className={cx("flex min-w-0 flex-col gap-0.5 rounded-lg px-2 py-1.5 ring-1", style)} title={`${name}: ${label}`}>
      <span className="flex items-center gap-1 text-[10.5px] font-medium uppercase tracking-wider opacity-80">
        <Icon size={11} aria-hidden /> {name}
      </span>
      <span className="truncate text-[12px] font-semibold first-letter:uppercase">{label}</span>
    </span>
  );
}

function RuleRow({ d }: { d: Decision }) {
  return (
    <li className="flex items-start gap-2 py-1.5">
      <span className="w-12 shrink-0 font-mono text-[11px] font-semibold text-ink">{d.rule}</span>
      <VerdictBadge verdict={d.verdict} size="sm" />
      <span className="min-w-0 break-words text-[12px] text-ink-2">{d.reason}</span>
    </li>
  );
}

export function DecisionCard({ view, compact }: { view: CallView; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const e = view.decision;
  const checks = fourChecks(e);
  const ev = e.evidence ?? view.final?.evidence;
  const rules = (e.decisions ?? []).slice(0, -1);
  return (
    <article
      className={cx(
        "rounded-xl border bg-surface p-3.5 transition",
        view.goal ? "border-untrusted/50 shadow-[0_0_0_3px_var(--untrusted-soft)]" : "border-line",
      )}
    >
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="font-mono text-[11px] text-muted">
            {e.agent} · {e.op?.tool}.{e.op?.action}
          </p>
          <p className="mt-0.5 flex items-center gap-1.5 text-[14px] font-semibold text-ink">
            {view.goal && (
              <span title="The attack's goal names this exact change" className="text-untrusted">
                <Target size={14} aria-label="attack goal" />
              </span>
            )}
            <Untrusted text={e.target || "(no target)"} n={40} className="text-[13.5px] font-semibold text-ink" />
          </p>
        </div>
        <VerdictBadge verdict={view.final?.verdict} rule={view.final?.rule} />
      </header>
      <div className={cx("mt-3 grid gap-1.5", compact ? "grid-cols-2" : "grid-cols-2 sm:grid-cols-4")}>
        <Light
          icon={Fingerprint}
          name="Integrity"
          state={checks.integrity.trusted === undefined ? undefined : checks.integrity.trusted ? "trusted" : "untrusted"}
        />
        <Light icon={KeyRound} name="Authorization" state={checks.authorization.state} />
        <Light icon={Target} name="Intent" state={checks.intent.state} />
        <Light icon={Microscope} name="Evidence" state={checks.evidence.state} />
      </div>
      {view.final?.reason && !(ev && view.final.group === "E") && (
        <p className="mt-2.5 text-[12.5px] leading-snug text-ink-2">{view.final.reason}</p>
      )}
      {ev && (
        <p className="tabular mt-2.5 text-[12px] text-ink-2">
          Evidence: <span className="font-medium capitalize text-ink">{ev.verdict}</span> · {ev.observations} observations
          (k = {ev.k}) · {ev.flows} established flows
          {ev.success_logins ? ` · ${ev.success_logins} successful logins` : ""}
        </p>
      )}
      <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 border-t border-line pt-2.5">
        <OutcomeBadge state={view.attempt?.state} reconciled={view.attempt?.reconciled} />
        {view.approval && (
          <span className="text-[12px] text-ink-2">
            approval: <span className="font-medium text-ink">{view.approval.state}</span>
            {view.approval.approver ? ` by ${view.approval.approver}` : ""}
          </span>
        )}
        <button
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="inline-flex items-center gap-1 text-[12px] font-medium text-ink-2 hover:text-ink"
        >
          {rules.length} rules <ChevronDown size={13} className={cx("transition", open && "rotate-180")} />
        </button>
      </div>
      {open && (
        <div className="mt-2 space-y-2">
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted">Target sources</p>
            <div className="mt-1">
              <Sources sources={e.sources} max={8} />
            </div>
          </div>
          <ul className="divide-y divide-line">
            {rules.map((d, i) => (
              <RuleRow key={`${d.rule}-${i}`} d={d} />
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}
