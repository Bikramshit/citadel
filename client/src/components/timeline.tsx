"use client";

import { motion } from "motion/react";
import {
  Ban,
  CircleCheck,
  CircleDot,
  Flag,
  FlagOff,
  Gavel,
  Hash,
  Hourglass,
  Play,
  Send,
  Server,
  ShieldX,
  Signature,
  TriangleAlert,
  UserCheck,
} from "lucide-react";
import { finalDecision, fmtTime } from "@/lib/derive";
import type { CitadelEvent, EventKind } from "@/lib/types";
import { OutcomeBadge, Untrusted, VerdictBadge } from "./badges";
import { cx } from "./ui";

const ICON: Record<EventKind, typeof Play> = {
  run_start: Play,
  plan_rejected: ShieldX,
  value: Hash,
  call: CircleDot,
  decision: Gavel,
  approval_request: TriangleAlert,
  approval: UserCheck,
  attempt: Hourglass,
  handoff_send: Send,
  handoff_accept: Signature,
  handoff_reject: Ban,
  env_change: Server,
  run_abort: FlagOff,
  run_end: Flag,
};

function Summary({ e }: { e: CitadelEvent }) {
  switch (e.kind) {
    case "decision": {
      const f = finalDecision(e);
      return <VerdictBadge verdict={f?.verdict} rule={f?.rule} size="sm" />;
    }
    case "attempt":
      return <OutcomeBadge state={e.attempt?.state} reconciled={e.attempt?.reconciled} />;
    case "value":
      return (
        <span className="text-[12px] text-ink-2">
          <span className="font-mono">{e.value_type}</span> · {e.trusted ? "trusted" : "untrusted"}
        </span>
      );
    case "handoff_send":
    case "handoff_accept":
      return <span className="text-[12px] text-ink-2">{(e.handoff?.data ?? []).join(", ")}</span>;
    case "approval_request":
    case "approval":
      return (
        <span className="text-[12px] text-ink-2">
          {e.approval?.state}
          {e.approval?.approver ? ` by ${e.approval.approver}` : ""} · {e.approval?.rule}
        </span>
      );
    case "env_change":
      return (
        <span className="text-[12px] text-ink-2">
          {e.change?.tool}.{e.change?.action} {e.change?.target} · {e.change?.outcome}
        </span>
      );
    case "plan_rejected":
      return <span className="text-[12px] text-critical-ink">{(e.decisions ?? []).map((d) => d.rule).join(", ")}</span>;
    case "run_abort":
    case "handoff_reject":
      return <span className="font-mono text-[12px] text-critical-ink">{e.code}</span>;
    case "run_end":
      return <span className="text-[12px] text-ink-2">{e.detail}</span>;
    default:
      return null;
  }
}

export function Timeline({ events, animate }: { events: CitadelEvent[]; animate?: boolean }) {
  return (
    <ol className="relative divide-y divide-line">
      {events.map((e) => {
        const Icon = ICON[e.kind] ?? CircleCheck;
        const bad = e.kind === "run_abort" || e.kind === "handoff_reject" || e.kind === "plan_rejected";
        // Narrow screens stack the row: one meta line (time, agent, kind) over the content.
        const row = (
          <>
            <span className="tabular hidden w-20 shrink-0 pt-0.5 font-mono text-[11px] text-muted sm:block">{fmtTime(e.at)}</span>
            <span
              className={cx(
                "grid size-6 shrink-0 place-items-center rounded-md ring-1",
                bad ? "bg-critical/10 text-critical-ink ring-critical/25" : "bg-surface-2 text-ink-2 ring-line",
              )}
            >
              <Icon size={13} aria-hidden />
            </span>
            <span className="flex min-w-0 flex-1 flex-col gap-0.5 sm:flex-row sm:gap-3">
              <span className="flex shrink-0 flex-wrap items-baseline gap-x-2 sm:gap-x-3">
                <span className="tabular font-mono text-[11px] text-muted sm:hidden">{fmtTime(e.at)}</span>
                <span className="text-[12px] capitalize text-ink-2 sm:w-24 sm:pt-0.5">{e.agent}</span>
                <span className="font-mono text-[11.5px] text-ink sm:w-32 sm:pt-0.5">{e.kind}</span>
              </span>
              <span className="min-w-0 flex-1 sm:pt-0.5">
                {e.op && (
                  <span className="mr-2 font-mono text-[11.5px] text-ink-2">
                    {e.op.tool}.{e.op.action}
                  </span>
                )}
                {e.target && <Untrusted text={e.target} n={44} className="mr-2 text-ink" />}
                <Summary e={e} />
              </span>
            </span>
          </>
        );
        return animate ? (
          <motion.li
            key={`${e.agent}-${e.seq}`}
            initial={{ opacity: 0, x: -6, backgroundColor: "var(--accent-soft)" }}
            animate={{ opacity: 1, x: 0, backgroundColor: "rgba(0,0,0,0)" }}
            transition={{ duration: 0.6 }}
            className="flex items-start gap-3 px-4 py-2"
          >
            {row}
          </motion.li>
        ) : (
          <li key={`${e.agent}-${e.seq}`} className="flex items-start gap-3 px-4 py-2">
            {row}
          </li>
        );
      })}
    </ol>
  );
}
