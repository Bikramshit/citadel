"use client";

import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, Ban, CircleCheck, FileWarning, KeyRound, Send, Server, Signature } from "lucide-react";
import type { RunStory } from "@/lib/derive";
import type { CitadelEvent } from "@/lib/types";
import { DecisionCard } from "./decision-card";
import { Sources, TrustDot, Untrusted, VerdictBadge } from "./badges";
import { cx } from "./ui";

function Lane({ title, icon: Icon, children, tone }: { title: string; icon: typeof Send; children: React.ReactNode; tone?: "accent" }) {
  return (
    <div className="relative flex min-w-0 flex-col [&>div>*]:min-w-0">
      <div
        className={cx(
          "mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.14em]",
          tone === "accent" ? "text-accent-ink" : "text-muted",
        )}
      >
        <Icon size={13} /> {title}
      </div>
      <div className="flex flex-col gap-2.5">{children}</div>
    </div>
  );
}

function Mini({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.25 }}
      className={cx("rounded-xl border border-line bg-surface p-3 text-[12.5px]", className)}
    >
      {children}
    </motion.div>
  );
}

function caps(detail?: string): string[] {
  return (detail ?? "").split(" ").filter(Boolean);
}

function ValueCard({ e }: { e: CitadelEvent }) {
  return (
    <Mini>
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[11px] text-muted">{e.value_id}</span>
        <TrustDot trusted={e.trusted} />
      </div>
      <p className="mt-1 font-mono text-[12px] font-medium text-ink">{e.value_type}</p>
      <div className="mt-1.5">
        <Sources sources={e.sources} max={3} />
      </div>
    </Mini>
  );
}

/** The run as five swimlanes: authority, Investigator, handoff, Responder, environment. */
export function StoryLanes({ s }: { s: RunStory }) {
  const inv = s.calls.filter((c) => c.decision.agent === "investigator");
  const resp = s.calls.filter((c) => c.decision.agent === "responder");
  const invValues = s.values.filter((v) => v.agent === "investigator");
  const respValues = s.values.filter((v) => v.agent === "responder");
  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_1.15fr_0.9fr_1.6fr_0.9fr]">
      <Lane title="Authority" icon={KeyRound} tone="accent">
        <AnimatePresence>
          {[...s.start.values()].map((e) => (
            <Mini key={e.seq} className="border-accent/30 bg-accent-soft/50">
              <p className="font-medium capitalize text-ink">{e.agent}</p>
              <p className="mt-0.5 text-[11.5px] text-ink-2">effective capabilities</p>
              <ul className="mt-1.5 space-y-1">
                {caps(e.detail).map((c) => (
                  <li key={c} className="break-all font-mono text-[11px] text-ink">
                    {c}
                  </li>
                ))}
              </ul>
            </Mini>
          ))}
        </AnimatePresence>
      </Lane>
      <Lane title="Investigator" icon={FileWarning}>
        <AnimatePresence>
          {s.rejectedPlans
            .filter((e) => e.agent === "investigator")
            .map((e) => (
              <Mini key={e.seq} className="border-critical/30">
                <p className="flex items-center gap-1.5 font-medium text-critical-ink">
                  <Ban size={13} /> Plan rejected before it ran
                </p>
                <ul className="mt-1.5 space-y-1">
                  {(e.decisions ?? []).map((d, i) => (
                    <li key={i} className="text-[11.5px] text-ink-2">
                      <span className="font-mono font-semibold text-ink">{d.rule}</span> {d.reason}
                    </li>
                  ))}
                </ul>
              </Mini>
            ))}
          {inv.map((c) => (
            <Mini key={c.key}>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[11.5px] text-ink">
                  {c.decision.op?.tool}.{c.decision.op?.action}
                </span>
                <VerdictBadge verdict={c.final?.verdict} rule={c.final?.rule} size="sm" />
              </div>
              <Untrusted text={c.decision.target ?? ""} n={48} className="mt-1 block text-ink-2" />
            </Mini>
          ))}
          {invValues.map((e) => (
            <ValueCard key={e.seq} e={e} />
          ))}
        </AnimatePresence>
      </Lane>
      <Lane title="Signed handoff" icon={Signature} tone="accent">
        <AnimatePresence>
          {s.handoffSend && (
            <Mini key="send" className="border-accent/30">
              <p className="flex items-center gap-1.5 font-medium text-ink">
                <Send size={13} className="text-accent" /> Sent · {s.handoffSend.handoff?.bytes} bytes
              </p>
              <p className="mt-1 text-[11.5px] text-ink-2">Ed25519 over the exact payload bytes</p>
              <ul className="mt-1.5 flex flex-wrap gap-1">
                {(s.handoffSend.handoff?.data ?? []).map((d) => (
                  <li key={d} className="rounded-md bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-2 ring-1 ring-line">
                    {d}
                  </li>
                ))}
              </ul>
            </Mini>
          )}
          {s.handoffAccept && (
            <Mini key="accept" className="border-good/30">
              <p className="flex items-center gap-1.5 font-medium text-good-ink">
                <CircleCheck size={13} /> Verified and accepted once
              </p>
              <p className="mt-1 text-[11.5px] text-ink-2">every value imported untrusted</p>
            </Mini>
          )}
          {s.handoffRejects.map((e) => (
            <Mini key={e.seq} className="border-critical/30">
              <p className="flex items-center gap-1.5 font-medium text-critical-ink">
                <Ban size={13} /> Rejected · <span className="font-mono">{e.code}</span>
              </p>
              <p className="mt-1 text-[11.5px] text-ink-2">nothing imported</p>
            </Mini>
          ))}
          {!s.handoffSend && !s.handoffRejects.length && <p className="text-[12px] text-muted">No handoff in this run.</p>}
        </AnimatePresence>
      </Lane>
      <Lane title="Responder decisions" icon={ArrowRight}>
        <AnimatePresence>
          {respValues.map((e) => (
            <ValueCard key={e.seq} e={e} />
          ))}
          {s.rejectedPlans
            .filter((e) => e.agent === "responder")
            .map((e) => (
              <Mini key={e.seq} className="border-critical/30">
                <p className="flex items-center gap-1.5 font-medium text-critical-ink">
                  <Ban size={13} /> Plan rejected before it ran
                </p>
                <ul className="mt-1.5 space-y-1">
                  {(e.decisions ?? []).map((d, i) => (
                    <li key={i} className="text-[11.5px] text-ink-2">
                      <span className="font-mono font-semibold text-ink">{d.rule}</span> {d.reason}
                    </li>
                  ))}
                </ul>
              </Mini>
            ))}
          {resp.map((c) => (
            <motion.div key={c.key} layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
              <DecisionCard view={c} compact />
            </motion.div>
          ))}
        </AnimatePresence>
      </Lane>
      <Lane title="Environment" icon={Server}>
        <AnimatePresence>
          {s.changes.map((e) => (
            <Mini key={e.seq} className={e.change?.outcome === "executed" ? "border-good/30" : "border-warning/40"}>
              <p className="font-mono text-[11.5px] text-ink">
                {e.change?.tool}.{e.change?.action}
              </p>
              <p className="mt-0.5 font-mono text-[13px] font-semibold text-ink">{e.change?.target}</p>
              <p className="mt-1 text-[11.5px] text-ink-2">{e.change?.outcome}</p>
            </Mini>
          ))}
          {s.aborts.map((e) => (
            <Mini key={e.seq} className="border-critical/30">
              <p className="font-medium text-critical-ink">
                <span className="capitalize">{e.agent}</span> aborted · <span className="font-mono">{e.code}</span>
              </p>
              <p className="mt-1 break-words text-[11.5px] text-ink-2">{e.detail}</p>
            </Mini>
          ))}
          {!s.changes.length && <p className="text-[12px] text-muted">No environment changes.</p>}
        </AnimatePresence>
      </Lane>
    </div>
  );
}
