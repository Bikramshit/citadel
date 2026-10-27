"use client";

import Link from "next/link";
import { motion } from "motion/react";
import {
  ArrowRight,
  CircleCheck,
  CircleX,
  Fingerprint,
  KeyRound,
  Microscope,
  Milestone,
  Radio,
  Scale,
  ShieldHalf,
  Target,
} from "lucide-react";
import { fetchM1, fetchRuns, useLoad } from "@/lib/api";
import { fmtCI, ratePct } from "@/lib/derive";
import { implOf, mainDir, rowsOf } from "@/lib/select";
import { ArchitectureFlow } from "../flow";
import { ConfigChip, ImplBanner, configDescription } from "../badges";
import { Card, CardHeader, ErrorNote, Skeleton, cx } from "../ui";

const CHECKS = [
  {
    name: "Integrity",
    icon: Fingerprint,
    q: "Did attacker-influenced data shape this value?",
    by: "Provenance labels set by the runtime. They only grow; nothing removes a source.",
  },
  {
    name: "Authorization",
    icon: KeyRound,
    q: "May this agent do this action to this resource in this run?",
    by: "The orchestrator's signed context, static capabilities, and the inventory.",
  },
  {
    name: "Intent",
    icon: Target,
    q: "Did the analyst's task ask for this action, and did the target come from the analyst?",
    by: "The task catalog and the analyst's typed parameters. A planner cannot name a target.",
  },
  {
    name: "Evidence",
    icon: Microscope,
    q: "Did trusted logs and an independent flow sensor corroborate this indicator?",
    by: "Trusted log fields and independent sensors. Text an attacker wrote counts for nothing.",
  },
];

const fade = {
  initial: { opacity: 0, y: 12 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-60px" },
  transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as const },
};

function Headline() {
  const { data, error } = useLoad((s) => fetchRuns(s));
  if (error) return <ErrorNote error={error} />;
  const dir = data ? mainDir(data) : undefined;
  const rows = rowsOf(dir);
  return (
    <Card>
      <CardHeader
        icon={<Scale size={16} />}
        title="Measured, not claimed"
        subtitle="How often each attack goal held after the run, read from the environment diff, per handoff configuration."
        actions={<ImplBanner impl={implOf(dir)} />}
      />
      <div className="grid grid-cols-1 gap-px overflow-hidden rounded-b-2xl bg-line sm:grid-cols-2 xl:grid-cols-4">
        {!data &&
          [0, 1, 2, 3].map((i) => (
            <div key={i} className="bg-surface p-5">
              <Skeleton className="h-4 w-16" />
              <Skeleton className="mt-4 h-10 w-24" />
              <Skeleton className="mt-3 h-3 w-40" />
            </div>
          ))}
        {data && rows.length === 0 && (
          <div className="bg-surface p-6 text-[13px] text-ink-2 sm:col-span-2 xl:col-span-4">
            No harness runs yet. Run <code className="rounded bg-surface-2 px-1 font-mono">make eval IMPL=scripted TRIALS=1</code>.
          </div>
        )}
        {rows.map((r) => {
          const pct = ratePct(r.attack_success);
          const c2 = r.config === "C2";
          return (
            <div key={r.config} className={cx("relative bg-surface p-5", c2 && "bg-gradient-to-b from-accent-soft to-surface")}>
              <div className="flex items-center justify-between">
                <ConfigChip config={r.config} />
                <span className="tabular text-[11px] text-muted">n = {r.attack_success.n}</span>
              </div>
              <p className="mt-4 text-[13px] text-ink-2">Attack success</p>
              <p className={cx("text-[40px] font-semibold leading-none tracking-tight", c2 ? "text-ink" : "text-ink")}>
                {Math.round(pct)}
                <span className="text-[22px] text-ink-2">%</span>
              </p>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface-3">
                <motion.div
                  className="h-full rounded-full"
                  style={{ background: c2 ? "var(--accent)" : "var(--mark-muted)" }}
                  initial={{ width: 0 }}
                  animate={{ width: `${pct}%` }}
                  transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
                />
              </div>
              <p className="mt-3 text-[12px] leading-snug text-ink-2">
                {r.attack_success.k} of {r.attack_success.n} attack runs · 95% CI <span className="tabular">{fmtCI(r.attack_success)}</span>
              </p>
              <p className="mt-1 text-[12px] text-muted">{configDescription(r.config)}</p>
            </div>
          );
        })}
      </div>
      {dir && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-5 py-3 text-[12px] text-ink-2">
          <span>
            {dir.meta.runs} runs · thresholds commit <span className="font-mono">{dir.meta.thresholds_commit.slice(0, 7)}</span> · code{" "}
            <span className="font-mono">{dir.meta.git_commit.slice(0, 7)}</span>
          </span>
          <Link href="/results" className="inline-flex items-center gap-1 font-medium text-accent-ink hover:underline">
            Every metric, with intervals <ArrowRight size={13} />
          </Link>
        </div>
      )}
    </Card>
  );
}

function MilestoneCard() {
  const { data, error } = useLoad((s) => fetchM1(s));
  return (
    <Card className="h-full">
      <CardHeader
        icon={<Milestone size={16} />}
        title="Milestone M1"
        subtitle="Two OS processes, one signed handoff over HTTP, scripted adversaries."
        actions={
          data && (
            <Link
              href={`/runs/view?id=${encodeURIComponent(data.trace)}&fixture=M1`}
              className="text-[12px] font-medium text-accent-ink hover:underline"
            >
              Open trace
            </Link>
          )
        }
      />
      <ol className="divide-y divide-line">
        {error && <li className="p-5 text-[13px] text-ink-2">No M1 trace yet. Run <code className="font-mono">make m1</code>.</li>}
        {!data && !error && (
          <li className="p-5">
            <Skeleton className="h-24" />
          </li>
        )}
        {data?.checks.checks.map((c) => (
          <li key={c.element} className="flex min-w-0 items-start gap-3 px-5 py-2.5">
            {c.ok ? (
              <CircleCheck size={16} className="mt-0.5 shrink-0 text-good" aria-label="passed" />
            ) : (
              <CircleX size={16} className="mt-0.5 shrink-0 text-critical" aria-label="failed" />
            )}
            <div className="min-w-0">
              <p className="text-[13px] font-medium text-ink first-letter:uppercase">
                <span className="mr-1.5 font-mono text-[11px] text-muted">{c.element}</span>
                {c.name}
              </p>
              <p className="truncate text-[12px] text-ink-2" title={c.detail}>
                {c.detail}
              </p>
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}

export function Overview() {
  return (
    <div className="space-y-10">
      <section className="relative">
        <motion.div {...fade} className="max-w-3xl">
          <p className="inline-flex items-center gap-2 rounded-full border border-line bg-surface/70 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-ink-2 backdrop-blur">
            <span className="size-1.5 rounded-full bg-accent" /> CaMeL, applied to two agents
          </p>
          <h1 className="mt-5 text-4xl font-semibold leading-[1.08] tracking-tight text-ink sm:text-5xl lg:text-[56px]">
            Every sensitive action,
            <br />
            <span className="bg-gradient-to-r from-accent to-accent-ink bg-clip-text text-transparent">checked four ways.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-[16px] leading-relaxed text-ink-2">
            A model-free orchestrator issues signed, scoped authority. Agents pass typed, signed handoffs whose data always
            arrives untrusted. Before a firewall rule or an account changes, the runtime checks integrity, authorization,
            intent, and evidence, each on its own, and every check is written to an audit log.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link
              href="/results"
              className="inline-flex h-10 items-center gap-2 rounded-xl bg-accent px-4 text-[14px] font-medium text-white shadow-[0_10px_30px_-12px_var(--accent)] transition hover:brightness-110"
            >
              Explore the results <ArrowRight size={15} />
            </Link>
            <Link
              href="/live"
              className="inline-flex h-10 items-center gap-2 rounded-xl bg-surface px-4 text-[14px] font-medium text-ink ring-1 ring-line-strong transition hover:bg-surface-2"
            >
              <Radio size={15} className="text-untrusted" /> Watch a live run
            </Link>
          </div>
        </motion.div>
        <motion.div {...fade} transition={{ ...fade.transition, delay: 0.1 }} className="mt-10">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center gap-4 border-b border-line px-5 py-3 text-[12px] text-ink-2">
              <span className="font-medium text-ink">How a run flows</span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-0.5 w-4 rounded bg-accent" /> authority
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-0.5 w-4 rounded bg-untrusted" /> attacker-influenced data
              </span>
            </div>
            <div className="hidden p-4 md:block">
              <ArchitectureFlow />
            </div>
            <ol className="space-y-2 p-5 text-[13px] text-ink-2 md:hidden">
              <li>1. The analyst picks a task; the orchestrator signs a scoped context.</li>
              <li>2. The Investigator reads logs, where attacker text lands, and extracts typed values.</li>
              <li>3. A signed handoff carries the values; they arrive untrusted.</li>
              <li>4. The Responder checks every action four ways before the mock tools run it.</li>
            </ol>
          </Card>
        </motion.div>
      </section>

      <section>
        <motion.h2 {...fade} className="text-[13px] font-medium uppercase tracking-[0.14em] text-muted">
          Four independent checks, any of which can deny on its own
        </motion.h2>
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {CHECKS.map((c, i) => (
            <motion.div key={c.name} {...fade} transition={{ ...fade.transition, delay: 0.06 * i }}>
              <Card className="group h-full p-5 transition hover:-translate-y-0.5 hover:border-line-strong">
                <span className="grid size-10 place-items-center rounded-xl bg-accent-soft text-accent ring-1 ring-accent/20">
                  <c.icon size={18} />
                </span>
                <h3 className="mt-4 text-[15px] font-semibold text-ink">{c.name}</h3>
                <p className="mt-1.5 text-[13.5px] leading-snug text-ink">{c.q}</p>
                <p className="mt-3 text-[12.5px] leading-relaxed text-ink-2">{c.by}</p>
              </Card>
            </motion.div>
          ))}
        </div>
      </section>

      <motion.section {...fade}>
        <Headline />
      </motion.section>

      <section className="grid grid-cols-1 gap-6 lg:grid-cols-[1.1fr_1fr]">
        <motion.div {...fade} className="min-w-0">
          <MilestoneCard />
        </motion.div>
        <motion.div {...fade} transition={{ ...fade.transition, delay: 0.08 }} className="min-w-0">
          <Card className="h-full">
            <CardHeader
              icon={<ShieldHalf size={16} />}
              title="What it does not claim"
              subtitle="Guarantees hold only under the threat model's assumptions, and tests check them; nothing is proven."
            />
            <ul className="space-y-3 p-5 text-[13px] leading-relaxed text-ink-2">
              <li>
                <span className="font-medium text-ink">Corroboration is not proof of intent.</span> An unlisted shared
                address produces real observations and can be blocked (B12, measured as an unauthorized effect).
              </li>
              <li>
                <span className="font-medium text-ink">Omission goes undetected.</span> Injected text can make the
                processor drop a real indicator (goal G4).
              </li>
              <li>
                <span className="font-medium text-ink">Mock tools only.</span> Nothing touches a real firewall or
                directory. One process per agent; run state is in memory.
              </li>
              <li>
                <span className="font-medium text-ink">Model runs wait on the access gate.</span> Results shown here
                come from deterministic scripted stand-ins unless a table says otherwise.
              </li>
            </ul>
          </Card>
        </motion.div>
      </section>
    </div>
  );
}
