"use client";

import { useMemo, useState } from "react";
import { ChartScatter, FlaskConical, Gauge, Microscope, Table2 } from "lucide-react";
import { fetchRuns, useLoad } from "@/lib/api";
import { fmtCI, fmtDate, fmtMean, fmtRate, ratePct, shortHash } from "@/lib/derive";
import { dirLabel, implOf, mainDir, rowsOf } from "@/lib/select";
import type { Rate, Row, RunDir } from "@/lib/types";
import { ConfigChip, ImplBanner, configDescription } from "../badges";
import { RateChart } from "../rate-chart";
import { Card, CardHeader, Empty, ErrorNote, PageHeader, Segmented, Select, Skeleton, cx } from "../ui";

type Metric = { key: keyof Row; title: string; better: "lower" | "higher"; note: string };

const METRICS: Metric[] = [
  { key: "attack_success", title: "Attack success", better: "lower", note: "Attack runs where the goal held afterward" },
  { key: "runs_with_unauthorized", title: "Runs with an unauthorized effect", better: "lower", note: "Any change outside the fixture's allowed set" },
  { key: "completion_benign", title: "Task completion, benign", better: "higher", note: "Every required change made, run not failed" },
  { key: "completion_attack", title: "Task completion under attack", better: "higher", note: "The real containment still done" },
  { key: "false_blocks", title: "False blocks", better: "lower", note: "Required benign changes not made because of a Deny" },
  { key: "failed", title: "Failed runs", better: "lower", note: "Crashes, timeouts, aborts, malformed plans" },
];

function RateCell({ r }: { r: Rate }) {
  if (r.n === 0) return <span className="text-muted">n = 0</span>;
  return (
    <span className="whitespace-nowrap">
      <span className="font-medium text-ink">{Math.round(ratePct(r))}%</span>{" "}
      <span className="text-ink-2">{fmtRate(r)}</span> <span className="text-muted">{fmtCI(r)}</span>
    </span>
  );
}

function Provenance({ dir }: { dir: RunDir }) {
  const m = dir.meta;
  const items = [
    ["Runs", `${m.runs} (${m.crashes} crashed, ${m.invalid} with invariant violations)`],
    ["Trials per fixture", String(m.trials)],
    ["Fixtures", m.fixtures_dir],
    ["Evidence rules", m.evidence || "on"],
    ["Thresholds", `k=${m.thresholds.k}, min flows ${m.thresholds.min_flows}, soft budget ${m.thresholds.soft_untrusted_pc}, iteration budget ${m.thresholds.iteration_budget}`],
    ["Thresholds commit", shortHash(m.thresholds_commit)],
    ["Code commit", `${shortHash(m.git_commit)}${m.git_dirty ? " (dirty)" : ""}`],
    ["Run dates", `${fmtDate(m.started)} to ${fmtDate(m.finished)}`],
  ];
  return (
    <Card>
      <CardHeader
        icon={<FlaskConical size={16} />}
        title="Where these numbers come from"
        subtitle={
          implOf(dir) === "model"
            ? "Model runs: how often attacks and tasks succeed with these models on these dates."
            : "Every model role was a deterministic worst-case stand-in following fixed rules. These show what the runtime enforces under adversarial inputs; they are not measurements of any model."
        }
        actions={<ImplBanner impl={implOf(dir)} />}
      />
      <dl className="grid grid-cols-1 gap-x-8 gap-y-3 p-5 text-[13px] sm:grid-cols-2 xl:grid-cols-4">
        {items.map(([k, v]) => (
          <div key={k} className="min-w-0">
            <dt className="text-[11px] font-medium uppercase tracking-wider text-muted">{k}</dt>
            <dd className="mt-0.5 break-words font-mono text-[12px] leading-snug text-ink">
              {v}
            </dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function MetricsTable({ rows }: { rows: Row[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="tabular w-full min-w-[920px] text-left text-[12.5px]">
        <thead className="border-b border-line text-[11px] uppercase tracking-wider text-muted">
          <tr>
            <th className="px-5 py-3 font-medium">Config</th>
            {METRICS.map((m) => (
              <th key={m.key} className="px-3 py-3 font-medium">
                {m.title}
              </th>
            ))}
            <th className="px-3 py-3 font-medium">Laundered</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rows.map((r) => (
            <tr key={r.config} className={cx(r.config === "C2" && "bg-accent-soft/40")}>
              <td className="px-5 py-3">
                <ConfigChip config={r.config} />
              </td>
              {METRICS.map((m) => (
                <td key={m.key} className="px-3 py-3">
                  <RateCell r={r[m.key] as Rate} />
                </td>
              ))}
              <td className="px-3 py-3">{r.config === "C1-instr" ? <RateCell r={r.laundered} /> : <span className="text-muted">–</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CostsTable({ rows }: { rows: Row[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="tabular w-full min-w-[720px] text-left text-[12.5px]">
        <thead className="border-b border-line text-[11px] uppercase tracking-wider text-muted">
          <tr>
            <th className="px-5 py-3 font-medium">Config</th>
            <th className="px-3 py-3 font-medium">Unauthorized effects per run</th>
            <th className="px-3 py-3 font-medium">Escalations per benign run</th>
            <th className="px-3 py-3 font-medium">Attacker-triggered escalations</th>
            <th className="px-3 py-3 font-medium">Uncertain outcomes per run</th>
            <th className="px-3 py-3 font-medium">Latency p50 / p95</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rows.map((r) => (
            <tr key={r.config}>
              <td className="px-5 py-3">
                <ConfigChip config={r.config} />
              </td>
              <td className="px-3 py-3 text-ink">
                {fmtMean(r.unauthorized)} <span className="text-muted">n = {r.unauthorized.n}</span>
              </td>
              <td className="px-3 py-3 text-ink">
                {r.config === "C0" ? (
                  <span className="text-muted">not applicable</span>
                ) : (
                  <>
                    {fmtMean(r.escalations_benign)} <span className="text-muted">n = {r.escalations_benign.n}</span>
                  </>
                )}
              </td>
              <td className="px-3 py-3 text-ink">
                {r.config === "C0" ? (
                  <span className="text-muted">not applicable</span>
                ) : (
                  <>
                    {fmtMean(r.attacker_escalations)} <span className="text-muted">n = {r.attacker_escalations.n}</span>
                  </>
                )}
              </td>
              <td className="px-3 py-3 text-ink">
                {fmtMean(r.uncertain)} <span className="text-muted">n = {r.uncertain.n}</span>
              </td>
              <td className="whitespace-nowrap px-3 py-3 text-ink">
                {r.p50_ms.toFixed(1)} / {r.p95_ms.toFixed(1)} ms <span className="text-muted">n = {r.latency_n}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Ablation({ dirs }: { dirs: RunDir[] }) {
  const legacy = dirs.filter((d) => d.meta.evidence === "legacy").sort((a, b) => b.meta.started.localeCompare(a.meta.started))[0];
  if (!legacy) return null;
  const ids = new Set((legacy.meta.fixtures ?? []).map((f) => f.id));
  const on = dirs
    .filter(
      (d) =>
        (d.meta.evidence || "on") === "on" &&
        (d.meta.configs ?? []).join() === (legacy.meta.configs ?? []).join() &&
        (d.meta.fixtures ?? []).length === ids.size &&
        (d.meta.fixtures ?? []).every((f) => ids.has(f.id)),
    )
    .sort((a, b) => b.meta.started.localeCompare(a.meta.started))[0];
  if (!on) return null;
  const a = rowsOf(on).find((r) => r.config === "C2");
  const b = rowsOf(legacy).find((r) => r.config === "C2");
  if (!a || !b) return null;
  const lines: { label: string; on: Rate; legacy: Rate }[] = [
    { label: "Attack success", on: a.attack_success, legacy: b.attack_success },
    { label: "Runs with an unauthorized effect", on: a.runs_with_unauthorized, legacy: b.runs_with_unauthorized },
    { label: "Task completion, benign", on: a.completion_benign, legacy: b.completion_benign },
  ];
  return (
    <Card>
      <CardHeader
        icon={<Microscope size={16} />}
        title="Experiment 3: what the evidence rules prevent, and what they cost"
        subtitle={`C2 on the same ${ids.size} fixtures, with E1 and E2 versus the superseded rule (untrusted and unprotected is allowed; accounts escalate).`}
        actions={<ImplBanner impl={implOf(on)} />}
      />
      <div className="grid grid-cols-1 gap-6 p-5 lg:grid-cols-3">
        {lines.map((l) => (
          <div key={l.label}>
            <p className="text-[13px] font-medium text-ink">{l.label}</p>
            <RateChart
              title={l.label}
              better={l.label.startsWith("Task") ? "higher" : "lower"}
              points={[
                { label: "E1+E2", rate: l.on, emphasized: true },
                { label: "old rule", rate: l.legacy },
              ]}
            />
          </div>
        ))}
      </div>
      <p className="border-t border-line px-5 py-3 text-[12px] text-ink-2">
        Escalations per benign run: <span className="tabular text-ink">{fmtMean(a.escalations_benign)}</span> with evidence rules,{" "}
        <span className="tabular text-ink">{fmtMean(b.escalations_benign)}</span> under the old rule (n = {a.escalations_benign.n}).
      </p>
    </Card>
  );
}

export function Results() {
  const { data, error } = useLoad((s) => fetchRuns(s));
  const [picked, setPicked] = useState<string>();
  const [view, setView] = useState<"chart" | "table">("chart");
  const dirs = useMemo(() => data ?? [], [data]);
  const dir = dirs.find((d) => d.dir === picked) ?? mainDir(dirs);
  const rows = rowsOf(dir);
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Results"
        title="What the runtime stopped, and what it cost"
        lead="Every number on this page is computed by the harness from recorded runs: environment diffs and policy events, never what a model said it did. Each rate carries its sample size and a 95% Wilson interval."
      />
      {error && <ErrorNote error={error} />}
      {!data && !error && <Skeleton className="h-64" />}
      {data && !dir && (
        <Card>
          <Empty title="No recorded runs">
            Run <code className="font-mono">make eval IMPL=scripted TRIALS=1</code>, then start{" "}
            <code className="font-mono">make dash</code>.
          </Empty>
        </Card>
      )}
      {dir && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <Select label="Run" value={dir.dir} onChange={(e) => setPicked(e.target.value)}>
              {dirs.map((d) => (
                <option key={d.dir} value={d.dir}>
                  {dirLabel(d)}
                </option>
              ))}
            </Select>
            <Segmented
              label="View"
              value={view}
              onChange={setView}
              options={[
                {
                  value: "chart",
                  label: (
                    <span className="inline-flex items-center gap-1.5">
                      <ChartScatter size={14} /> Charts
                    </span>
                  ),
                },
                {
                  value: "table",
                  label: (
                    <span className="inline-flex items-center gap-1.5">
                      <Table2 size={14} /> Table
                    </span>
                  ),
                },
              ]}
            />
          </div>
          <Provenance dir={dir} />
          {view === "chart" ? (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {METRICS.map((m) => (
                <Card key={m.key} className="p-5">
                  <div className="mb-3 flex items-baseline justify-between gap-3">
                    <h3 className="text-[14px] font-semibold text-ink">{m.title}</h3>
                    <span className="text-[11px] text-muted">{m.better === "lower" ? "lower is better" : "higher is better"}</span>
                  </div>
                  <p className="-mt-2 mb-3 text-[12px] text-ink-2">{m.note}</p>
                  <RateChart
                    title={m.title}
                    better={m.better}
                    points={rows.map((r) => ({ label: r.config, rate: r[m.key] as Rate, emphasized: r.config === "C2" }))}
                  />
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardHeader icon={<Table2 size={16} />} title="All rates" subtitle="k/n, the percentage, and the 95% Wilson interval." />
              <MetricsTable rows={rows} />
            </Card>
          )}
          <Card>
            <CardHeader
              icon={<Gauge size={16} />}
              title="Costs"
              subtitle="Means per run with their sample sizes. C0 has no approvals, so its escalation cells do not apply."
            />
            <CostsTable rows={rows} />
          </Card>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {rows.map((r) => (
              <div key={r.config} className="rounded-xl border border-line bg-surface/70 p-4 text-[12px] text-ink-2">
                <ConfigChip config={r.config} /> <span className="ml-1">{configDescription(r.config)}</span>
              </div>
            ))}
          </div>
          <Ablation dirs={dirs} />
        </>
      )}
    </div>
  );
}
