"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { ArrowUpRight, ShieldCheck, ShieldX, Target } from "lucide-react";
import { fetchFixtures, fetchRunEvents, fetchRuns, useLoad } from "@/lib/api";
import { callViews, changeKey } from "@/lib/derive";
import { mainDir } from "@/lib/select";
import { CONFIGS, type ConfigName, type Fixture, type RunSummary } from "@/lib/types";
import { ConfigChip, configDescription } from "../badges";
import { DecisionCard } from "../decision-card";
import { Card, Empty, ErrorNote, PageHeader, Select, Skeleton, cx } from "../ui";

function Column({ run, fixture }: { run?: RunSummary; fixture?: Fixture }) {
  const events = useLoad((s) => (run ? fetchRunEvents(run.id, s) : Promise.resolve([])), [run?.id]);
  const calls = useMemo(() => callViews(events.data ?? [], fixture), [events.data, fixture]);
  const goalCalls = calls.filter((c) => c.goal);
  const goals = new Set((fixture?.goal_any_of ?? []).map(changeKey));
  if (!run) {
    return (
      <Card>
        <Empty title="Not recorded">This configuration has no run for this fixture in the selected directory.</Empty>
      </Card>
    );
  }
  const attack = run.kind === "attack";
  return (
    <Card className={cx(run.config === "C2" && "ring-2 ring-accent/30")}>
      <div className="border-b border-line p-5">
        <div className="flex items-center justify-between gap-2">
          <ConfigChip config={run.config} />
          <Link
            href={`/runs/view?id=${encodeURIComponent(run.id)}&fixture=${encodeURIComponent(run.fixture)}`}
            className="inline-flex items-center gap-1 text-[12px] font-medium text-accent-ink hover:underline"
          >
            Full story <ArrowUpRight size={13} />
          </Link>
        </div>
        <p className="mt-2 text-[13px] text-ink-2">{configDescription(run.config)}</p>
        {attack && (
          <p
            className={cx(
              "mt-4 inline-flex items-center gap-2 rounded-xl px-3 py-2 text-[14px] font-semibold ring-1",
              run.attack_success ? "bg-critical/10 text-critical-ink ring-critical/30" : "bg-good/10 text-good-ink ring-good/30",
            )}
          >
            {run.attack_success ? <ShieldX size={16} /> : <ShieldCheck size={16} />}
            {run.attack_success ? "Attack goal held" : "Attack stopped"}
          </p>
        )}
      </div>
      <div className="space-y-4 p-5">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted">Environment after the run</p>
          {(run.diff ?? []).length === 0 ? (
            <p className="mt-1.5 text-[13px] text-ink-2">No changes.</p>
          ) : (
            <ul className="mt-1.5 space-y-1">
              {(run.diff ?? []).map((c) => (
                <li
                  key={changeKey(c)}
                  className={cx(
                    "flex items-center gap-2 rounded-lg px-2 py-1 font-mono text-[12px]",
                    goals.has(changeKey(c)) ? "bg-untrusted-soft text-untrusted-ink" : "bg-surface-2 text-ink",
                  )}
                >
                  {goals.has(changeKey(c)) && <Target size={12} aria-label="attack goal" />}
                  {c.tool}.{c.action} {c.target}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted">Decisions on the attack's targets</p>
          {events.loading && !events.data && <Skeleton className="mt-2 h-32" />}
          {events.data && run.config === "C0" && (
            <p className="mt-1.5 text-[13px] text-ink-2">C0 has no runtime: tool calls run directly, with no decision recorded.</p>
          )}
          {events.data && run.config !== "C0" && goalCalls.length === 0 && (
            <p className="mt-1.5 text-[13px] text-ink-2">No call reached the attack's targets: nothing to decide.</p>
          )}
          <div className="mt-2 space-y-2">
            {goalCalls.map((c) => (
              <DecisionCard key={c.key} view={c} compact />
            ))}
          </div>
        </div>
      </div>
    </Card>
  );
}

export function Compare() {
  const runs = useLoad((s) => fetchRuns(s));
  const fixtures = useLoad((s) => fetchFixtures(s));
  const [fixtureId, setFixtureId] = useState("A-G2b-downstream");
  const [shown, setShown] = useState<ConfigName[]>(["C1-instr", "C2"]);
  const dir = runs.data ? mainDir(runs.data) : undefined;
  const fixture = fixtures.data?.find((f) => f.id === fixtureId);
  const byConfig = new Map((dir?.runs ?? []).filter((r) => r.fixture === fixtureId && r.trial === 1).map((r) => [r.config, r]));
  const attackFixtures = (fixtures.data ?? []).filter((f) => f.kind === "attack" && f.id !== "M1");
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Compare"
        title="The same injection, different handoffs"
        lead="Policies are identical in every Citadel configuration; only the handoff differs. Under C1-instr the Responder reads a free-text report as the analyst's request, so injected names can arrive as analyst parameters. Under C2 they arrive as untrusted typed data and must pass the evidence rules."
      />
      {(runs.error || fixtures.error) && <ErrorNote error={(runs.error ?? fixtures.error)!} />}
      <div className="flex flex-wrap items-center gap-3">
        <Select label="Fixture" value={fixtureId} onChange={(e) => setFixtureId(e.target.value)}>
          {attackFixtures.map((f) => (
            <option key={f.id} value={f.id}>
              {f.id}
            </option>
          ))}
        </Select>
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Configurations shown">
          {CONFIGS.map((c) => {
            const on = shown.includes(c);
            return (
              <button
                key={c}
                aria-pressed={on}
                onClick={() => setShown((s) => (on ? s.filter((x) => x !== c) : CONFIGS.filter((x) => x === c || s.includes(x))))}
                className={cx(
                  "h-8 rounded-lg px-3 font-mono text-[12px] font-medium ring-1 transition",
                  on ? "bg-accent-soft text-accent-ink ring-accent/30" : "bg-surface text-ink-2 ring-line hover:text-ink",
                )}
              >
                {c}
              </button>
            );
          })}
        </div>
      </div>
      {fixture && (
        <Card className="flex flex-wrap items-start gap-4 p-5">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-untrusted-soft text-untrusted ring-1 ring-untrusted/25">
            <Target size={18} />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-[14px] font-medium text-ink">{fixture.description}</p>
            <p className="mt-1 text-[12.5px] text-ink-2">
              {fixture.goal_none_of?.length
                ? `The attack succeeds if none of these happens: ${fixture.goal_none_of.map(changeKey).join(", ")}.`
                : `The attack succeeds if any of these happens: ${(fixture.goal_any_of ?? []).map(changeKey).join(", ")}.`}
            </p>
          </div>
        </Card>
      )}
      {!runs.data && !runs.error && <Skeleton className="h-96" />}
      {runs.data && (
        <div className={cx("grid grid-cols-1 gap-5", shown.length >= 3 ? "xl:grid-cols-3 2xl:grid-cols-4" : "lg:grid-cols-2")}>
          {shown.map((c) => (
            <Column key={`${fixtureId}-${c}`} run={byConfig.get(c)} fixture={fixture} />
          ))}
        </div>
      )}
    </div>
  );
}
