"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, ListTree, Pause, Play, RotateCcw, Rows3, ShieldCheck, ShieldX, TriangleAlert } from "lucide-react";
import { fetchFixtures, fetchRunEvents, fetchRuns, useLoad } from "@/lib/api";
import { story } from "@/lib/derive";
import { ConfigChip, ImplBanner, configDescription } from "../badges";
import { StoryLanes } from "../run-story";
import { Timeline } from "../timeline";
import { Button, Card, CardHeader, ErrorNote, Segmented, Skeleton, Tag } from "../ui";

export function RunView() {
  const params = useSearchParams();
  const id = params.get("id") ?? "";
  const fixtureId = params.get("fixture") ?? id.split("/").at(-2) ?? "";
  const events = useLoad((s) => fetchRunEvents(id, s), [id]);
  const fixtures = useLoad((s) => fetchFixtures(s));
  const runs = useLoad((s) => fetchRuns(s));
  const fixture = fixtures.data?.find((f) => f.id === fixtureId);
  const summary = useMemo(() => runs.data?.flatMap((d) => d.runs ?? []).find((r) => r.id === id), [runs.data, id]);
  const all = useMemo(() => [...(events.data ?? [])].sort((a, b) => a.seq - b.seq || a.at.localeCompare(b.at)), [events.data]);
  const [step, setStep] = useState<number | null>(null);
  const [playing, setPlaying] = useState(false);
  const [tab, setTab] = useState<"story" | "timeline">("story");
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => {
      setStep((s) => {
        const next = (s ?? 0) + 1;
        if (next >= all.length) {
          setPlaying(false);
          return null;
        }
        return next;
      });
    }, 420);
    return () => clearInterval(t);
  }, [playing, all.length]);
  const shown = step === null ? all : all.slice(0, step);
  const s = useMemo(() => story(shown, fixture), [shown, fixture]);
  const config = summary?.config ?? all[0]?.config ?? "";
  const counts = s.calls.reduce(
    (acc, c) => {
      if (c.final) acc[c.final.verdict]++;
      return acc;
    },
    { allow: 0, escalate: 0, deny: 0 },
  );

  if (!id) return <ErrorNote error={new Error("No run selected.")} />;
  return (
    <div className="space-y-6">
      <Link href="/runs" className="inline-flex items-center gap-1.5 text-[13px] font-medium text-ink-2 hover:text-ink">
        <ArrowLeft size={14} /> All runs
      </Link>
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0 max-w-3xl">
          <div className="flex flex-wrap items-center gap-2">
            {config && <ConfigChip config={config} />}
            {fixture?.goal && <Tag>{fixture.goal}</Tag>}
            {fixture?.style && <Tag>{fixture.style}</Tag>}
            <ImplBanner impl={summary?.impl} />
          </div>
          <h1 className="mt-3 font-mono text-2xl font-semibold tracking-tight text-ink md:text-3xl">{fixtureId || "Run"}</h1>
          <p className="mt-2 text-[14.5px] leading-relaxed text-ink-2">{fixture?.description ?? id}</p>
          {config && <p className="mt-1 text-[13px] text-muted">{configDescription(config)}</p>}
        </div>
        {summary && (
          <div className="flex flex-wrap gap-2">
            {summary.kind === "attack" ? (
              summary.attack_success ? (
                <span className="inline-flex items-center gap-1.5 rounded-xl bg-critical/10 px-3 py-2 text-[13px] font-semibold text-critical-ink ring-1 ring-critical/30">
                  <ShieldX size={16} /> Attack goal held
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-xl bg-good/10 px-3 py-2 text-[13px] font-semibold text-good-ink ring-1 ring-good/30">
                  <ShieldCheck size={16} /> Attack stopped
                </span>
              )
            ) : null}
            <span className="inline-flex items-center gap-1.5 rounded-xl bg-surface px-3 py-2 text-[13px] font-medium text-ink ring-1 ring-line">
              {summary.completed ? "Task completed" : "Task not completed"}
            </span>
            {summary.unauthorized > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-xl bg-surface px-3 py-2 text-[13px] font-medium text-ink ring-1 ring-serious">
                <TriangleAlert size={15} className="text-serious" /> {summary.unauthorized} unauthorized change
                {summary.unauthorized > 1 ? "s" : ""}
              </span>
            )}
          </div>
        )}
      </div>

      {events.error && <ErrorNote error={events.error} />}
      {!events.data && !events.error && <Skeleton className="h-96" />}
      {events.data && (
        <>
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
              <div className="flex flex-wrap items-center gap-3">
                <Segmented
                  label="View"
                  value={tab}
                  onChange={setTab}
                  options={[
                    {
                      value: "story",
                      label: (
                        <span className="inline-flex items-center gap-1.5">
                          <ListTree size={14} /> Story
                        </span>
                      ),
                    },
                    {
                      value: "timeline",
                      label: (
                        <span className="inline-flex items-center gap-1.5">
                          <Rows3 size={14} /> Timeline
                        </span>
                      ),
                    },
                  ]}
                />
                <span className="tabular text-[12px] text-ink-2">
                  {counts.allow} allowed · {counts.escalate} escalated · {counts.deny} denied · {s.changes.length} changes
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant={playing ? "secondary" : "primary"}
                  onClick={() => {
                    if (playing) setPlaying(false);
                    else {
                      setStep((v) => (v === null ? 0 : v));
                      setPlaying(true);
                    }
                  }}
                  aria-label={playing ? "Pause replay" : "Replay the run event by event"}
                >
                  {playing ? <Pause size={14} /> : <Play size={14} />} {playing ? "Pause" : "Replay"}
                </Button>
                {step !== null && (
                  <Button variant="ghost" onClick={() => (setPlaying(false), setStep(null))} aria-label="Show the whole run">
                    <RotateCcw size={14} />
                  </Button>
                )}
              </div>
            </div>
            <div className="flex items-center gap-3 border-t border-line px-5 py-2.5">
              <span className="tabular w-24 shrink-0 text-[11px] text-muted">
                event {shown.length} / {all.length}
              </span>
              <input
                type="range"
                min={0}
                max={all.length}
                value={step ?? all.length}
                onChange={(e) => {
                  setPlaying(false);
                  const v = Number(e.target.value);
                  setStep(v >= all.length ? null : v);
                }}
                aria-label="Scrub through the run's events"
                className="h-1.5 w-full cursor-pointer accent-[var(--accent)]"
              />
            </div>
          </Card>
          {tab === "story" ? (
            <StoryLanes s={s} />
          ) : (
            <Card>
              <CardHeader title="Every event" subtitle={`${shown.length} of ${all.length} events, in log order`} />
              <Timeline events={shown} />
            </Card>
          )}
        </>
      )}
    </div>
  );
}
