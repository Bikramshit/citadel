"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Ban, Check, Play, Radio, ShieldQuestion, Timer } from "lucide-react";
import { answerApproval, fetchApprovals, fetchFixtures, startRun, useEventStream, useLoad } from "@/lib/api";
import { story } from "@/lib/derive";
import { CONFIGS, type ApprovalRequest, type CitadelEvent, type ConfigName } from "@/lib/types";
import { Sources, Untrusted, VerdictBadge, configDescription } from "../badges";
import { StoryLanes } from "../run-story";
import { Timeline } from "../timeline";
import { Button, Card, CardHeader, Empty, ErrorNote, PageHeader, Segmented, Select, cx } from "../ui";

// RequestedAt and ExpiresAt are on the run's clock, which may sit at a
// fixture's date; the lifetime between them counts down in wall time from
// when the request was first seen (at most one poll late).
function Countdown({ requested, expires }: { requested: string; expires: string }) {
  const [deadline] = useState(() => Date.now() + (new Date(expires).getTime() - new Date(requested).getTime()));
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  if (!Number.isFinite(deadline)) return null;
  const ms = Math.max(0, deadline - now);
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return (
    <span className="tabular inline-flex items-center gap-1 text-[12px] text-ink-2">
      <Timer size={12} /> expires in {m}:{String(s).padStart(2, "0")}
    </span>
  );
}

function ApprovalCard({ req, principal, token, onDone }: { req: ApprovalRequest; principal: string; token: string; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const answer = async (yes: boolean) => {
    setBusy(true);
    setErr(undefined);
    try {
      await answerApproval(token, req.Key, principal, yes);
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const ev = req.Evidence;
  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.97, y: 10 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.97 }}
      className="sheen relative overflow-hidden rounded-2xl border border-warning/50 bg-surface shadow-lift"
    >
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-warning to-serious" />
      <div className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider text-warning-ink">
              <ShieldQuestion size={14} /> Approval needed
            </p>
            <p className="mt-2 font-mono text-[12px] text-ink-2">
              {req.Agent} · {req.Op.tool}.{req.Op.action}
            </p>
            <p className="mt-0.5 font-mono text-[18px] font-semibold text-ink">
              <Untrusted text={req.Target} n={40} className="text-[18px] font-semibold text-ink" />
            </p>
          </div>
          <Countdown requested={req.RequestedAt} expires={req.ExpiresAt} />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-2">
          <VerdictBadge verdict={req.Decision.verdict} rule={req.Decision.rule} size="sm" />
          <span>{req.Decision.reason}</span>
        </div>
        <dl className="mt-4 space-y-2 text-[12.5px]">
          {Object.entries(req.Args ?? {}).map(([name, v]) => (
            <div key={name} className="grid grid-cols-[72px_1fr] gap-2">
              <dt className="font-mono text-muted">{name}</dt>
              <dd className="min-w-0">
                <span className="font-mono text-ink">{v}</span>
                <div className="mt-1">
                  <Sources sources={req.Sources?.[name]} max={6} />
                </div>
              </dd>
            </div>
          ))}
          {ev && (
            <div className="grid grid-cols-[72px_1fr] gap-2">
              <dt className="font-mono text-muted">evidence</dt>
              <dd className="tabular text-ink">
                <span className="font-medium capitalize">{ev.verdict}</span> · {ev.observations} observations (k = {ev.k}) · {ev.flows}{" "}
                established flows{ev.conflict ? ` · ${ev.conflict.replaceAll("_", " ")}` : ""}
              </dd>
            </div>
          )}
        </dl>
        <p className="mt-4 text-[12px] text-ink-2">
          Approving authorizes this exact call once. It grants no capability, changes no label, and cannot override a Deny.
        </p>
        {err && <p className="mt-2 text-[12px] text-critical-ink">{err}</p>}
        <div className="mt-4 flex gap-2">
          <Button variant="primary" disabled={busy} onClick={() => answer(true)}>
            <Check size={14} /> Approve as {principal}
          </Button>
          <Button variant="danger" disabled={busy} onClick={() => answer(false)}>
            <Ban size={14} /> Deny
          </Button>
        </div>
      </div>
    </motion.div>
  );
}

export function Live() {
  const fixtures = useLoad((s) => fetchFixtures(s));
  const [fixture, setFixture] = useState("A-G3b-downstream");
  const [config, setConfig] = useState<ConfigName>("C2");
  const [events, setEvents] = useState<CitadelEvent[]>([]);
  const [runId, setRunId] = useState<string>();
  const [startedAt, setStartedAt] = useState<number>();
  const [error, setError] = useState<string>();
  const [approvals, setApprovals] = useState<{ principal: string; token: string; pending: ApprovalRequest[] }>();
  const runRef = useRef<string | undefined>(undefined);
  runRef.current = runId;

  const onEvent = useCallback((e: CitadelEvent) => {
    // Follow the first run that starts after the button was pressed.
    if (!runRef.current && e.kind === "run_start" && e.run) {
      runRef.current = e.run;
      setRunId(e.run);
    }
    if (runRef.current && e.run && e.run !== runRef.current) return;
    if (!runRef.current) return;
    setEvents((prev) => [...prev, e]);
  }, []);
  const status = useEventStream(startedAt !== undefined, onEvent);

  const pollApprovals = useCallback(async () => {
    try {
      const a = await fetchApprovals();
      setApprovals({ principal: a.principal, token: a.token, pending: a.pending ?? [] });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    pollApprovals();
    if (startedAt === undefined) return;
    const t = setInterval(pollApprovals, 1500);
    return () => clearInterval(t);
  }, [startedAt, pollApprovals]);

  const start = async () => {
    setError(undefined);
    setEvents([]);
    setRunId(undefined);
    runRef.current = undefined;
    try {
      const token: string = approvals?.token ?? (await fetchApprovals()).token;
      setStartedAt(Date.now());
      await new Promise((r) => setTimeout(r, 300)); // let the stream subscribe first
      await startRun(token, fixture, config);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const fx = fixtures.data?.find((f) => f.id === fixture);
  const s = useMemo(() => story(events, fx), [events, fx]);
  const finished = events.some((e) => e.kind === "env_change") || (s.end.size >= 2 && !s.handoffSend) || s.aborts.length > 0;
  const pending = (approvals?.pending ?? []).filter((p) => !runId || p.RunID === runId);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Live"
        title="Run a fixture and watch every check happen"
        lead="Starts a run inside citadel dash with the deterministic scripted stand-ins and streams its audit events as they are written. Escalations wait for your answer below, as the context's principal."
      />
      {fixtures.error && <ErrorNote error={fixtures.error} />}
      <Card>
        <div className="flex flex-wrap items-center gap-3 p-4">
          <Select label="Fixture" value={fixture} onChange={(e) => setFixture(e.target.value)}>
            {["attack", "benign"].map((k) => (
              <optgroup key={k} label={k === "attack" ? "Attacks" : "Benign"}>
                {(fixtures.data ?? [])
                  .filter((f) => (k === "attack" ? f.kind === "attack" && f.id !== "M1" : f.kind === "benign"))
                  .map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.id}
                    </option>
                  ))}
              </optgroup>
            ))}
            <optgroup label="Milestone">
              <option value="M1">M1</option>
            </optgroup>
          </Select>
          <Segmented label="Configuration" value={config} onChange={setConfig} options={CONFIGS.map((c) => ({ value: c, label: c }))} />
          <Button variant="primary" onClick={start} disabled={!fixtures.data}>
            <Play size={14} /> Start run
          </Button>
          <span className="ml-auto inline-flex items-center gap-2 text-[12px] text-ink-2">
            <Radio size={14} className={cx(status === "open" ? "text-good" : "text-muted")} />
            {status === "open" ? "streaming" : status === "connecting" ? "connecting" : status === "error" ? "stream interrupted" : "idle"}
            {runId && <span className="font-mono text-muted">· {runId}</span>}
          </span>
        </div>
        {fx && (
          <p className="border-t border-line px-4 py-3 text-[13px] text-ink-2">
            <span className="font-medium text-ink">{fx.id}</span> · {fx.description}{" "}
            <span className="text-muted">· {configDescription(config)}</span>
          </p>
        )}
        {error && <p className="border-t border-line px-4 py-3 text-[13px] text-critical-ink">{error}</p>}
      </Card>

      <AnimatePresence>
        {pending.length > 0 && approvals && (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {pending.map((p) => (
              <ApprovalCard key={p.Key} req={p} principal={approvals.principal} token={approvals.token} onDone={pollApprovals} />
            ))}
          </div>
        )}
      </AnimatePresence>

      {startedAt === undefined ? (
        <Card>
          <Empty title="Nothing running">
            Pick a fixture and a configuration, then start a run. Try <span className="font-mono">A-G3b-downstream</span> under C1-instr and
            then C2 to watch the same injected text get laundered, then stopped.
          </Empty>
        </Card>
      ) : (
        <>
          <StoryLanes s={s} />
          <Card>
            <CardHeader
              title="Event stream"
              subtitle={finished ? `${events.length} events · run finished` : `${events.length} events so far`}
            />
            {events.length === 0 ? <p className="p-5 text-[13px] text-muted">Waiting for the run to start…</p> : <Timeline events={events} animate />}
          </Card>
        </>
      )}
    </div>
  );
}
