"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Approvals, CitadelEvent, Fixture, M1Report, RunDir } from "./types";

// Every request goes through this app's own API route, which proxies to
// `citadel dash` on 127.0.0.1. The browser never talks to another origin.
export const API = "/api/citadel";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${API}/${path}`, { cache: "no-store", signal });
  if (!res.ok) {
    let code = `HTTP_${res.status}`;
    let detail = res.statusText;
    try {
      const body = (await res.json()) as { error?: string; detail?: string };
      code = body.error ?? code;
      detail = body.detail ?? detail;
    } catch {
      // keep the status text
    }
    throw new ApiError(res.status, code, detail);
  }
  return (await res.json()) as T;
}

export const fetchRuns = (s?: AbortSignal) => getJSON<{ dirs: RunDir[] | null }>("api/runs", s).then((d) => d.dirs ?? []);
export const fetchFixtures = (s?: AbortSignal) =>
  getJSON<{ fixtures: Fixture[] | null }>("api/fixtures", s).then((d) => d.fixtures ?? []);
export const fetchApprovals = (s?: AbortSignal) => getJSON<Approvals>("api/approvals", s);
export const fetchM1 = (s?: AbortSignal) => getJSON<M1Report>("api/m1", s);

export function encodeRunId(id: string): string {
  return id.split("/").map(encodeURIComponent).join("/");
}

export const fetchRunEvents = (id: string, s?: AbortSignal) =>
  getJSON<CitadelEvent[] | null>(`api/runs/${encodeRunId(id)}`, s).then((e) => e ?? []);

async function postJSON<T>(path: string, token: string, body: unknown): Promise<T> {
  const res = await fetch(`${API}/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Citadel-Token": token },
    body: JSON.stringify(body),
  });
  const json = (await res.json().catch(() => ({}))) as T & { error?: string; detail?: string };
  if (!res.ok) throw new ApiError(res.status, json.error ?? `HTTP_${res.status}`, json.detail ?? res.statusText);
  return json;
}

export const startRun = (token: string, fixture: string, config: string) =>
  postJSON<{ run_id: string }>("run", token, { fixture, config });

export const answerApproval = (token: string, key: string, approver: string, yes: boolean) =>
  postJSON<{ ok: boolean }>("approve", token, { key, approver, yes });

export interface Loadable<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  reload: () => void;
}

// useLoad fetches on mount and on reload. While a reload is in flight the
// previous data stays on screen, so views never flash a skeleton on refetch.
export function useLoad<T>(load: (signal: AbortSignal) => Promise<T>, deps: unknown[] = []): Loadable<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const loader = useRef(load);
  loader.current = load;
  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    loader
      .current(ac.signal)
      .then((d) => {
        setData(d);
        setError(undefined);
      })
      .catch((e: unknown) => {
        if (!ac.signal.aborted) setError(e instanceof Error ? e : new Error(String(e)));
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false);
      });
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, ...deps]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}

// useEventStream subscribes to the live server-sent-event stream.
export function useEventStream(enabled: boolean, onEvent: (e: CitadelEvent) => void) {
  const handler = useRef(onEvent);
  handler.current = onEvent;
  const [status, setStatus] = useState<"idle" | "connecting" | "open" | "error">("idle");
  useEffect(() => {
    if (!enabled) {
      setStatus("idle");
      return;
    }
    setStatus("connecting");
    const es = new EventSource(`${API}/events`);
    es.onopen = () => setStatus("open");
    es.onerror = () => setStatus("error");
    es.onmessage = (m) => {
      try {
        handler.current(JSON.parse(m.data) as CitadelEvent);
      } catch {
        // a malformed message is dropped; the replay log stays authoritative
      }
    };
    return () => es.close();
  }, [enabled]);
  return status;
}
