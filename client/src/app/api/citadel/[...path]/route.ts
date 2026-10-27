// A narrow proxy from this app to `citadel dash` on 127.0.0.1. Only the
// dashboard's own endpoints pass; POSTs must come from this app's origin and
// carry the dashboard's token, which `citadel dash` checks again.

import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const UPSTREAM = process.env.CITADEL_URL ?? "http://127.0.0.1:8080";

const GET_ALLOWED = [/^api\/runs$/, /^api\/runs\/[^?#]+$/, /^api\/fixtures$/, /^api\/approvals$/, /^api\/m1$/, /^events$/];
const POST_ALLOWED = [/^run$/, /^approve$/];
const MAX_BODY = 64 * 1024;

type Ctx = { params: Promise<{ path: string[] }> };

function upstreamURL(segments: string[]): URL | null {
  if (segments.some((s) => s === ".." || s === "." || s === "")) return null;
  const path = segments.map(encodeURIComponent).join("/");
  const base = new URL(UPSTREAM);
  if (base.hostname !== "127.0.0.1" && base.hostname !== "localhost") return null;
  return new URL(`/${path}`, base);
}

function relay(upstream: Response): Response {
  const headers = new Headers();
  const type = upstream.headers.get("content-type");
  if (type) headers.set("content-type", type);
  headers.set("cache-control", "no-cache, no-store, no-transform");
  if (type?.startsWith("text/event-stream")) headers.set("x-accel-buffering", "no");
  return new Response(upstream.body, { status: upstream.status, headers });
}

function unavailable(err: unknown): Response {
  const detail = err instanceof Error ? err.message : String(err);
  return Response.json(
    { error: "ERR_UPSTREAM", detail: `citadel dash is not reachable at ${UPSTREAM}: ${detail}` },
    { status: 502 },
  );
}

export async function GET(req: NextRequest, ctx: Ctx): Promise<Response> {
  const { path } = await ctx.params;
  const joined = path.join("/");
  if (!GET_ALLOWED.some((r) => r.test(joined))) return Response.json({ error: "ERR_NOT_FOUND" }, { status: 404 });
  const url = upstreamURL(path);
  if (!url) return Response.json({ error: "ERR_SCHEMA" }, { status: 400 });
  try {
    const upstream = await fetch(url, {
      headers: { accept: joined === "events" ? "text/event-stream" : "application/json" },
      cache: "no-store",
      signal: req.signal,
    });
    return relay(upstream);
  } catch (err) {
    return unavailable(err);
  }
}

export async function POST(req: NextRequest, ctx: Ctx): Promise<Response> {
  const { path } = await ctx.params;
  const joined = path.join("/");
  if (!POST_ALLOWED.some((r) => r.test(joined))) return Response.json({ error: "ERR_NOT_FOUND" }, { status: 404 });
  const origin = req.headers.get("origin");
  if (!origin || new URL(origin).host !== req.headers.get("host")) {
    return Response.json({ error: "ERR_NOT_PRINCIPAL", detail: "cross-origin request refused" }, { status: 403 });
  }
  const token = req.headers.get("x-citadel-token") ?? "";
  const body = await req.text();
  if (body.length > MAX_BODY) return Response.json({ error: "ERR_SIZE" }, { status: 413 });
  const url = upstreamURL(path);
  if (!url) return Response.json({ error: "ERR_SCHEMA" }, { status: 400 });
  try {
    const upstream = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-citadel-token": token },
      body,
      cache: "no-store",
    });
    return relay(upstream);
  } catch (err) {
    return unavailable(err);
  }
}
