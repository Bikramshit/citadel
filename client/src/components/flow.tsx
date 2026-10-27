// The architecture at a glance: authority flows from the model-free
// orchestrator (blue); attacker text enters through the logs and stays
// untrusted data all the way to the Responder's four checks (orange).

function Box({
  x,
  y,
  w,
  h,
  title,
  sub,
  tone = "neutral",
}: {
  x: number;
  y: number;
  w: number;
  h: number;
  title: string;
  sub?: string;
  tone?: "neutral" | "accent" | "untrusted";
}) {
  const stroke = tone === "accent" ? "var(--accent)" : tone === "untrusted" ? "var(--untrusted)" : "var(--line-strong)";
  const fill = tone === "accent" ? "var(--accent-soft)" : tone === "untrusted" ? "var(--untrusted-soft)" : "var(--surface)";
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={14} fill={fill} stroke={stroke} strokeWidth={tone === "neutral" ? 1 : 1.5} />
      <text x={x + 14} y={y + 24} className="fill-ink text-[13px] font-semibold">
        {title}
      </text>
      {sub && (
        <text x={x + 14} y={y + 42} className="fill-ink-2 text-[11px]">
          {sub}
        </text>
      )}
    </g>
  );
}

function Pill({ x, y, label, tone }: { x: number; y: number; label: string; tone: "accent" | "untrusted" | "neutral" }) {
  const w = label.length * 6.4 + 18;
  const stroke = tone === "accent" ? "var(--accent)" : tone === "untrusted" ? "var(--untrusted)" : "var(--line-strong)";
  return (
    <g>
      <rect x={x} y={y} width={w} height={20} rx={10} fill="var(--surface-2)" stroke={stroke} strokeOpacity={0.6} />
      <text x={x + 9} y={y + 14} className="fill-ink-2 font-mono text-[10.5px]">
        {label}
      </text>
    </g>
  );
}

function Edge({ d, tone, label, lx, ly }: { d: string; tone: "accent" | "untrusted" | "neutral"; label?: string; lx?: number; ly?: number }) {
  const color = tone === "accent" ? "var(--accent)" : tone === "untrusted" ? "var(--untrusted)" : "var(--axis)";
  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeOpacity={0.25} strokeWidth={2} />
      <path d={d} fill="none" stroke={color} strokeWidth={2} className="flow-dash" markerEnd={`url(#arrow-${tone})`} />
      {label && lx !== undefined && ly !== undefined && (
        <text x={lx} y={ly} textAnchor="middle" className="fill-ink-2 font-mono text-[10px]">
          {label}
        </text>
      )}
    </g>
  );
}

export function ArchitectureFlow() {
  return (
    <svg viewBox="0 0 1060 334" className="h-auto w-full" role="img" aria-labelledby="flow-title flow-desc">
      <title id="flow-title">Citadel architecture</title>
      <desc id="flow-desc">
        The analyst picks a task; the model-free orchestrator signs an authorization context. The Investigator reads logs,
        where attacker text arrives, and hands typed data to the Responder through a signed handoff. The data stays
        untrusted, and the Responder checks every action for integrity, authorization, intent, and evidence before the
        mock tools run it.
      </desc>
      <defs>
        {(["accent", "untrusted", "neutral"] as const).map((t) => (
          <marker key={t} id={`arrow-${t}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" fill={t === "accent" ? "var(--accent)" : t === "untrusted" ? "var(--untrusted)" : "var(--axis)"} />
          </marker>
        ))}
      </defs>

      <Box x={10} y={150} w={118} h={58} title="Analyst" sub="picks a catalog task" />
      <Box x={168} y={150} w={150} h={58} title="Orchestrator" sub="no model · signs authority" tone="accent" />
      <Box x={378} y={8} w={164} h={52} title="Attacker" sub="writes text into logs" tone="untrusted" />

      <Box x={362} y={118} w={196} h={124} title="Investigator" sub="logs.read + one handoff" />
      <Pill x={376} y={174} label="planner · trusted input" tone="neutral" />
      <Pill x={376} y={202} label="processor · no tools" tone="untrusted" />

      <Box x={598} y={140} w={156} h={78} title="Signed handoff" sub="Ed25519 · exact bytes" tone="accent" />
      <text x={612} y={203} className="fill-untrusted-ink font-mono text-[10px]">
        data arrives untrusted
      </text>

      <Box x={794} y={96} w={256} h={168} title="Responder" sub="effective = static ∩ grant ∩ task" />
      <Pill x={808} y={150} label="integrity" tone="accent" />
      <Pill x={886} y={150} label="authorization" tone="accent" />
      <Pill x={808} y={176} label="intent" tone="accent" />
      <Pill x={866} y={176} label="evidence" tone="accent" />
      <Pill x={808} y={212} label="admit · budgets · once" tone="neutral" />

      <Box x={834} y={276} w={176} h={50} title="Mock tools" sub="idempotent · no real systems" />

      <Edge d="M128 179 H164" tone="neutral" />
      <Edge d="M318 179 H358" tone="accent" />
      <text x={243} y={232} textAnchor="middle" className="fill-accent-ink font-mono text-[10px]">
        signed context
      </text>
      <Edge d="M243 150 C243 70 700 60 860 94" tone="accent" />
      <text x={700} y={58} textAnchor="middle" className="fill-accent-ink font-mono text-[10px]">
        the same context, embedded in the handoff
      </text>
      <Edge d="M460 60 V114" tone="untrusted" />
      <Edge d="M558 180 H594" tone="untrusted" />
      <Edge d="M754 180 H790" tone="untrusted" />
      <Edge d="M922 264 V272" tone="accent" />
    </svg>
  );
}
