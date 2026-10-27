import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleHelp,
  CircleX,
  FlaskConical,
  Hourglass,
  LockOpen,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { useId } from "react";
import type { AttemptState, Verdict } from "@/lib/types";
import { clip, sourceKind, sourceTrusted, visible } from "@/lib/derive";
import { cx } from "./ui";

// Status colors always travel with an icon and a word, never alone.
const verdictStyle: Record<Verdict, { icon: typeof CircleCheck; cls: string; label: string }> = {
  allow: { icon: CircleCheck, cls: "text-good-ink bg-good/10 ring-good/30", label: "Allow" },
  escalate: { icon: TriangleAlert, cls: "text-warning-ink bg-warning/15 ring-warning/40", label: "Escalate" },
  deny: { icon: Ban, cls: "text-critical-ink bg-critical/10 ring-critical/30", label: "Deny" },
};

export function VerdictBadge({ verdict, rule, size = "md" }: { verdict?: Verdict; rule?: string; size?: "sm" | "md" }) {
  if (!verdict) return null;
  const s = verdictStyle[verdict];
  const Icon = s.icon;
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded-full font-medium ring-1",
        size === "sm" ? "px-1.5 py-0.5 text-[11px]" : "px-2 py-0.5 text-[12px]",
        s.cls,
      )}
    >
      <Icon size={size === "sm" ? 12 : 13} aria-hidden />
      {s.label}
      {rule && <span className="font-mono opacity-80">· {rule}</span>}
    </span>
  );
}

const outcomeStyle: Record<AttemptState, { icon: typeof CircleCheck; cls: string; label: string }> = {
  succeeded: { icon: CircleCheck, cls: "text-good-ink", label: "Succeeded" },
  failed: { icon: CircleX, cls: "text-critical-ink", label: "Failed" },
  // An uncertain outcome is never shown as denied or failed.
  uncertain: { icon: CircleHelp, cls: "text-warning-ink", label: "Executed; runtime outcome unconfirmed" },
  attempted: { icon: Hourglass, cls: "text-ink-2", label: "Attempted" },
};

export function OutcomeBadge({ state, reconciled }: { state?: AttemptState; reconciled?: boolean }) {
  if (!state) {
    return (
      <span className="inline-flex items-center gap-1 text-[12px] text-muted">
        <CircleDashed size={13} aria-hidden /> Not executed
      </span>
    );
  }
  const s = outcomeStyle[state];
  const Icon = s.icon;
  return (
    <span className={cx("inline-flex items-center gap-1 text-[12px] font-medium", s.cls)}>
      <Icon size={13} aria-hidden />
      {s.label}
      {reconciled && <span className="font-normal text-ink-2">(after lookup)</span>}
    </span>
  );
}

export function SourceChip({ source }: { source: string }) {
  const trusted = sourceTrusted(source);
  const kind = sourceKind(source);
  const Icon = trusted ? ShieldCheck : LockOpen;
  return (
    <span
      title={`${trusted ? "Trusted" : "Untrusted"} source: ${source}`}
      className={cx(
        "inline-flex max-w-full items-center gap-1 rounded-md px-1.5 py-0.5 font-mono text-[11px] ring-1",
        trusted ? "bg-accent-soft text-accent-ink ring-accent/25" : "bg-untrusted-soft text-untrusted-ink ring-untrusted/30",
      )}
    >
      <Icon size={11} aria-hidden className="shrink-0" />
      <span className="truncate">{kind === "peer" ? `peer:${source.split(":")[1]?.split("/")[0]}` : source}</span>
    </span>
  );
}

export function Sources({ sources, max = 4 }: { sources?: string[] | null; max?: number }) {
  // Untrusted sources lead: they are what makes a value untrusted.
  const list = [...(sources ?? [])].sort((a, b) => Number(sourceTrusted(a)) - Number(sourceTrusted(b)));
  if (!list.length) return <span className="text-[12px] text-muted">no sources</span>;
  const shown = list.slice(0, max);
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((s) => (
        <SourceChip key={s} source={s} />
      ))}
      {list.length > max && (
        <span className="rounded-md px-1 text-[11px] text-muted" title={list.slice(max).join("\n")}>
          +{list.length - max}
        </span>
      )}
    </span>
  );
}

export function TrustDot({ trusted }: { trusted: boolean | undefined }) {
  if (trusted === undefined) return null;
  return (
    <span className="inline-flex items-center gap-1 text-[12px] text-ink-2">
      <span className={cx("size-2 rounded-full", trusted ? "bg-accent" : "bg-untrusted")} aria-hidden />
      {trusted ? "trusted" : "untrusted"}
    </span>
  );
}

const configText: Record<string, string> = {
  C0: "No runtime: ordinary tool calling",
  "C1-instr": "Free-text report, read as the analyst's request",
  "C1-data": "Free-text report, read as untrusted data",
  C2: "Typed, signed handoff (Citadel)",
};

export function ConfigChip({ config, emphasized }: { config: string; emphasized?: boolean }) {
  return (
    <span
      title={configText[config]}
      className={cx(
        "inline-flex items-center whitespace-nowrap rounded-md px-1.5 py-0.5 font-mono text-[11px] font-medium ring-1",
        emphasized || config === "C2" ? "bg-accent-soft text-accent-ink ring-accent/30" : "bg-surface-2 text-ink-2 ring-line",
      )}
    >
      {config}
    </span>
  );
}

export function configDescription(config: string): string {
  return configText[config] ?? config;
}

/** Attacker-controlled text, shown inert: truncated, control characters made visible. */
export function Untrusted({ text, n = 96, className }: { text: string; n?: number; className?: string }) {
  return (
    <span title={text} className={cx("break-all font-mono text-[12px]", className)}>
      {clip(visible(text), n)}
    </span>
  );
}

export function ImplBanner({ impl }: { impl?: string }) {
  if (!impl) return null;
  if (impl === "model") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-accent-soft px-2.5 py-1 text-[12px] font-medium text-accent-ink ring-1 ring-accent/25">
        Model runs
      </span>
    );
  }
  return (
    <span
      title="Every model role was a deterministic worst-case stand-in. These are not measurements of any model."
      className="inline-flex items-center gap-1.5 rounded-full bg-surface-2 px-2.5 py-1 text-[12px] font-medium text-ink-2 ring-1 ring-line"
    >
      <FlaskConical size={13} aria-hidden /> Deterministic · scripted stand-ins
    </span>
  );
}

export function Logo({ className }: { className?: string }) {
  // A battlement over a keyhole: the citadel, and the signed boundary. Each
  // instance needs its own gradient id: a shared one resolves to the first
  // copy in the document, which may sit in a hidden sidebar and not render.
  const id = useId();
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--accent)" />
          <stop offset="1" stopColor="var(--accent-ink)" />
        </linearGradient>
      </defs>
      <path
        d="M5 6h4v3h3V6h3v3h2V6h3v3h3V6h4v11c0 6-5.2 9.7-11 11.5C10.2 26.7 5 23 5 17V6z"
        fill={`url(#${id})`}
      />
      <circle cx="16" cy="16" r="2.6" fill="var(--surface)" />
      <path d="M14.7 17.5h2.6l.9 5h-4.4z" fill="var(--surface)" />
    </svg>
  );
}
