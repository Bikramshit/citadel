import type { ComponentProps, ReactNode } from "react";
import { CircleAlert, Inbox } from "lucide-react";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

export function Card({ className, ...p }: ComponentProps<"section">) {
  return (
    <section
      className={cx("sheen rounded-2xl border border-line bg-surface shadow-card", className)}
      {...p}
    />
  );
}

export function CardHeader({
  title,
  subtitle,
  icon,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b border-line px-5 py-4">
      <div className="flex min-w-[min(100%,16rem)] flex-1 items-start gap-3">
        {icon && (
          <span className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-lg bg-surface-2 text-ink-2 ring-1 ring-line">
            {icon}
          </span>
        )}
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold tracking-tight text-ink">{title}</h2>
          {subtitle && <p className="mt-0.5 text-[13px] leading-snug text-ink-2">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}

export function PageHeader({
  eyebrow,
  title,
  lead,
  actions,
}: {
  eyebrow: string;
  title: ReactNode;
  lead?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-6 pb-8">
      <div className="max-w-3xl">
        <p className="font-mono text-[11px] font-medium uppercase tracking-[0.18em] text-accent-ink">{eyebrow}</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-ink md:text-[34px] md:leading-[1.15]">{title}</h1>
        {lead && <p className="mt-3 text-[15px] leading-relaxed text-ink-2">{lead}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Button({
  variant = "secondary",
  className,
  ...p
}: ComponentProps<"button"> & { variant?: "primary" | "secondary" | "ghost" | "danger" }) {
  const styles = {
    primary: "bg-accent text-white hover:brightness-110 shadow-[0_6px_18px_-8px_var(--accent)]",
    secondary: "bg-surface text-ink ring-1 ring-line-strong hover:bg-surface-2",
    ghost: "text-ink-2 hover:bg-surface-2 hover:text-ink",
    danger: "bg-surface text-critical-ink ring-1 ring-line-strong hover:bg-surface-2",
  }[variant];
  return (
    <button
      className={cx(
        "inline-flex h-9 items-center justify-center gap-2 rounded-lg px-3.5 text-[13px] font-medium transition disabled:cursor-not-allowed disabled:opacity-50",
        styles,
        className,
      )}
      {...p}
    />
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: ReactNode }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-lg bg-surface-2 p-0.5 ring-1 ring-line">
      {options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={o.value === value}
          onClick={() => onChange(o.value)}
          className={cx(
            "h-8 rounded-md px-3 text-[13px] font-medium transition",
            o.value === value ? "bg-surface text-ink shadow-card ring-1 ring-line" : "text-ink-2 hover:text-ink",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Select({ label, className, children, ...p }: ComponentProps<"select"> & { label: string }) {
  return (
    <label className={cx("inline-flex min-w-0 max-w-full items-center gap-2 text-[13px] text-ink-2", className)}>
      <span className="shrink-0 font-medium">{label}</span>
      <select
        className="h-9 min-w-0 max-w-[22rem] flex-1 truncate rounded-lg bg-surface px-3 pr-8 text-[13px] text-ink ring-1 ring-line-strong outline-none focus:ring-accent"
        {...p}
      >
        {children}
      </select>
    </label>
  );
}

export function Mono({ className, ...p }: ComponentProps<"span">) {
  return <span className={cx("font-mono text-[12px]", className)} {...p} />;
}

export function Tag({ className, ...p }: ComponentProps<"span">) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded-md bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-2 ring-1 ring-line",
        className,
      )}
      {...p}
    />
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <span className="grid size-10 place-items-center rounded-full bg-surface-2 text-muted ring-1 ring-line">
        <Inbox size={18} />
      </span>
      <p className="text-[14px] font-medium text-ink">{title}</p>
      {children && <div className="max-w-md text-[13px] leading-relaxed text-ink-2">{children}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: Error }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-line bg-surface p-4 text-[13px]" role="alert">
      <CircleAlert size={18} className="mt-0.5 shrink-0 text-critical" aria-hidden />
      <div>
        <p className="font-medium text-ink">Cannot reach the Citadel dashboard service</p>
        <p className="mt-1 text-ink-2">{error.message}</p>
        <p className="mt-2 text-ink-2">
          Start it with <code className="rounded bg-surface-2 px-1 font-mono">make dash</code> (it listens on
          127.0.0.1:8080), or set <code className="rounded bg-surface-2 px-1 font-mono">CITADEL_URL</code>.
        </p>
      </div>
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("animate-pulse rounded-lg bg-surface-2", className)} />;
}
