"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { GitCompareArrows, Grid3x3, LayoutDashboard, Monitor, Moon, Radio, ScrollText, Sun } from "lucide-react";
import { fetchFixtures, useLoad } from "@/lib/api";
import { Logo } from "./badges";
import { cx } from "./ui";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/results", label: "Results", icon: ScrollText },
  { href: "/runs", label: "Runs", icon: Grid3x3 },
  { href: "/compare", label: "Compare", icon: GitCompareArrows },
  { href: "/live", label: "Live", icon: Radio },
];

type Theme = "light" | "dark" | "system";

function applyTheme(t: Theme) {
  const dark = t === "dark" || (t === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

function ThemeSwitch() {
  const [theme, setTheme] = useState<Theme>("system");
  useEffect(() => {
    let saved: Theme = "system";
    try {
      saved = (localStorage.getItem("citadel-theme") as Theme | null) ?? "system";
    } catch {
      // storage can be unavailable; the system theme applies
    }
    setTheme(saved);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      let t: Theme = "system";
      try {
        t = (localStorage.getItem("citadel-theme") as Theme | null) ?? "system";
      } catch {}
      if (t === "system") applyTheme("system");
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  const set = (t: Theme) => {
    setTheme(t);
    try {
      localStorage.setItem("citadel-theme", t);
    } catch {}
    applyTheme(t);
  };
  const opts: { t: Theme; icon: typeof Sun; label: string }[] = [
    { t: "light", icon: Sun, label: "Light theme" },
    { t: "system", icon: Monitor, label: "System theme" },
    { t: "dark", icon: Moon, label: "Dark theme" },
  ];
  return (
    <div role="radiogroup" aria-label="Theme" className="inline-flex rounded-lg bg-surface-2 p-0.5 ring-1 ring-line">
      {opts.map(({ t, icon: Icon, label }) => (
        <button
          key={t}
          role="radio"
          aria-checked={theme === t}
          aria-label={label}
          title={label}
          onClick={() => set(t)}
          className={cx(
            "grid size-7 place-items-center rounded-md transition",
            theme === t ? "bg-surface text-ink shadow-card ring-1 ring-line" : "text-muted hover:text-ink",
          )}
        >
          <Icon size={14} />
        </button>
      ))}
    </div>
  );
}

function Connection() {
  const { data, error, loading } = useLoad((s) => fetchFixtures(s));
  const state = error ? "down" : loading && !data ? "checking" : "up";
  return (
    <div className="flex items-center gap-2 rounded-lg bg-surface-2 px-2.5 py-2 text-[12px] ring-1 ring-line">
      <span className="relative flex size-2">
        {state === "up" && <span className="absolute inline-flex size-full animate-ping rounded-full bg-good opacity-50" />}
        <span
          className={cx(
            "relative inline-flex size-2 rounded-full",
            state === "up" ? "bg-good" : state === "down" ? "bg-critical" : "bg-muted",
          )}
        />
      </span>
      <span className="text-ink-2">
        citadel dash{" "}
        <span className="font-medium text-ink">
          {state === "up" ? "connected" : state === "down" ? "unreachable" : "connecting"}
        </span>
      </span>
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const active = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));
  return (
    <div className="blueprint min-h-dvh">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-line bg-surface/80 backdrop-blur-xl lg:flex">
        <Link href="/" className="flex items-center gap-2.5 px-5 pb-6 pt-6">
          <Logo className="size-8" />
          <span>
            <span className="block text-[15px] font-semibold tracking-tight text-ink">Citadel</span>
            <span className="block font-mono text-[10px] uppercase tracking-[0.16em] text-muted">Agent runtime</span>
          </span>
        </Link>
        <nav className="flex flex-col gap-0.5 px-3" aria-label="Main">
          {NAV.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              aria-current={active(href) ? "page" : undefined}
              className={cx(
                "group flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13.5px] font-medium transition",
                active(href) ? "bg-accent-soft text-accent-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink",
              )}
            >
              <Icon size={16} className={cx(active(href) ? "text-accent" : "text-muted group-hover:text-ink-2")} />
              {label}
            </Link>
          ))}
        </nav>
        <div className="mt-auto flex flex-col gap-3 p-4">
          <Connection />
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-muted">Theme</span>
            <ThemeSwitch />
          </div>
        </div>
      </aside>
      <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-line bg-surface/85 px-4 py-3 backdrop-blur-xl lg:hidden">
        <Link href="/" className="flex items-center gap-2">
          <Logo className="size-7" />
          <span className="text-[15px] font-semibold">Citadel</span>
        </Link>
        <ThemeSwitch />
      </header>
      <nav
        aria-label="Main"
        className="sticky top-[57px] z-20 flex gap-1 overflow-x-auto border-b border-line bg-surface/85 px-3 py-2 backdrop-blur-xl lg:hidden"
      >
        {NAV.map(({ href, label }) => (
          <Link
            key={href}
            href={href}
            className={cx(
              "shrink-0 rounded-md px-2.5 py-1.5 text-[13px] font-medium",
              active(href) ? "bg-accent-soft text-accent-ink" : "text-ink-2",
            )}
          >
            {label}
          </Link>
        ))}
      </nav>
      <main className="lg:pl-60">
        <div className="mx-auto max-w-[1280px] px-4 pb-24 pt-8 sm:px-6 lg:px-10 lg:pt-12">{children}</div>
      </main>
    </div>
  );
}
