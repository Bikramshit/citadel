import type { RunDir, Row } from "./types";

/** The newest run directory that ran every configuration with evidence rules on. */
export function mainDir(dirs: RunDir[]): RunDir | undefined {
  const full = dirs.filter((d) => (d.meta.configs ?? []).length >= 4 && (d.meta.evidence || "on") === "on");
  return newest(full) ?? newest(dirs);
}

export function newest(dirs: RunDir[]): RunDir | undefined {
  return [...dirs].sort((a, b) => b.meta.started.localeCompare(a.meta.started))[0];
}

/** Rows of the directory's first implementation (a directory holds one). */
export function rowsOf(dir: RunDir | undefined): Row[] {
  return dir?.summary?.[0]?.rows ?? [];
}

export function implOf(dir: RunDir | undefined): string | undefined {
  return dir?.summary?.[0]?.impl ?? dir?.meta.impl;
}

export function dirLabel(d: RunDir): string {
  const ev = d.meta.evidence && d.meta.evidence !== "on" ? ` · evidence ${d.meta.evidence}` : "";
  const configs = (d.meta.configs ?? []).join(", ");
  return `${d.meta.started.slice(0, 16).replace("T", " ")} · ${configs}${ev} · ${d.meta.runs} runs`;
}
