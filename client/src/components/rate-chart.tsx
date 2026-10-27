"use client";

import { useLayoutEffect, useRef, useState } from "react";
import type { Rate } from "@/lib/types";
import { fmtCI, fmtRate, ratePct } from "@/lib/derive";
import { configDescription } from "./badges";
import { cx } from "./ui";

export interface RatePoint {
  label: string;
  rate: Rate;
  emphasized?: boolean;
}

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.getBoundingClientRect().width); // draw on first paint; the observer handles resizes
    const ro = new ResizeObserver(([entry]) => entry && setWidth(entry.contentRect.width));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return { ref, width };
}

const ROW = 38;
const LABEL_W = 78;
const VALUE_W = 92;
const TOP = 6;
const AXIS = 24;

/**
 * A rate per category as one point with its 95% Wilson interval as a
 * whisker. One series: the emphasized category takes the accent, the rest
 * the muted mark color. Every value is also in the table view.
 */
export function RateChart({ points, title, better }: { points: RatePoint[]; title: string; better: "lower" | "higher" }) {
  const { ref, width } = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const plotW = Math.max(120, width - LABEL_W - VALUE_W);
  const x = (v: number) => LABEL_W + v * plotW;
  const height = TOP + points.length * ROW + AXIS;
  const ticks = [0, 0.25, 0.5, 0.75, 1];
  const hovered = hover === null ? undefined : points[hover];
  return (
    <figure className="relative" aria-label={title}>
      <div ref={ref} className="w-full">
        {width > 0 && (
          <svg width={width} height={height} role="img" aria-label={`${title}, ${better} is better`}>
            {ticks.map((t) => (
              <g key={t}>
                <line x1={x(t)} x2={x(t)} y1={TOP} y2={TOP + points.length * ROW} stroke="var(--grid)" strokeWidth={1} />
                <text
                  x={x(t)}
                  y={TOP + points.length * ROW + 16}
                  textAnchor="middle"
                  className="tabular fill-muted text-[11px]"
                >
                  {Math.round(t * 100)}%
                </text>
              </g>
            ))}
            {points.map((p, i) => {
              const cy = TOP + i * ROW + ROW / 2;
              const color = p.emphasized ? "var(--accent)" : "var(--mark-muted)";
              const has = p.rate.n > 0;
              const value = has ? p.rate.k / p.rate.n : 0;
              return (
                <g
                  key={p.label}
                  tabIndex={0}
                  role="listitem"
                  aria-label={`${p.label}: ${fmtRate(p.rate)}, ${Math.round(ratePct(p.rate))} percent, 95% interval ${fmtCI(p.rate)}`}
                  onPointerEnter={() => setHover(i)}
                  onPointerLeave={() => setHover(null)}
                  onFocus={() => setHover(i)}
                  onBlur={() => setHover(null)}
                  className="outline-none"
                >
                  <rect x={0} y={cy - ROW / 2} width={width} height={ROW} fill={hover === i ? "var(--surface-2)" : "transparent"} rx={6} />
                  <text x={0} y={cy + 4} className={cx("font-mono text-[12px]", p.emphasized ? "fill-ink font-semibold" : "fill-ink-2")}>
                    {p.label}
                  </text>
                  {has && (
                    <>
                      <line
                        x1={x(p.rate.lo)}
                        x2={x(p.rate.hi)}
                        y1={cy}
                        y2={cy}
                        stroke={color}
                        strokeWidth={2}
                        strokeLinecap="round"
                        opacity={p.emphasized ? 0.55 : 0.9}
                      />
                      <line x1={x(p.rate.lo)} x2={x(p.rate.lo)} y1={cy - 5} y2={cy + 5} stroke={color} strokeWidth={2} strokeLinecap="round" opacity={p.emphasized ? 0.55 : 0.9} />
                      <line x1={x(p.rate.hi)} x2={x(p.rate.hi)} y1={cy - 5} y2={cy + 5} stroke={color} strokeWidth={2} strokeLinecap="round" opacity={p.emphasized ? 0.55 : 0.9} />
                      <circle cx={x(value)} cy={cy} r={6} fill={color} stroke="var(--surface)" strokeWidth={2} />
                    </>
                  )}
                  <text x={width - VALUE_W + 12} y={cy + 4} className="tabular fill-ink-2 text-[12px]">
                    {has ? (
                      <>
                        <tspan className={p.emphasized ? "fill-ink font-semibold" : "fill-ink"}>{Math.round(ratePct(p.rate))}%</tspan>
                        <tspan className="fill-muted"> · {fmtRate(p.rate)}</tspan>
                      </>
                    ) : (
                      "n = 0"
                    )}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>
      {hovered && hover !== null && hovered.rate.n > 0 && (
        <div
          className="pointer-events-none absolute z-10 w-56 -translate-x-1/2 rounded-xl border border-line bg-surface p-3 text-[12px] shadow-card"
          style={{
            left: Math.min(Math.max(x(hovered.rate.k / hovered.rate.n), 112), Math.max(112, width - 112)),
            top: TOP + hover * ROW + ROW + 2,
          }}
        >
          <p className="text-[18px] font-semibold text-ink">
            {Math.round(ratePct(hovered.rate))}%{" "}
            <span className="text-[12px] font-normal text-ink-2">
              {hovered.rate.k} of {hovered.rate.n} runs
            </span>
          </p>
          <p className="mt-1 text-ink-2">
            95% Wilson interval <span className="tabular text-ink">{fmtCI(hovered.rate)}</span>
          </p>
          <p className="mt-1.5 flex items-center gap-1.5 text-muted">
            <span className="h-0.5 w-3 rounded" style={{ background: hovered.emphasized ? "var(--accent)" : "var(--mark-muted)" }} />
            <span className="font-mono">{hovered.label}</span> · {configDescription(hovered.label)}
          </p>
        </div>
      )}
    </figure>
  );
}
