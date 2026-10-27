"use client";

import { useEffect, useRef, useState, type CSSProperties, type PointerEvent, type ReactNode } from "react";
import { motion, useMotionValue, useReducedMotion, useSpring, useTransform } from "motion/react";
import { cx } from "./ui";

const SPRING = { stiffness: 220, damping: 22, mass: 0.6 };

/** Whether the device has a precise pointer that can hover (not touch). */
function useFinePointer(): boolean {
  const [fine, setFine] = useState(false);
  useEffect(() => {
    const m = window.matchMedia("(hover: hover) and (pointer: fine)");
    const sync = () => setFine(m.matches);
    sync();
    m.addEventListener("change", sync);
    return () => m.removeEventListener("change", sync);
  }, []);
  return fine;
}

/**
 * A card that leans toward the pointer in 3D, with a glare and a lit border
 * that follow it. Children marked `depth-1` or `depth-2` float above the face
 * while it tilts, if every element between them and the card keeps
 * `tilt-face` (preserve-3d) and none clips with overflow. `stack` draws two
 * sheets behind the card. Decorative only: off for touch input and for
 * reduced motion.
 */
export function Tilt({
  children,
  className,
  max = 7,
  radius = "1rem",
  stack,
}: {
  children: ReactNode;
  className?: string;
  /** Largest lean, in degrees. Keep it small for large cards. */
  max?: number;
  radius?: string;
  stack?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const fine = useFinePointer();
  const on = fine && !reduce;
  const px = useMotionValue(0);
  const py = useMotionValue(0);
  const rotateX = useSpring(useTransform(py, [-0.5, 0.5], [max, -max]), SPRING);
  const rotateY = useSpring(useTransform(px, [-0.5, 0.5], [-max, max]), SPRING);

  const move = (e: PointerEvent<HTMLDivElement>) => {
    const el = ref.current;
    if (!on || !el) return;
    // The outer box never transforms, so its rectangle is stable while the body leans.
    const r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width;
    const y = (e.clientY - r.top) / r.height;
    px.set(x - 0.5);
    py.set(y - 0.5);
    el.style.setProperty("--gx", `${(x * 100).toFixed(1)}%`);
    el.style.setProperty("--gy", `${(y * 100).toFixed(1)}%`);
  };
  const leave = () => {
    px.set(0);
    py.set(0);
  };

  return (
    <div
      ref={ref}
      data-tilt={on ? "" : undefined}
      onPointerMove={move}
      onPointerLeave={leave}
      className={cx("tilt", className)}
      style={{ "--tilt-radius": radius } as CSSProperties}
    >
      <motion.div style={on ? { rotateX, rotateY } : undefined} className="tilt-body relative h-full">
        {stack && (
          <>
            <span aria-hidden className="tilt-layer tilt-layer-2" />
            <span aria-hidden className="tilt-layer tilt-layer-1" />
          </>
        )}
        <div className="tilt-face relative h-full">{children}</div>
        <span aria-hidden className="tilt-glare" />
        <span aria-hidden className="tilt-spot" />
      </motion.div>
    </div>
  );
}
