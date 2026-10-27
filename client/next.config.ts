import type { NextConfig } from "next";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants";

// The client renders attacker-written log text, so it ships a strict policy:
// same-origin everything, no framing. Next's runtime needs inline scripts
// (and eval and a websocket only in development, for fast refresh).
const csp = (isDev: boolean) => [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self'${isDev ? " ws://127.0.0.1:* ws://localhost:*" : ""}`,
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join("; ");

const config = (phase: string): NextConfig => ({
  reactStrictMode: true,
  poweredByHeader: false,
  // Server-sent events from citadel dash pass through the API proxy; response
  // compression would buffer them.
  compress: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp(phase === PHASE_DEVELOPMENT_SERVER) },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
});

export default config;
