// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import type { NextConfig } from "next";
import withBundleAnalyzer from "@next/bundle-analyzer";

const analyze = withBundleAnalyzer({
  enabled: process.env.ANALYZE === "true",
});

const isDev = process.env.NODE_ENV !== "production";

/**
 * Build identity, baked into the bundle.
 *
 * The commit is what actually identifies a build — the version string sat at
 * 0.1.0 through dozens of shipped commits — so it is read from whichever
 * variable the builder provides. Vercel sets VERCEL_GIT_COMMIT_SHA; GitHub
 * Actions sets GITHUB_SHA; a laptop sets neither and gets "dev", which is the
 * honest answer for a build nobody can trace.
 */
const buildEnv = {
  NEXT_PUBLIC_BUILD_VERSION: process.env.npm_package_version || "0.0.0",
  NEXT_PUBLIC_BUILD_COMMIT:
    process.env.NEXT_PUBLIC_BUILD_COMMIT ||
    process.env.VERCEL_GIT_COMMIT_SHA ||
    process.env.GITHUB_SHA ||
    "dev",
  NEXT_PUBLIC_BUILD_TIME: new Date().toISOString(),
};

const nextConfig: NextConfig = {
  env: buildEnv,
  ...(process.env.STANDALONE === "1" && { output: "standalone" }),
  turbopack: {
    resolveAlias: {
      '@noble/hashes/hmac': '@noble/hashes/hmac.js',
      '@noble/hashes/sha256': '@noble/hashes/sha2.js',
      '@noble/hashes/hkdf': '@noble/hashes/hkdf.js',
    },
  },

  // Suppress React DevTools warning in production
  reactStrictMode: true,

  // Disable x-powered-by header
  poweredByHeader: false,

  // Security headers
  headers: async () => {
    const securityHeaders = [
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" },
      { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
      {
        key: "Content-Security-Policy",
        value: [
          "default-src 'self'",
          `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' blob: data:",
          "connect-src 'self' ws: wss: http://localhost:* https://*",
          "font-src 'self'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
          "frame-ancestors 'none'",
          "worker-src 'self' blob:",
        ].join("; "),
      },
    ];

    if (isDev) {
      securityHeaders.push({ key: "Cache-Control", value: "no-store, must-revalidate" });
    }

    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

export default analyze(nextConfig);
