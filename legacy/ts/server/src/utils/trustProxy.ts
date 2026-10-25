// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * How many proxy hops in front of this server are trusted.
 *
 * This number decides which entry of `X-Forwarded-For` is treated as the
 * caller, and therefore which key every rate limiter buckets on. Getting it
 * wrong is not a small misconfiguration — it breaks the limiters in one of two
 * directions, and both are silent:
 *
 *   - **too high** — the server reads further left than the trusted chain
 *     reaches, into entries the client wrote itself. A caller sending
 *     `X-Forwarded-For: <random>` lands in a fresh bucket on every request and
 *     no limit ever fires, while the limiter still looks enforced. This is
 *     exactly the bug SEC-20260721-004 fixed on the WebSocket path.
 *   - **too low** — the server reads an address belonging to the proxy, so
 *     every caller in the world shares one bucket. The limiter then works
 *     perfectly and denies service to everybody at once.
 *
 * It lives in its own module because `index.ts` and `websocket/handler.ts` must
 * agree on it. They used to agree by a comment and a duplicated constant; the
 * comment was right, but nothing made it stay right. Deployments change the
 * chain — putting Cloudflare in front of Render adds a hop — and a value that
 * has to be edited in two files is a value that will one day be edited in one.
 *
 * `TRUST_PROXY` accepts:
 *   unset / '0' / 'false'  → 0, no proxy trusted (local development)
 *   '1' / 'true'           → 1 hop  (Render alone — the current production shape)
 *   '2'                    → 2 hops (Cloudflare in front of Render)
 *   any other integer 0–10
 *
 * The legacy boolean spellings are kept because production is configured with
 * them today, and a rename that silently turns trust off would be the "too low"
 * failure above.
 */

/** Upper bound. A chain deeper than this is a misconfiguration, not a topology. */
const MAX_TRUSTED_HOPS = 10

export interface TrustProxyResult {
  ok: boolean
  hops: number
  reason?: string
}

/**
 * Parses the configured hop count. Returns `ok: false` with a reason rather than
 * throwing, so the caller decides whether to refuse to boot — an invalid value
 * must never quietly become a default.
 */
export function parseTrustProxyHops(raw: string | undefined): TrustProxyResult {
  if (raw === undefined || raw === '') return { ok: true, hops: 0 }

  const normalised = raw.trim().toLowerCase()

  if (normalised === 'false' || normalised === '0') return { ok: true, hops: 0 }
  if (normalised === 'true') return { ok: true, hops: 1 }

  if (!/^\d+$/.test(normalised)) {
    return {
      ok: false,
      hops: 0,
      reason: `TRUST_PROXY must be a whole number of proxy hops (or true/false), got '${raw}'`,
    }
  }

  const hops = Number.parseInt(normalised, 10)
  if (hops > MAX_TRUSTED_HOPS) {
    return {
      ok: false,
      hops: 0,
      reason: `TRUST_PROXY of ${hops} exceeds the maximum of ${MAX_TRUSTED_HOPS}; a chain that deep is a misconfiguration`,
    }
  }

  return { ok: true, hops }
}

/**
 * The hop count for this process. Reads the same variables the WebSocket path
 * historically accepted so an existing deployment keeps working.
 */
export function getTrustedProxyHops(env: NodeJS.ProcessEnv = process.env): number {
  const primary = parseTrustProxyHops(env.TRUST_PROXY)
  if (primary.hops > 0) return primary.hops

  // `WS_TRUST_PROXY` was accepted by the WebSocket handler alone. Kept so a
  // deployment setting only that one does not silently lose proxy trust when
  // both paths start reading the same function.
  return parseTrustProxyHops(env.WS_TRUST_PROXY).hops
}
