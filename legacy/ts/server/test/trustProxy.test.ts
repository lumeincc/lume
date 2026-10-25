// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The trusted-hop count decides which `X-Forwarded-For` entry every rate limiter
 * buckets on, so it is worth more tests than its size suggests.
 *
 * Both ways of getting it wrong are silent:
 *   too high — the server reads into entries the caller wrote, so each request
 *              lands in a fresh bucket and no limit ever fires;
 *   too low  — the server reads a proxy address, so everyone shares one bucket
 *              and the limiter denies service to all of them at once.
 *
 * The value used to be a duplicated constant in two files kept in step by a
 * comment. These tests exist because the deployment shape is about to change:
 * putting Cloudflare in front of Render adds a hop.
 */

import { describe, it, expect } from 'vitest'
import { parseTrustProxyHops, getTrustedProxyHops } from '../src/utils/trustProxy'

describe('parseTrustProxyHops', () => {
  it('treats an unset value as trusting nothing', () => {
    // Local development talks to the socket directly; trusting a forwarded
    // header there would let any caller pick their own rate-limit bucket.
    expect(parseTrustProxyHops(undefined)).toEqual({ ok: true, hops: 0 })
    expect(parseTrustProxyHops('')).toEqual({ ok: true, hops: 0 })
  })

  it('keeps the legacy boolean spellings production is configured with', () => {
    // Renaming these to numbers-only would silently drop proxy trust in prod,
    // which is the "everyone in one bucket" failure.
    expect(parseTrustProxyHops('true')).toEqual({ ok: true, hops: 1 })
    expect(parseTrustProxyHops('TRUE')).toEqual({ ok: true, hops: 1 })
    expect(parseTrustProxyHops('false')).toEqual({ ok: true, hops: 0 })
    expect(parseTrustProxyHops('0')).toEqual({ ok: true, hops: 0 })
  })

  it('accepts a hop count, which is what a Cloudflare front needs', () => {
    expect(parseTrustProxyHops('1')).toEqual({ ok: true, hops: 1 }) // Render alone
    expect(parseTrustProxyHops('2')).toEqual({ ok: true, hops: 2 }) // Cloudflare → Render
    expect(parseTrustProxyHops(' 3 ')).toEqual({ ok: true, hops: 3 })
  })

  it('refuses a value it cannot parse instead of defaulting to zero', () => {
    // A silent fallback to 0 would look like the limiter working, right up
    // until it rate-limited every user together.
    for (const bad of ['yes', 'one', '1.5', '-1', 'null', 'on']) {
      const result = parseTrustProxyHops(bad)
      expect(result.ok, `expected '${bad}' to be refused`).toBe(false)
      expect(result.reason).toBeTruthy()
    }
  })

  it('refuses an implausibly deep chain', () => {
    const result = parseTrustProxyHops('11')
    expect(result.ok).toBe(false)
    expect(result.reason).toContain('maximum')
  })
})

describe('getTrustedProxyHops', () => {
  it('reads TRUST_PROXY', () => {
    expect(getTrustedProxyHops({ TRUST_PROXY: '2' } as NodeJS.ProcessEnv)).toBe(2)
  })

  it('still honours WS_TRUST_PROXY alone', () => {
    // Only the WebSocket handler read this one. A deployment that sets just it
    // must not lose proxy trust now that both paths share this function.
    expect(getTrustedProxyHops({ WS_TRUST_PROXY: 'true' } as NodeJS.ProcessEnv)).toBe(1)
  })

  it('prefers TRUST_PROXY when both are set', () => {
    expect(
      getTrustedProxyHops({ TRUST_PROXY: '2', WS_TRUST_PROXY: '1' } as NodeJS.ProcessEnv)
    ).toBe(2)
  })

  it('trusts nothing when neither is set', () => {
    expect(getTrustedProxyHops({} as NodeJS.ProcessEnv)).toBe(0)
  })
})
