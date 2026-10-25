// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Locks the cross-client wire format.
 *
 * This is the contract both clients must agree on, and breaking it fails
 * silently: the ratchet still decrypts, and the message merely renders as
 * "[Unable to decrypt message]" on the other side. These assertions are
 * transcribed from the web client's own send and receive paths
 * (app/(authenticated)/chat/[id]/page.tsx builds the object, and
 * hooks/useMessengerSync.ts reads `decoded.content` / `decoded.timestamp`).
 */

import { describe, it, expect } from 'vitest'
import { encodeWirePayload, decodeWirePayload } from '@/lib/wirePayload'

describe('wire payload — cross-client contract', () => {
  it('emits exactly the JSON shape the web client parses', () => {
    const raw = encodeWirePayload('привет', 1_700_000_000_000)
    expect(JSON.parse(raw)).toEqual({ content: 'привет', timestamp: 1_700_000_000_000 })
  })

  it('is NOT wrapped in the nacl-box envelope from lib/messagePayload', () => {
    // That module exists for the web's tests only. If this ever starts holding
    // `v`/`alg`/`ciphertext`, every message becomes unreadable on the web.
    const parsed = JSON.parse(encodeWirePayload('hi', 1)) as Record<string, unknown>
    expect(parsed.alg).toBeUndefined()
    expect(parsed.ciphertext).toBeUndefined()
    expect(parsed.v).toBeUndefined()
  })

  it('reads a payload produced by the web client', () => {
    // Exactly what the web emits, including the fields this client ignores.
    const fromWeb = JSON.stringify({
      content: 'из веба',
      timestamp: 1_700_000_000_001,
      selfDestruct: null,
      replyTo: { id: 'x', content: 'y' },
      attachment: { fileId: 'f', size: 10 },
    })
    const decoded = decodeWirePayload(fromWeb)
    expect(decoded?.content).toBe('из веба')
    expect(decoded?.timestamp).toBe(1_700_000_000_001)
  })

  it('round-trips its own output', () => {
    const decoded = decodeWirePayload(encodeWirePayload('туда-обратно', 42))
    expect(decoded).toMatchObject({ content: 'туда-обратно', timestamp: 42 })
  })

  it('carries a group id through when present', () => {
    const decoded = decodeWirePayload(JSON.stringify({ content: 'g', timestamp: 1, groupId: 'gid' }))
    expect(decoded?.groupId).toBe('gid')
  })

  it('fails closed on anything unreadable', () => {
    expect(decodeWirePayload('not json')).toBeNull()
    expect(decodeWirePayload('null')).toBeNull()
    expect(decodeWirePayload('[]')).toBeNull()
    expect(decodeWirePayload(JSON.stringify({ timestamp: 1 }))).toBeNull()
    expect(decodeWirePayload(JSON.stringify({ content: 42, timestamp: 1 }))).toBeNull()
  })

  it('tolerates a missing timestamp rather than dropping the message', () => {
    const decoded = decodeWirePayload(JSON.stringify({ content: 'no ts' }))
    expect(decoded?.content).toBe('no ts')
    expect(typeof decoded?.timestamp).toBe('number')
  })
})
