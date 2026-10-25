// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Concurrent sockets are capped, per address and in total.
 *
 * The handshake limiter bounds how *fast* one address may connect — ten a
 * minute — and the per-user cap bounds how many sockets one account holds.
 * Neither bounded how many sockets one address could accumulate: at ten a
 * minute, sustained, that is six hundred held sockets an hour, and registering
 * more accounts raises the per-user ceiling rather than reaching it.
 *
 * The sockets here are *authenticated and held open*, which is the only way to
 * reach the cap at all. An earlier version of this file used nonsense tokens;
 * every socket was closed immediately on the auth failure, released its slot,
 * and the cap was never approached — the tests passed against code with no cap
 * in it. They are written this way deliberately.
 *
 * Each test claims its own address through `X-Forwarded-For` (with TRUST_PROXY
 * set), so one test cannot exhaust another's handshake budget, and the shared
 * hop-count logic gets exercised on the way.
 *
 * Production defaults are far more generous than the ones used here — 128 per
 * address — because LUME's users sit behind carrier NAT, VPNs and Tor, where
 * one address legitimately carries many people.
 */

import { createServer, type Server } from 'http'
import express from 'express'
import { WebSocketServer, WebSocket } from 'ws'
import jwt from 'jsonwebtoken'
import nacl from 'tweetnacl'
import { encodeBase64 } from 'tweetnacl-util'
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'

vi.hoisted(() => {
  process.env.DB_PATH = ':memory:'
  process.env.WS_JWT_SECRET = 'x'.repeat(40)
  process.env.SKIP_ORIGIN_CHECK = '1'
  process.env.NODE_ENV = 'test'
  // One trusted hop, so X-Forwarded-For decides the bucket and each test can
  // work from its own address.
  process.env.TRUST_PROXY = '1'
  // Small enough to reach without opening a hundred sockets in a unit test.
  process.env.WS_MAX_CONNECTIONS_PER_IP = '3'
  process.env.WS_MAX_CONNECTIONS_TOTAL = '8'
})

import { initWebSocket } from '../src/websocket/handler'
import database from '../src/db/database'

let server: Server
let wss: WebSocketServer
let port = 0

function registerUser(prefix: string): string {
  const id = crypto.randomUUID()
  const idKey = nacl.sign.keyPair()
  const spk = nacl.sign.keyPair()
  database.createUser(
    id,
    `${prefix}_${id.slice(0, 8)}`,
    encodeBase64(idKey.publicKey),
    encodeBase64(idKey.publicKey),
    encodeBase64(spk.publicKey),
    encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey))
  )
  return id
}

function makeToken(userId: string): string {
  return jwt.sign({ sub: userId }, process.env.WS_JWT_SECRET as string, {
    algorithm: 'HS256',
    expiresIn: '10m',
    issuer: 'lume',
    audience: 'lume-ws',
  })
}

interface Attempt {
  ws: WebSocket
  /** `null` when the socket opened and stayed open. */
  closeCode: number | null
}

/**
 * Opens one authenticated socket from `address` and reports how it ended up.
 *
 * A refusal arrives *after* the socket opens — the cap is enforced inside the
 * connection handler, which runs once the upgrade has completed — so 'open' is
 * not evidence of admission. The first version of this helper resolved on
 * 'open' and therefore recorded every refused socket as admitted, which is why
 * these tests passed against a cap that was working correctly.
 *
 * So admission is confirmed by using the socket: send a ping, and an admitted
 * socket answers with a pong. That is a round trip rather than a delay, so it
 * cannot go quietly wrong on a slower machine the way a timeout would.
 */
function connectFrom(address: string, prefix: string): Promise<Attempt> {
  const token = makeToken(registerUser(prefix))
  return new Promise(resolve => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, ['lume', `auth.${token}`], {
      headers: { 'X-Forwarded-For': address },
    })
    let settled = false
    const finish = (closeCode: number | null): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ ws, closeCode })
    }
    const timer = setTimeout(() => finish(null), 5000)

    ws.on('open', () => ws.send(JSON.stringify({ type: 'ping' })))
    ws.on('message', () => finish(null)) // answered ⇒ genuinely admitted
    ws.on('close', code => finish(code))
    ws.on('error', () => {
      /* a refused handshake surfaces here too; 'close' settles it */
    })
  })
}

/** Waits for a socket to actually be gone, so slot release can be observed. */
function closed(ws: WebSocket): Promise<void> {
  return new Promise(resolve => {
    if (ws.readyState === WebSocket.CLOSED) return resolve()
    ws.on('close', () => resolve())
    ws.terminate()
  })
}

beforeAll(async () => {
  const app = express()
  server = createServer(app)
  wss = new WebSocketServer({ server, path: '/ws' })
  initWebSocket(wss)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  port = (server.address() as { port: number }).port
})

afterAll(async () => {
  wss.close()
  await new Promise<void>(resolve => server.close(() => resolve()))
})

describe('concurrent connection caps', () => {
  it('admits sockets up to the per-address cap and refuses the next with 4005', async () => {
    const address = '203.0.113.10'
    const held: WebSocket[] = []

    for (let i = 0; i < 3; i++) {
      const { ws, closeCode } = await connectFrom(address, `cap_a${i}`)
      expect(closeCode, `socket ${i + 1} of 3 should be admitted`).toBeNull()
      held.push(ws)
    }

    // Each socket belongs to a different account, so the per-user cap of 5 is
    // nowhere near — this can only be the per-address rule.
    const overflow = await connectFrom(address, 'cap_overflow')
    expect(overflow.closeCode).toBe(4005)

    for (const ws of held) await closed(ws)
  })

  it('does not punish a different address for the first one being full', async () => {
    // The cap must isolate callers. A per-address rule that leaked across
    // addresses would be a denial-of-service delivered by the defence itself.
    const busy = '203.0.113.20'
    const held: WebSocket[] = []
    for (let i = 0; i < 3; i++) {
      const { ws, closeCode } = await connectFrom(busy, `iso_busy${i}`)
      expect(closeCode).toBeNull()
      held.push(ws)
    }

    const other = await connectFrom('203.0.113.21', 'iso_other')
    expect(other.closeCode).toBeNull()

    await closed(other.ws)
    for (const ws of held) await closed(ws)
  })

  it('releases a slot when a socket closes', async () => {
    const address = '203.0.113.30'
    const held: WebSocket[] = []
    for (let i = 0; i < 3; i++) {
      const { ws, closeCode } = await connectFrom(address, `rel_${i}`)
      expect(closeCode).toBeNull()
      held.push(ws)
    }

    // Full: the next one is refused.
    const refused = await connectFrom(address, 'rel_refused')
    expect(refused.closeCode).toBe(4005)

    // Free one slot, and exactly one more should fit. A leaked slot here is the
    // slow accumulation the cap exists to prevent, so it is the case worth
    // asserting rather than assuming.
    const first = held.shift()
    if (first) await closed(first)

    const readmitted = await connectFrom(address, 'rel_readmitted')
    expect(readmitted.closeCode).toBeNull()

    await closed(readmitted.ws)
    for (const ws of held) await closed(ws)
  })
})
