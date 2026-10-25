// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Real-time delivery against the live relay: B holds a WebSocket open, A sends,
 * and the message must arrive pushed — not polled — and decrypt correctly.
 *
 * Run: npm run e2e:realtime
 */

import '../src/polyfills.core'
import { webcrypto } from 'node:crypto'
import type { NewMessageEvent, WebSocketLike } from '../src/realtime'

if (!globalThis.crypto) (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto

const PIN = '123456'
const TEXT = 'Доставлено по WebSocket, без опроса.'
const TIMEOUT_MS = 30_000

function randomName() {
  return `t_${Math.random().toString(36).slice(2, 10)}`
}

async function main() {
  if (typeof globalThis.WebSocket !== 'function') {
    console.error('This Node build has no global WebSocket; cannot run the realtime check.')
    process.exit(1)
  }

  const { registerNewAccount } = await import('../src/registration')
  const { openSession } = await import('../src/session')
  const { createNodeTestPlatform } = await import('../src/platform/node')
  const { setCurrentPlatform } = await import('../src/platform/current')
  const { sendMessage, receiveMessage } = await import('../src/messaging')
  const { RealtimeClient } = await import('../src/realtime')
  const { authApi } = await import('../src/lib/api')
  const { WS_URL } = await import('../src/lib/config')

  console.log(`ws: ${WS_URL}\n`)

  const platformA = createNodeTestPlatform()
  const platformB = createNodeTestPlatform()
  const nameA = randomName()
  const nameB = randomName()

  setCurrentPlatform(platformA)
  const a = await registerNewAccount(platformA, nameA, PIN)
  if (!a.ok) throw new Error(`register A: ${a.error}`)

  setCurrentPlatform(platformB)
  const b = await registerNewAccount(platformB, nameB, PIN)
  if (!b.ok) throw new Error(`register B: ${b.error}`)
  console.log(`A = @${nameA}\nB = @${nameB}\n`)

  // ── B opens a socket and waits to be pushed to ─────────────────────────────
  const tokenRes = await authApi.getSession(b.account.userId)
  if (tokenRes.error || !tokenRes.data) throw new Error(`ws token: ${tokenRes.error}`)

  let pushed: NewMessageEvent | null = null
  const statuses: string[] = []

  // Node's built-in WebSocket cannot send custom headers, and the relay refuses a
  // handshake without an allow-listed Origin. React Native can set it natively;
  // here the `ws` package stands in so the harness exercises the same path.
  const { default: WSLib } = await import('ws')
  const socketFactory = (url: string, protocols: string[], options: { headers: Record<string, string> }) =>
    new WSLib(url, protocols, { headers: options.headers }) as unknown as WebSocketLike

  const client = new RealtimeClient(
    {
      onStatus: (s, d) => {
        statuses.push(s)
        const why = d?.code ? ` (code ${d.code}${d.reason ? `: ${d.reason}` : ''})` : ''
        console.log(`  [ws] ${s}${why}`)
      },
      onMessage: m => {
        pushed = m
      },
    },
    socketFactory
  )

  client.connect(tokenRes.data.token)

  const connected = await new Promise<boolean>(resolve => {
    const started = Date.now()
    const poll = setInterval(() => {
      if (client.isConnected) {
        clearInterval(poll)
        resolve(true)
      } else if (Date.now() - started > TIMEOUT_MS) {
        clearInterval(poll)
        resolve(false)
      }
    }, 200)
  })
  if (!connected) throw new Error('WebSocket never reached connected state')
  console.log('  B is listening\n')

  // ── A sends ────────────────────────────────────────────────────────────────
  setCurrentPlatform(platformA)
  const sessionA = await openSession(platformA, PIN)
  if (!sessionA.ok) throw new Error(`open A: ${sessionA.reason}`)

  console.log(`A sends: "${TEXT}"`)
  const sentAt = Date.now()
  const sent = await sendMessage(a.account.userId, { id: b.account.userId, username: nameB }, TEXT)
  if (!sent.ok) throw new Error(`send: ${sent.error}`)

  // ── It must arrive by push ─────────────────────────────────────────────────
  const arrived = await new Promise<boolean>(resolve => {
    const started = Date.now()
    const poll = setInterval(() => {
      if (pushed) {
        clearInterval(poll)
        resolve(true)
      } else if (Date.now() - started > TIMEOUT_MS) {
        clearInterval(poll)
        resolve(false)
      }
    }, 100)
  })
  const latency = Date.now() - sentAt

  if (!arrived || !pushed) {
    client.disconnect()
    throw new Error('message was never pushed over the socket')
  }
  const event = pushed as NewMessageEvent
  console.log(`  pushed to B in ${latency}ms (from @${event.senderUsername})`)

  // ── B decrypts what the socket delivered ───────────────────────────────────
  setCurrentPlatform(platformB)
  const sessionB = await openSession(platformB, PIN)
  if (!sessionB.ok) throw new Error(`open B: ${sessionB.reason}`)

  const received = await receiveMessage({
    id: event.id,
    senderId: event.senderId,
    encryptedPayload: event.encryptedPayload,
  })
  client.disconnect()

  if (!received.ok) throw new Error(`decrypt: ${received.error}`)
  console.log(`B decrypted: "${received.text}"`)

  const pass = received.text === TEXT && statuses.includes('connected')
  console.log(`\n${pass ? 'REALTIME TEST PASSED' : 'REALTIME TEST FAILED'}`)
  process.exit(pass ? 0 : 1)
}

main().catch(e => {
  console.error('realtime check crashed:', e instanceof Error ? e.message : e)
  process.exit(1)
})
