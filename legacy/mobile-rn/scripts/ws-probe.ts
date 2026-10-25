// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Diagnostic: why does a socket to the relay die?
 *
 * The relay terminates a connection that has not answered its protocol-level
 * ping since the previous 30s sweep. Browsers and React Native answer those
 * inside the WebSocket implementation. Node's built-in (undici) WebSocket is the
 * unknown, so this runs the same connection twice — once on the global
 * WebSocket, once on the `ws` package which is known to auto-pong — and reports
 * how long each survives. A difference means the earlier 1006 was a harness
 * artefact, not a client or relay bug.
 *
 * Run: npm run ws:probe   (requires `npm i --no-save ws`)
 */

import '../src/polyfills.core'
import { webcrypto } from 'node:crypto'

if (!globalThis.crypto) (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto

const OBSERVE_MS = 75_000

async function probeGlobal(url: string, token: string): Promise<string> {
  return new Promise(resolve => {
    const t0 = Date.now()
    const ws = new WebSocket(url, ['lume', `auth.${token}`])
    const done = (msg: string) => resolve(msg)
    ws.onopen = () => console.log(`  [global] open at ${Date.now() - t0}ms`)
    ws.onclose = e => done(`closed after ${Date.now() - t0}ms (code ${e.code})`)
    ws.onerror = () => {}
    setTimeout(() => {
      const alive = ws.readyState === 1
      try {
        ws.close()
      } catch {
        /* ignore */
      }
      done(alive ? `SURVIVED ${OBSERVE_MS}ms` : `dead before ${OBSERVE_MS}ms`)
    }, OBSERVE_MS)
  })
}

async function probeWsLib(url: string, token: string): Promise<string> {
  const { default: WSLib } = await import('ws')
  const { APP_ORIGIN } = await import('../src/lib/config')
  return new Promise(resolve => {
    const t0 = Date.now()
    // The relay rejects a socket with no Origin (isOriginAllowed('') === false)
    // and then terminates it immediately, so its 4007 close frame never arrives
    // and the client only sees 1006. Declaring the app origin is the same fix
    // already applied to the HTTP path.
    const ws = new WSLib(url, ['lume', `auth.${token}`], { headers: { Origin: APP_ORIGIN } })
    let pings = 0
    ws.on('open', () => console.log(`  [ws lib] open at ${Date.now() - t0}ms`))
    ws.on('ping', () => {
      pings++
      console.log(`  [ws lib] server ping #${pings} at ${Date.now() - t0}ms (auto-pong)`)
    })
    ws.on('close', (c: number) => resolve(`closed after ${Date.now() - t0}ms (code ${c}, ${pings} server pings)`))
    ws.on('error', () => {})
    setTimeout(() => {
      const alive = ws.readyState === 1
      try {
        ws.close()
      } catch {
        /* ignore */
      }
      resolve(alive ? `SURVIVED ${OBSERVE_MS}ms (${pings} server pings)` : `dead before ${OBSERVE_MS}ms`)
    }, OBSERVE_MS)
  })
}

async function main() {
  const { registerNewAccount } = await import('../src/registration')
  const { createNodeTestPlatform } = await import('../src/platform/node')
  const { setCurrentPlatform } = await import('../src/platform/current')
  const { authApi } = await import('../src/lib/api')
  const { WS_URL } = await import('../src/lib/config')

  const platform = createNodeTestPlatform()
  setCurrentPlatform(platform)
  const acc = await registerNewAccount(platform, `t_${Math.random().toString(36).slice(2, 10)}`, '123456')
  if (!acc.ok) throw new Error(acc.error)
  const tok = await authApi.getSession(acc.account.userId)
  if (tok.error || !tok.data) throw new Error(tok.error)

  console.log(`ws: ${WS_URL}\nobserving each client for ${OBSERVE_MS / 1000}s\n`)

  console.log('1) Node global WebSocket (undici):')
  console.log(`  -> ${await probeGlobal(WS_URL, tok.data.token)}\n`)

  const tok2 = await authApi.getSession(acc.account.userId)
  console.log('2) ws package:')
  console.log(`  -> ${await probeWsLib(WS_URL, tok2.data!.token)}`)
  process.exit(0)
}

main().catch(e => {
  console.error('probe crashed:', e instanceof Error ? e.message : e)
  process.exit(1)
})
