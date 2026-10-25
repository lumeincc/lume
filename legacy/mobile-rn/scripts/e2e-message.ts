// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * End-to-end proof against the live relay: two throwaway accounts exchange a
 * real message, and we show what the relay actually stored.
 *
 * The key vault and the "current platform" are process-wide singletons — exactly
 * one identity is active at a time on a real device — so this script switches
 * between A and B by reopening each session, which is also what a second device
 * would do.
 *
 * Run: npm run e2e:message
 */

import '../src/polyfills.core'
import { webcrypto } from 'node:crypto'

if (!globalThis.crypto) (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto

const PIN = '123456'
const SECRET_TEXT = 'Hello! Only the two of us can read this. 🔒'

function randomName() {
  return `t_${Math.random().toString(36).slice(2, 10)}`
}

async function main() {
  const { registerNewAccount } = await import('../src/registration')
  const { openSession } = await import('../src/session')
  const { createNodeTestPlatform } = await import('../src/platform/node')
  const { setCurrentPlatform } = await import('../src/platform/current')
  const { sendMessage, receiveMessage } = await import('../src/messaging')
  const { messagesApi } = await import('../src/lib/api')
  const { API_URL } = await import('../src/lib/config')

  console.log(`relay: ${API_URL}\n`)

  // ── Two accounts, each with its own device storage ─────────────────────────
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

  // ── A sends to B ───────────────────────────────────────────────────────────
  setCurrentPlatform(platformA)
  const sessionA = await openSession(platformA, PIN)
  if (!sessionA.ok) throw new Error(`open A: ${sessionA.reason}`)

  console.log(`A sends: "${SECRET_TEXT}"`)
  const sent = await sendMessage(a.account.userId, { id: b.account.userId, username: nameB }, SECRET_TEXT)
  if (!sent.ok) throw new Error(`send: ${sent.error}`)
  console.log(`  sent, message id ${sent.messageId}\n`)

  // ── What the relay is holding ──────────────────────────────────────────────
  setCurrentPlatform(platformB)
  const sessionB = await openSession(platformB, PIN)
  if (!sessionB.ok) throw new Error(`open B: ${sessionB.reason}`)

  const pending = await messagesApi.getPending(b.account.userId)
  if (pending.error || !pending.data) throw new Error(`pending: ${pending.error}`)
  const msg = pending.data.messages[0]
  if (!msg) throw new Error('relay returned no messages')

  const stored = msg.encryptedPayload
  console.log('WHAT THE RELAY STORED (this is all it ever sees):')
  // Printed whole rather than truncated: the point of this line is that a reader
  // can look at everything the relay holds and find no message in it. An ellipsis
  // invites the suspicion that the plaintext is in the part we cut.
  console.log(`  ${stored}`)
  const leaks = stored.includes(SECRET_TEXT) || stored.includes('Hello')
  console.log(`  contains the plaintext? ${leaks ? 'YES — LEAK!' : 'no'}\n`)

  // ── B decrypts ─────────────────────────────────────────────────────────────
  const received = await receiveMessage({
    id: msg.id,
    senderId: msg.senderId,
    encryptedPayload: msg.encryptedPayload,
  })
  if (!received.ok) throw new Error(`receive: ${received.error}`)
  console.log(`B decrypted: "${received.text}"`)

  const matches = received.text === SECRET_TEXT
  console.log(`  matches what A sent? ${matches}\n`)

  // ── A second message, to prove the ratchet keeps working ───────────────────
  setCurrentPlatform(platformA)
  await openSession(platformA, PIN)
  const second = 'A second message — a fresh key for every one.'
  const sent2 = await sendMessage(a.account.userId, { id: b.account.userId, username: nameB }, second)
  if (!sent2.ok) throw new Error(`send 2: ${sent2.error}`)

  setCurrentPlatform(platformB)
  await openSession(platformB, PIN)
  const pending2 = await messagesApi.getPending(b.account.userId)
  const msg2 = pending2.data?.messages.find(m => m.id === sent2.messageId)
  if (!msg2) throw new Error('second message not found')

  const received2 = await receiveMessage({
    id: msg2.id,
    senderId: msg2.senderId,
    encryptedPayload: msg2.encryptedPayload,
  })
  if (!received2.ok) throw new Error(`receive 2: ${received2.error}`)
  console.log(`B decrypted #2: "${received2.text}"`)

  // Different message keys must produce different ciphertext for different text.
  const differentCiphertext = msg.encryptedPayload !== msg2.encryptedPayload
  console.log(`  ciphertexts differ between messages? ${differentCiphertext}\n`)

  // ── Restart both sides, then keep talking ─────────────────────────────────
  // The ratchet advances with every message, so if that state is not persisted a
  // conversation silently dies the moment either app is closed. Dropping every
  // in-memory key here is exactly what a relaunch does.
  const { closeSession } = await import('../src/session')
  const { vaultGetSession, vaultGetAllSessions } = await import('../src/crypto/keyVault')

  const describeSession = (label: string, id: string) => {
    const s = vaultGetSession(id)
    console.log(
      `  [${label}] sessions=${JSON.stringify(Object.keys(vaultGetAllSessions()))} ` +
        (s
          ? `send#=${s.sendingMessageNumber} recv#=${s.receivingMessageNumber} prevLen=${s.previousSendingChainLength}`
          : 'NO SESSION')
    )
  }

  describeSession('B before restart', a.account.userId)
  await closeSession()

  setCurrentPlatform(platformA)
  const reopenedA = await openSession(platformA, PIN)
  if (!reopenedA.ok) throw new Error(`reopen A: ${reopenedA.reason}`)
  describeSession('A after restart', b.account.userId)

  const afterRestart = 'A third, after restarting both clients.'
  const sent3 = await sendMessage(a.account.userId, { id: b.account.userId, username: nameB }, afterRestart)
  if (!sent3.ok) throw new Error(`send 3: ${sent3.error}`)

  await closeSession()
  setCurrentPlatform(platformB)
  const reopenedB = await openSession(platformB, PIN)
  if (!reopenedB.ok) throw new Error(`reopen B: ${reopenedB.reason}`)

  describeSession("B after restart", a.account.userId)
  const pending3 = await messagesApi.getPending(b.account.userId)
  const msg3 = pending3.data?.messages.find(m => m.id === sent3.messageId)
  if (!msg3) throw new Error('third message not found')

  const received3 = await receiveMessage({
    id: msg3.id,
    senderId: msg3.senderId,
    encryptedPayload: msg3.encryptedPayload,
  })
  const survived = received3.ok && received3.text === afterRestart
  console.log(`B decrypted #3 after a restart of BOTH sides: ${survived ? `"${received3.ok ? received3.text : ''}"` : `FAILED — ${received3.ok ? '' : received3.error}`}`)
  console.log(`  ratchet state survived the restart? ${survived}\n`)

  const pass =
    matches && !leaks && received2.text === second && differentCiphertext && survived
  console.log(pass ? 'E2E MESSAGE TEST PASSED' : 'E2E MESSAGE TEST FAILED')
  process.exit(pass ? 0 : 1)
}

main().catch(e => {
  console.error('e2e crashed:', e instanceof Error ? e.message : e)
  process.exit(1)
})
