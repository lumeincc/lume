// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Registers a throwaway peer and sends it a message, so the app running on a real
 * phone can be watched receiving and decrypting it.
 *
 * Usage: npm run send:device -- <recipient-username> ["text"]
 */

import '../src/polyfills.core'
import { webcrypto } from 'node:crypto'

if (!globalThis.crypto) (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto

async function main() {
  const recipient = process.argv[2]
  const text = process.argv[3] ?? 'Привет с компьютера! Это сообщение зашифровано.'
  if (!recipient) {
    console.error('usage: npm run send:device -- <username> ["text"]')
    process.exit(1)
  }

  const { registerNewAccount } = await import('../src/registration')
  const { createNodeTestPlatform } = await import('../src/platform/node')
  const { setCurrentPlatform } = await import('../src/platform/current')
  const { sendMessage } = await import('../src/messaging')
  const { authApi } = await import('../src/lib/api')

  const platform = createNodeTestPlatform()
  setCurrentPlatform(platform)

  const sender = `peer_${Math.random().toString(36).slice(2, 8)}`
  const acc = await registerNewAccount(platform, sender, '123456')
  if (!acc.ok) throw new Error(`register: ${acc.error}`)
  console.log(`sender: @${sender}`)

  const bundle = await authApi.getBundle(recipient)
  if (bundle.error || !bundle.data) throw new Error(`lookup @${recipient}: ${bundle.error}`)
  console.log(`recipient: @${recipient} (${bundle.data.id})`)

  const res = await sendMessage(acc.account.userId, { id: bundle.data.id, username: recipient }, text)
  if (!res.ok) throw new Error(`send: ${res.error}`)

  console.log(`\nsent: "${text}"`)
  console.log(`message id: ${res.messageId}`)
  console.log(`\nAdd @${sender} on the phone to reply.`)
  process.exit(0)
}

main().catch(e => {
  console.error('failed:', e instanceof Error ? e.message : e)
  process.exit(1)
})
