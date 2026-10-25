// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Creating a second account on a device must not inherit anything from the first.
 *
 * Both failure modes below were observed in the shipped web client:
 *
 *   - with the SAME pin the salt is reused, so the new account derives the same
 *     master key and the previous account's contacts and messages decrypt
 *     straight into it — one person's conversations shown under another's login;
 *   - with a DIFFERENT pin the old records simply stop opening and the store
 *     declares itself corrupt ("Не удалось прочитать локальные данные").
 *
 * Neither is acceptable in a messenger, so registration wipes first.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

const register = vi.fn()
vi.mock('@/lib/api', () => ({
  authApi: { register: (...a: unknown[]) => register(...a) },
  messagesApi: {},
}))

import { registerNewAccount } from '@/registration'
import { openSession, closeSession } from '@/session'
import { createNodeTestPlatform } from '@/platform/node'
import { setCurrentPlatform } from '@/platform/current'
import { saveContacts, saveMessages, loadContacts, loadMessages, loadIdentityKeys } from '@/vault'
import { vaultGetMasterKey } from '@/crypto/keyVault'
import type { Platform } from '@/platform/adapter'

const PIN = '112233'

describe('account isolation', () => {
  let platform: Platform

  beforeEach(() => {
    vi.clearAllMocks()
    let n = 0
    register.mockImplementation(() =>
      Promise.resolve({ data: { id: `server-id-${++n}`, username: 'x', message: 'ok' } })
    )
    platform = createNodeTestPlatform()
    setCurrentPlatform(platform)
  })

  // The key vault is a process-wide singleton, so a test that ends with an open
  // session leaks its keys into the next one.
  afterEach(async () => {
    await closeSession()
  })

  /** Give the open account some history, as a real user would have. */
  async function seedHistory(contactId: string, text: string) {
    const key = vaultGetMasterKey()
    await saveContacts(
      platform,
      [{ id: contactId, username: 'friend', publicKey: 'pk', exchangeKey: 'ek', addedAt: 1 }],
      key
    )
    await saveMessages(
      platform,
      [{ id: 'm1', contactId, outgoing: false, text, timestamp: 1 }],
      key
    )
  }

  it('a second account with the SAME pin cannot see the first account’s history', async () => {
    const first = await registerNewAccount(platform, 'alice', PIN)
    expect(first.ok).toBe(true)
    await seedHistory('contact-a', 'секрет первого аккаунта')
    await closeSession()

    // Same PIN — the dangerous case, because the key derivation would otherwise
    // land on the same master key.
    const second = await registerNewAccount(platform, 'bob', PIN)
    expect(second.ok).toBe(true)

    const opened = await openSession(platform, PIN)
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.contacts).toEqual([])
      const messages = await loadMessages(platform, vaultGetMasterKey())
      expect(messages).toEqual([])
    }
  })

  it('a second account with a DIFFERENT pin opens cleanly instead of reporting corruption', async () => {
    await registerNewAccount(platform, 'alice', PIN)
    await seedHistory('contact-a', 'история первого')
    await closeSession()

    const second = await registerNewAccount(platform, 'bob', '998877')
    expect(second.ok).toBe(true)

    const opened = await openSession(platform, '998877')
    expect(opened.ok).toBe(true)
    if (opened.ok) {
      expect(opened.contacts).toEqual([])
      expect(await loadContacts(platform, vaultGetMasterKey())).toEqual([])
    }
  })

  it('the second account’s identity is its own, not the first’s', async () => {
    const first = await registerNewAccount(platform, 'alice', PIN)
    await closeSession()
    const second = await registerNewAccount(platform, 'bob', PIN)

    expect(first.ok && second.ok).toBe(true)
    if (first.ok && second.ok) {
      expect(second.account.identity.signing.publicKey).not.toBe(
        first.account.identity.signing.publicKey
      )
      const stored = await loadIdentityKeys(platform, vaultGetMasterKey())
      expect(stored?.signing.publicKey).toBe(second.account.identity.signing.publicKey)
    }
  })

  it('the first account’s PIN no longer opens the device after it is replaced', async () => {
    await registerNewAccount(platform, 'alice', PIN)
    await closeSession()
    await registerNewAccount(platform, 'bob', '998877')
    await closeSession()

    const withOldPin = await openSession(platform, PIN)
    expect(withOldPin.ok).toBe(false)
    if (!withOldPin.ok) expect(withOldPin.reason).toBe('wrong-pin')
  })
})
