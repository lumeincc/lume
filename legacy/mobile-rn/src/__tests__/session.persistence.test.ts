// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Ratchet sessions must survive a relaunch. They advance with every message, so
 * losing them does not just lose history — both sides permanently stop being able
 * to decrypt each other.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { createNodeTestPlatform } from '@/platform/node'
import { setCurrentPlatform } from '@/platform/current'
import { openSession, closeSession, flushSessions } from '@/session'
import { createAccount } from '@/onboarding'
import { vaultUpsertSession, vaultGetAllSessions, vaultGetSession } from '@/crypto/keyVault'
import { loadRatchetSessions } from '@/vault'
import { vaultGetMasterKey } from '@/crypto/keyVault'
import type { Platform } from '@/platform/adapter'
import type { SerializedSession } from '@/crypto/ratchet'

const PIN = '135790'

/** A structurally valid serialized session; the contents are opaque to storage. */
function fakeSession(tag: string): SerializedSession {
  return {
    dhSendingKeyPair: { publicKey: `pub-${tag}`, secretKey: `sec-${tag}` },
    dhReceivingPublicKey: null,
    rootKey: `root-${tag}`,
    sendingChainKey: `send-${tag}`,
    receivingChainKey: null,
    sendingMessageNumber: 7,
    receivingMessageNumber: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: {},
  } as unknown as SerializedSession
}

describe('ratchet session persistence', () => {
  let platform: Platform

  beforeEach(async () => {
    platform = createNodeTestPlatform()
    setCurrentPlatform(platform)
    await createAccount(platform, PIN)
    await closeSession()
  })

  it('writes sessions to the vault when the ratchet advances', async () => {
    const opened = await openSession(platform, PIN)
    expect(opened.ok).toBe(true)

    vaultUpsertSession('contact-1', fakeSession('a'))
    await flushSessions()

    const stored = await loadRatchetSessions(platform, vaultGetMasterKey())
    expect(Object.keys(stored)).toEqual(['contact-1'])
  })

  it('restores sessions on the next unlock — a conversation survives a relaunch', async () => {
    await openSession(platform, PIN)
    vaultUpsertSession('contact-1', fakeSession('a'))
    vaultUpsertSession('contact-2', fakeSession('b'))
    await flushSessions()

    // A relaunch: every in-memory key is dropped.
    await closeSession()
    expect(vaultGetAllSessions()).toEqual({})

    const reopened = await openSession(platform, PIN)
    expect(reopened.ok).toBe(true)
    expect(Object.keys(vaultGetAllSessions()).sort()).toEqual(['contact-1', 'contact-2'])
    expect(vaultGetSession('contact-1')?.sendingMessageNumber).toBe(7)
  })

  it('closeSession waits for a queued write instead of dropping it', async () => {
    await openSession(platform, PIN)
    vaultUpsertSession('contact-1', fakeSession('a'))

    // Deliberately no flush: closing must not lose the write it triggered, which
    // is what happens if the master key is zeroed while the write is in flight.
    await closeSession()

    const reopened = await openSession(platform, PIN)
    expect(reopened.ok).toBe(true)
    expect(Object.keys(vaultGetAllSessions())).toEqual(['contact-1'])
  })

  it('opening another account does not clobber the first one’s sessions', async () => {
    // Regression: vaultSetSessions notifies listeners, so a listener left
    // attached from the previous session fired while the vault already held the
    // NEW account's keys but still pointed at the OLD platform. It wrote an empty
    // session map into the first account's storage under the wrong master key,
    // destroying the sender's ratchet state — a conversation that could never
    // recover. Note there is deliberately no closeSession between the two opens:
    // that is what hid the bug from the test below.
    await openSession(platform, PIN)
    vaultUpsertSession('contact-1', fakeSession('a'))
    await flushSessions()

    const second = createNodeTestPlatform()
    setCurrentPlatform(second)
    await createAccount(second, PIN)
    await openSession(second, PIN)

    // Back to the first account: its session must still be there.
    setCurrentPlatform(platform)
    const back = await openSession(platform, PIN)
    expect(back.ok).toBe(true)
    expect(Object.keys(vaultGetAllSessions())).toEqual(['contact-1'])
    expect(vaultGetSession('contact-1')?.sendingMessageNumber).toBe(7)
  })

  it('keeps each account’s sessions in its own vault', async () => {
    const other = createNodeTestPlatform()
    setCurrentPlatform(other)
    await createAccount(other, PIN)
    await closeSession()

    setCurrentPlatform(platform)
    await openSession(platform, PIN)
    vaultUpsertSession('mine', fakeSession('a'))
    await flushSessions()
    await closeSession()

    setCurrentPlatform(other)
    const otherOpened = await openSession(other, PIN)
    expect(otherOpened.ok).toBe(true)
    expect(vaultGetAllSessions()).toEqual({})
  })
})
