// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, it, expect } from 'vitest'
import { createIdentity, recoverIdentity, createAccount, restoreAccount } from '@/onboarding'
import { nodePlatform, createNodeTestPlatform } from '@/platform/node'
import { unlock, hasAccount, wipeVault } from '@/vault'

describe('onboarding — create & recover identity', () => {
  it('creates a mnemonic + Ed25519/X25519 public keys + a derived master key', async () => {
    const res = await createIdentity(nodePlatform, '123456')
    expect(res.mnemonic.split(' ').length).toBe(12)
    expect(typeof res.identity.signing.publicKey).toBe('string')
    expect(res.identity.signing.publicKey.length).toBeGreaterThan(0)
    expect(typeof res.identity.exchange.publicKey).toBe('string')
    expect(res.salt.length).toBe(16)
    expect(res.masterKeyLength).toBe(32)
  })

  it('recovering from the produced mnemonic yields the same identity (deterministic)', async () => {
    const created = await createIdentity(nodePlatform, '123456')
    const recovered = await recoverIdentity(created.mnemonic)
    expect(recovered.signing.publicKey).toBe(created.identity.signing.publicKey)
    expect(recovered.exchange.publicKey).toBe(created.identity.exchange.publicKey)
  })

  it('two fresh identities differ', async () => {
    const a = await createIdentity(nodePlatform, '123456')
    const b = await createIdentity(nodePlatform, '123456')
    expect(a.mnemonic).not.toBe(b.mnemonic)
    expect(a.identity.signing.publicKey).not.toBe(b.identity.signing.publicKey)
  })
})

describe('account lifecycle — setup, relaunch, recovery', () => {
  const PIN = '246810'

  it('setup then unlock returns the same identity (survives a relaunch)', async () => {
    const platform = createNodeTestPlatform()
    expect(await hasAccount(platform)).toBe(false)

    const created = await createAccount(platform, PIN)
    expect(created.mnemonic.split(' ').length).toBe(12)
    expect(await hasAccount(platform)).toBe(true)

    // A relaunch is just a fresh unlock against the same stores.
    const res = await unlock(platform, PIN)
    expect(res.ok).toBe(true)
    if (res.ok) {
      expect(res.identity.signing.publicKey).toBe(created.identity.signing.publicKey)
      expect(res.identity.exchange.publicKey).toBe(created.identity.exchange.publicKey)
    }
  })

  it('the wrong PIN does not open a real account', async () => {
    const platform = createNodeTestPlatform()
    await createAccount(platform, PIN)
    expect(await unlock(platform, '111111')).toEqual({ ok: false, reason: 'wrong-pin' })
  })

  it('restoring from the mnemonic on a clean device yields the same identity', async () => {
    const first = createNodeTestPlatform()
    const created = await createAccount(first, PIN)

    // A different device: empty vault, empty keystore.
    const fresh = createNodeTestPlatform()
    const restored = await restoreAccount(fresh, created.mnemonic, '999999')
    expect(restored.signing.publicKey).toBe(created.identity.signing.publicKey)
    expect(restored.exchange.publicKey).toBe(created.identity.exchange.publicKey)

    // And it unlocks under the new PIN chosen during restore.
    const res = await unlock(fresh, '999999')
    expect(res.ok).toBe(true)
  })

  it('a wiped vault is recoverable from the mnemonic — losing the device secret is survivable', async () => {
    const platform = createNodeTestPlatform()
    const created = await createAccount(platform, PIN)

    await wipeVault(platform)
    expect(await hasAccount(platform)).toBe(false)

    const restored = await restoreAccount(platform, created.mnemonic, PIN)
    expect(restored.signing.publicKey).toBe(created.identity.signing.publicKey)
  })
})
