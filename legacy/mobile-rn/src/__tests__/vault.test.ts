// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, it, expect, beforeEach } from 'vitest'
import {
  deriveMasterKey,
  saveIdentityKeys,
  loadIdentityKeys,
  savePinToken,
  verifyPinToken,
  hasAccount,
  unlock,
  wipeVault,
  encryptWithKey,
  decryptWithKey,
  VAULT_KEYS,
  MASTER_KEY_BYTES,
  type EncryptedRecord,
} from '@/vault'
import { createNodeTestPlatform, createMemorySecretStore } from '@/platform/node'
import { generateIdentityKeys } from '@/crypto/keys'
import type { Platform } from '@/platform/adapter'

// 600k PBKDF2 twice per unlock makes these slow by design; keep the count low.
const PIN = '123456'

describe('vault', () => {
  let platform: Platform

  beforeEach(() => {
    platform = createNodeTestPlatform()
  })

  async function seedAccount(pin = PIN) {
    const identity = generateIdentityKeys()
    const masterKey = await deriveMasterKey(platform, pin)
    await saveIdentityKeys(platform, identity, masterKey)
    await savePinToken(platform, masterKey)
    return { identity, masterKey }
  }

  it('round-trips an identity through the encrypted vault', async () => {
    const { identity, masterKey } = await seedAccount()
    const loaded = await loadIdentityKeys(platform, masterKey)
    expect(loaded?.signing.publicKey).toBe(identity.signing.publicKey)
    expect(loaded?.signing.secretKey).toBe(identity.signing.secretKey)
    expect(loaded?.exchange.publicKey).toBe(identity.exchange.publicKey)
  })

  it('stores records in the web client v2 format, with no plaintext key material', async () => {
    const { identity } = await seedAccount()
    const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.IDENTITY)
    expect(record?.v).toBe(2)
    expect(typeof record?.ciphertext).toBe('string')
    expect(typeof record?.nonce).toBe('string')
    // The secret key must not be recoverable from the stored blob.
    const blob = JSON.stringify(record)
    expect(blob).not.toContain(identity.signing.secretKey)
    expect(blob).not.toContain(identity.exchange.secretKey)
  })

  it('derives a stable 32-byte master key for the same PIN, and a different one for another PIN', async () => {
    const a = await deriveMasterKey(platform, PIN)
    const b = await deriveMasterKey(platform, PIN)
    const c = await deriveMasterKey(platform, '654321')
    expect(a.length).toBe(MASTER_KEY_BYTES)
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'))
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(c).toString('hex'))
  })

  it('reports no-account before setup and hasAccount after', async () => {
    expect(await hasAccount(platform)).toBe(false)
    expect(await unlock(platform, PIN)).toEqual({ ok: false, reason: 'no-account' })
    await seedAccount()
    expect(await hasAccount(platform)).toBe(true)
  })

  it('unlocks with the right PIN', async () => {
    const { identity } = await seedAccount()
    const res = await unlock(platform, PIN)
    expect(res.ok).toBe(true)
    if (res.ok) expect(res.identity.signing.publicKey).toBe(identity.signing.publicKey)
  })

  it('rejects a wrong PIN as wrong-pin, not corruption', async () => {
    await seedAccount()
    const res = await unlock(platform, '000000')
    expect(res).toEqual({ ok: false, reason: 'wrong-pin' })
  })

  it('reports a damaged identity record as corrupt, not as a wrong PIN', async () => {
    await seedAccount()
    // PIN token stays valid; only the identity blob is mangled.
    await platform.kv.set(VAULT_KEYS.IDENTITY, { v: 2, ciphertext: 'AAAA', nonce: 'BBBB' })
    const res = await unlock(platform, PIN)
    expect(res).toEqual({ ok: false, reason: 'corrupt' })
  })

  it('verifyPinToken only accepts the key the token was sealed with', async () => {
    const { masterKey } = await seedAccount()
    expect(await verifyPinToken(platform, masterKey)).toBe(true)
    const other = await deriveMasterKey(platform, '999999')
    expect(await verifyPinToken(platform, other)).toBe(false)
  })

  it('wipeVault removes both the store and the device secret', async () => {
    await seedAccount()
    await wipeVault(platform)
    expect(await hasAccount(platform)).toBe(false)
    expect(await platform.secure.getSecret('lume_device_secret')).toBeNull()
  })

  // ── The property that lifts the at-rest ceiling (SEC-20260721-020) ──────────
  it('cannot be opened from the stored blob alone — the keystore secret is required', async () => {
    const { identity } = await seedAccount()

    // Simulate an attacker who exfiltrated app storage (the SQLite file) but not
    // the hardware-backed keystore: same kv contents, fresh empty keystore.
    const stolen: Platform = {
      crypto: platform.crypto,
      kv: platform.kv,
      secure: createMemorySecretStore(),
    }

    // Even with the CORRECT PIN, the vault must not open.
    const res = await unlock(stolen, PIN)
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.reason).toBe('wrong-pin')

    // And the identity must remain unreadable under the key that store yields.
    const wrongKey = await deriveMasterKey(stolen, PIN)
    expect(await loadIdentityKeys(stolen, wrongKey)).toBeNull()

    // Sanity: the original platform still opens it, so the test is not vacuous.
    const ok = await unlock(platform, PIN)
    expect(ok.ok).toBe(true)
    if (ok.ok) expect(ok.identity.signing.publicKey).toBe(identity.signing.publicKey)
  })

  it('encrypt/decrypt helpers round-trip and reject a foreign key', async () => {
    const key = new Uint8Array(32).fill(3)
    const foreign = new Uint8Array(32).fill(4)
    const rec = encryptWithKey('hello вложение', key)
    expect(decryptWithKey(rec, key)).toBe('hello вложение')
    expect(decryptWithKey(rec, foreign)).toBeNull()
  })
})
