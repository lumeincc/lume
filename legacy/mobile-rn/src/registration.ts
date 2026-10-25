// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Account setup against the relay.
 *
 * The order mirrors the web client deliberately: the server call happens BEFORE
 * anything is written locally, so a rejected username (or an unreachable relay)
 * leaves no half-made account on the device. Only the public halves of the key
 * material are ever sent; the secrets go straight into the sealed vault.
 */

import { createAccountWithMnemonic, recoverIdentityFromMnemonic } from './crypto/mnemonic'
import { generatePreKeyBundle } from './crypto/keys'
import { authApi } from './lib/api'
import { vaultClear, vaultSetAuth } from './crypto/keyVault'
import {
  deriveMasterKey,
  saveIdentityKeys,
  savePinToken,
  savePreKeyMaterial,
  saveProfile,
  wipeVault,
} from './vault'
import type { IdentityKeys } from './crypto/keys'
import type { Platform } from './platform/adapter'

/** How many one-time prekeys to publish at setup — the web client uses 20. */
const ONE_TIME_PREKEY_COUNT = 20

export interface RegisteredAccount {
  /** Show once, have the user write it down, then drop it. */
  mnemonic: string
  identity: IdentityKeys
  userId: string
  username: string
}

export type RegistrationResult =
  | { ok: true; account: RegisteredAccount }
  | { ok: false; error: string }

/**
 * Writes the account to the vault and then hands the live keys to the in-memory
 * key vault, which is what lets every later request be signed.
 *
 * Ownership of the master key transfers to the key vault here — it holds the
 * reference rather than a copy, so zeroing it after `vaultSetAuth` would leave
 * the vault holding a key of zeros and every signature would fail. It is zeroed
 * only on the failure path; `vaultClear` owns it from then on.
 */
async function persist(
  platform: Platform,
  pin: string,
  identity: IdentityKeys,
  bundle: ReturnType<typeof generatePreKeyBundle>,
  profile: { userId: string; username: string }
): Promise<void> {
  const masterKey = await deriveMasterKey(platform, pin)
  try {
    await saveIdentityKeys(platform, identity, masterKey)
    await savePinToken(platform, masterKey)
    await savePreKeyMaterial(
      platform,
      {
        signedPreKey: bundle.signedPreKey,
        oneTimePreKeys: bundle.oneTimePreKeys,
        updatedAt: Date.now(),
      },
      masterKey
    )
    await saveProfile(platform, profile, masterKey)
  } catch (e) {
    masterKey.fill(0)
    throw e
  }
  vaultSetAuth(identity, masterKey)
}

/**
 * Create an identity, publish its public keys, then seal everything locally.
 */
export async function registerNewAccount(
  platform: Platform,
  username: string,
  pin: string
): Promise<RegistrationResult> {
  // A brand-new identity must register UNSIGNED. Any keys left in the vault from
  // a previous account would sign the request, and the relay would reject it for
  // declaring an identity key that does not match the signature.
  vaultClear()

  // And the previous account's records must go with it. Leaving them is not a
  // tidiness issue, it is a correctness and privacy one: the salt is reused, so
  // the same PIN derives the same master key and the OLD account's contacts and
  // messages decrypt straight into the NEW one. A different PIN is no better —
  // the records simply stop opening and the store reports itself as corrupt.
  await wipeVault(platform)

  const { mnemonic, identity } = await createAccountWithMnemonic()
  const bundle = generatePreKeyBundle(identity.exchange, identity.signing, ONE_TIME_PREKEY_COUNT)

  const { data, error } = await authApi.register({
    username,
    identityKey: identity.signing.publicKey,
    exchangeIdentityKey: identity.exchange.publicKey,
    signedPrekey: bundle.signedPreKey.publicKey,
    signedPrekeySignature: bundle.signature,
    oneTimePrekeys: bundle.oneTimePreKeys.map((key, i) => ({
      id: `${username}-prekey-${i}`,
      publicKey: key.publicKey,
    })),
  })

  if (error || !data) return { ok: false, error: error ?? 'Registration failed' }

  await persist(platform, pin, identity, bundle, { userId: data.id, username })
  return { ok: true, account: { mnemonic, identity, userId: data.id, username } }
}

/**
 * Silent re-bind: republish the identity this device already holds.
 *
 * The relay's user row is a cache of a client-authoritative identity. On a free
 * tier the database is ephemeral, so a redeploy wipes it and every signed call
 * starts answering "User not found" even though nothing is wrong with the
 * account. The web client handles that by re-registering the same keys on
 * unlock; this is the mobile equivalent.
 *
 * The identity, safety numbers and existing ratchet sessions are unchanged — only
 * the server-side row and the published prekeys are recreated. Requires an open
 * session, because the request is signed with the identity it re-registers,
 * which is what proves ownership.
 */
export async function rebindIdentity(
  platform: Platform,
  identity: IdentityKeys,
  username: string,
  masterKey: Uint8Array
): Promise<{ ok: true; userId: string } | { ok: false; error: string }> {
  const bundle = generatePreKeyBundle(identity.exchange, identity.signing, ONE_TIME_PREKEY_COUNT)

  const { data, error } = await authApi.register({
    username,
    identityKey: identity.signing.publicKey,
    exchangeIdentityKey: identity.exchange.publicKey,
    signedPrekey: bundle.signedPreKey.publicKey,
    signedPrekeySignature: bundle.signature,
    oneTimePrekeys: bundle.oneTimePreKeys.map((key, i) => ({
      id: `${username}-prekey-${i}`,
      publicKey: key.publicKey,
    })),
  })
  if (error || !data) return { ok: false, error: error ?? 'Rebind failed' }

  // The published prekeys changed, so the local secrets must follow or this
  // device could not answer the handshakes it just advertised.
  await savePreKeyMaterial(
    platform,
    {
      signedPreKey: bundle.signedPreKey,
      oneTimePreKeys: bundle.oneTimePreKeys,
      updatedAt: Date.now(),
    },
    masterKey
  )
  await saveProfile(platform, { userId: data.id, username }, masterKey)
  return { ok: true, userId: data.id }
}

/**
 * Re-bind an existing identity (recovered from its mnemonic) to the relay. The
 * server row is a cache of a client-authoritative identity, so re-registering the
 * same keys is how a new device — or a reset server — picks the account back up
 * without changing the identity or the safety numbers.
 */
export async function restoreAccountFromMnemonic(
  platform: Platform,
  mnemonic: string,
  username: string,
  pin: string
): Promise<RegistrationResult> {
  const identity = await recoverIdentityFromMnemonic(mnemonic)

  // Restoring replaces whatever account was on this device, so its records go
  // first — for the same reason as above.
  vaultClear()
  await wipeVault(platform)

  // Unlike a new account, a re-bind must be SIGNED: the relay verifies that the
  // identity key in the body matches the signature, which is what proves this
  // device really holds the identity it is reclaiming.
  const rebindKey = await deriveMasterKey(platform, pin)
  vaultSetAuth(identity, rebindKey)

  const bundle = generatePreKeyBundle(identity.exchange, identity.signing, ONE_TIME_PREKEY_COUNT)

  const { data, error } = await authApi.register({
    username,
    identityKey: identity.signing.publicKey,
    exchangeIdentityKey: identity.exchange.publicKey,
    signedPrekey: bundle.signedPreKey.publicKey,
    signedPrekeySignature: bundle.signature,
    oneTimePrekeys: bundle.oneTimePreKeys.map((key, i) => ({
      id: `${username}-prekey-${i}`,
      publicKey: key.publicKey,
    })),
  })

  if (error || !data) return { ok: false, error: error ?? 'Restore failed' }

  await persist(platform, pin, identity, bundle, { userId: data.id, username })
  return { ok: true, account: { mnemonic, identity, userId: data.id, username } }
}
