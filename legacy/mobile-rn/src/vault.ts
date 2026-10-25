// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The encrypted vault — mobile counterpart of the web client's crypto/storage.ts.
 *
 * The record format is deliberately identical to the web's v2 records
 * (`{ v: 2, ciphertext, nonce }`, NaCl secretbox under a 32-byte master key), so
 * the two clients stay conceptually one design rather than two. What differs is
 * only what the web cannot do:
 *
 *   - persistence goes through a KeyValueStore (SQLite on device) instead of IndexedDB;
 *   - the master key is derived from the PIN **and** a high-entropy device secret
 *     held by the OS keystore, which lifts the at-rest ceiling that a 4–6 digit
 *     PIN imposes on the web store (SEC-20260721-020).
 *
 * Key material never leaves this module in plaintext form on disk, and the master
 * key is returned to the caller rather than cached here — the caller owns its
 * lifetime and is expected to zero it.
 */

import nacl from 'tweetnacl'
import { encodeBase64, decodeBase64 } from 'tweetnacl-util'
import type { IdentityKeys, KeyPair } from './crypto/keys'
import type { SerializedSession } from './crypto/ratchet'
import type { Platform } from './platform/adapter'

/** Storage keys. Names match the web client so the two schemas stay recognisable. */
export const VAULT_KEYS = {
  IDENTITY: 'identity_keys',
  ENCRYPTION_SALT: 'encryption_salt',
  PIN_TOKEN: 'pin_hash',
  PREKEYS: 'prekeys',
  PROFILE: 'profile',
  CONTACTS: 'contacts',
  SESSIONS: 'sessions',
  CHATS: 'chats',
} as const

/** Keystore entry holding the device secret. Never written to app storage. */
const DEVICE_SECRET_KEY = 'lume_device_secret'

/** Matches the web client (OWASP 2023 for PBKDF2-SHA256). */
export const PBKDF2_ITERATIONS = 600_000
export const MASTER_KEY_BYTES = 32
const SALT_BYTES = 16
const DEVICE_SECRET_BYTES = 32

/** Plaintext sentinel used to tell "wrong PIN" apart from "damaged record". */
const PIN_SENTINEL = 'lume-pin-ok'

/** The web client's v2 record shape. */
export interface EncryptedRecord {
  v: 2
  ciphertext: string
  nonce: string
}

export function encryptWithKey(data: string, masterKey: Uint8Array): EncryptedRecord {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  const ciphertext = nacl.secretbox(new TextEncoder().encode(data), nonce, masterKey)
  return { v: 2, ciphertext: encodeBase64(ciphertext), nonce: encodeBase64(nonce) }
}

/**
 * Fails closed on anything that is not an intact record sealed under this key.
 * A damaged blob must return null rather than throw: NaCl rejects a short nonce
 * or a bad base64 payload with an exception, and letting that escape would crash
 * the caller instead of surfacing as "this vault is corrupt".
 */
export function decryptWithKey(record: EncryptedRecord, masterKey: Uint8Array): string | null {
  if (record?.v !== 2 || typeof record.ciphertext !== 'string' || typeof record.nonce !== 'string') return null
  try {
    const nonce = decodeBase64(record.nonce)
    const ciphertext = decodeBase64(record.ciphertext)
    if (nonce.length !== nacl.secretbox.nonceLength) return null
    if (ciphertext.length <= nacl.secretbox.overheadLength) return null
    const opened = nacl.secretbox.open(ciphertext, nonce, masterKey)
    return opened ? new TextDecoder().decode(opened) : null
  } catch {
    return null
  }
}

/**
 * The device secret is created once per install and lives only in the OS keystore.
 * Losing it (app uninstalled, keystore cleared) makes the local vault
 * unrecoverable by design — the identity itself is still recoverable from the
 * BIP39 mnemonic, which is what LUME's recovery model already relies on.
 */
async function getOrCreateDeviceSecret(platform: Platform): Promise<Uint8Array> {
  const existing = await platform.secure.getSecret(DEVICE_SECRET_KEY)
  if (existing) {
    const decoded = decodeBase64(existing)
    if (decoded.length === DEVICE_SECRET_BYTES) return decoded
  }
  const fresh = platform.crypto.randomBytes(DEVICE_SECRET_BYTES)
  await platform.secure.setSecret(DEVICE_SECRET_KEY, encodeBase64(fresh))
  return fresh
}

/**
 * The salt is not secret, so it lives in normal storage next to the vault. It is
 * created on first use and never rotated: rotating it would orphan every record
 * sealed under the old master key.
 */
async function getOrCreateSalt(platform: Platform): Promise<Uint8Array> {
  const existing = await platform.kv.get<string>(VAULT_KEYS.ENCRYPTION_SALT)
  if (existing) {
    const decoded = decodeBase64(existing)
    if (decoded.length === SALT_BYTES) return decoded
  }
  const fresh = platform.crypto.randomBytes(SALT_BYTES)
  await platform.kv.set(VAULT_KEYS.ENCRYPTION_SALT, encodeBase64(fresh))
  return fresh
}

/**
 * Derive the master key from the PIN and the keystore-held device secret.
 *
 * Mixing the device secret into the PBKDF2 password — rather than using it as the
 * salt — keeps the 600k stretch applied to the whole input, so an attacker who
 * has the stored blob but not the keystore has no low-entropy target to grind.
 */
export async function deriveMasterKey(platform: Platform, pin: string): Promise<Uint8Array> {
  const salt = await getOrCreateSalt(platform)
  const deviceSecret = await getOrCreateDeviceSecret(platform)
  const pinBytes = new TextEncoder().encode(pin)

  const password = new Uint8Array(pinBytes.length + deviceSecret.length)
  password.set(pinBytes, 0)
  password.set(deviceSecret, pinBytes.length)

  try {
    return await platform.crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, MASTER_KEY_BYTES)
  } finally {
    // Zero every copy of the low-entropy input and the device secret.
    password.fill(0)
    pinBytes.fill(0)
    deviceSecret.fill(0)
  }
}

/**
 * Store a sentinel sealed under the master key. Being able to open it proves the
 * PIN was right, which is what lets `unlock` report a wrong PIN without treating a
 * damaged vault as one (the failure mode behind SEC-20260721-002 on the web).
 */
export async function savePinToken(platform: Platform, masterKey: Uint8Array): Promise<void> {
  await platform.kv.set(VAULT_KEYS.PIN_TOKEN, encryptWithKey(PIN_SENTINEL, masterKey))
}

export async function verifyPinToken(platform: Platform, masterKey: Uint8Array): Promise<boolean> {
  const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.PIN_TOKEN)
  if (!record) return false
  return decryptWithKey(record, masterKey) === PIN_SENTINEL
}

export async function saveIdentityKeys(
  platform: Platform,
  keys: IdentityKeys,
  masterKey: Uint8Array
): Promise<void> {
  await platform.kv.set(VAULT_KEYS.IDENTITY, encryptWithKey(JSON.stringify(keys), masterKey))
}

export async function loadIdentityKeys(
  platform: Platform,
  masterKey: Uint8Array
): Promise<IdentityKeys | null> {
  const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.IDENTITY)
  if (!record) return null
  const plaintext = decryptWithKey(record, masterKey)
  if (!plaintext) return null
  return JSON.parse(plaintext) as IdentityKeys
}

/**
 * The private halves of the prekey bundle. The server only ever sees the public
 * keys; these secrets stay here so this device can answer an X3DH handshake and
 * consume one-time prekeys.
 */
export interface PreKeyMaterial {
  signedPreKey: KeyPair
  oneTimePreKeys: KeyPair[]
  updatedAt: number
  /** When the current signed prekey was generated — drives 7-day rotation. */
  spkCreatedAt?: number
  /** Kept through its grace window so in-flight X3DH sessions can still complete. */
  previousSignedPreKey?: KeyPair
  previousSpkRetiredAt?: number
}

/** The web client's name for the same shape; kept so vendored modules type-check. */
export type LocalPreKeyMaterial = PreKeyMaterial

export async function savePreKeyMaterial(
  platform: Platform,
  material: PreKeyMaterial,
  masterKey: Uint8Array
): Promise<void> {
  await platform.kv.set(VAULT_KEYS.PREKEYS, encryptWithKey(JSON.stringify(material), masterKey))
}

export async function loadPreKeyMaterial(
  platform: Platform,
  masterKey: Uint8Array
): Promise<PreKeyMaterial | null> {
  const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.PREKEYS)
  if (!record) return null
  const plaintext = decryptWithKey(record, masterKey)
  return plaintext ? (JSON.parse(plaintext) as PreKeyMaterial) : null
}

/** Non-secret account facts (username, server id) — still sealed, to avoid leaking them at rest. */
export interface AccountProfile {
  userId: string
  username: string
}

export async function saveProfile(
  platform: Platform,
  profile: AccountProfile,
  masterKey: Uint8Array
): Promise<void> {
  await platform.kv.set(VAULT_KEYS.PROFILE, encryptWithKey(JSON.stringify(profile), masterKey))
}

export async function loadProfile(
  platform: Platform,
  masterKey: Uint8Array
): Promise<AccountProfile | null> {
  const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.PROFILE)
  if (!record) return null
  const plaintext = decryptWithKey(record, masterKey)
  return plaintext ? (JSON.parse(plaintext) as AccountProfile) : null
}

/**
 * A contact, in the web client's shape.
 *
 * `publicKey` and `exchangeKey` are what identity pinning checks against, so this
 * record is a security boundary, not just a display convenience: losing it would
 * silently downgrade every later handshake back to trust-on-first-use.
 */
export interface Contact {
  id: string
  username: string
  publicKey: string
  exchangeKey: string
  displayName?: string
  addedAt: number
  verified?: boolean
  verifiedAt?: number
}

export async function saveContacts(
  platform: Platform,
  contacts: Contact[],
  masterKey: Uint8Array
): Promise<void> {
  await platform.kv.set(VAULT_KEYS.CONTACTS, encryptWithKey(JSON.stringify(contacts), masterKey))
}

export async function loadContacts(platform: Platform, masterKey: Uint8Array): Promise<Contact[]> {
  const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.CONTACTS)
  if (!record) return []
  const plaintext = decryptWithKey(record, masterKey)
  if (!plaintext) return []
  const parsed = JSON.parse(plaintext) as unknown
  return Array.isArray(parsed) ? (parsed as Contact[]) : []
}

/** Serialized Double Ratchet sessions, keyed by contact id. */
export type RatchetSessions = Record<string, SerializedSession>

export async function saveRatchetSessions(
  platform: Platform,
  sessions: RatchetSessions,
  masterKey: Uint8Array
): Promise<void> {
  await platform.kv.set(VAULT_KEYS.SESSIONS, encryptWithKey(JSON.stringify(sessions), masterKey))
}

export async function loadRatchetSessions(
  platform: Platform,
  masterKey: Uint8Array
): Promise<RatchetSessions> {
  const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.SESSIONS)
  if (!record) return {}
  const plaintext = decryptWithKey(record, masterKey)
  if (!plaintext) return {}
  const parsed = JSON.parse(plaintext) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
  return parsed as RatchetSessions
}

/**
 * How many messages this device keeps.
 *
 * The whole list is sealed as a single blob, so its size is the cost of every
 * save and of every unlock. Left unbounded it grows until both are slow and the
 * record no longer fits comfortably in memory — the same reasoning behind the
 * relay's own retention caps. The oldest messages are dropped first.
 */
export const MAX_STORED_MESSAGES = 5_000

/** A decrypted message, held only on this device. */
export interface StoredMessage {
  id: string
  contactId: string
  /** True when this device sent it. */
  outgoing: boolean
  text: string
  timestamp: number
  /**
   * Delivery state for outgoing messages. Absent on messages written before the
   * outbox existed and on every received message, both of which are settled by
   * definition — so treat a missing value as 'sent'.
   */
  status?: 'pending' | 'sent' | 'failed'
  /** Why delivery failed, kept so the UI can explain rather than just mark it. */
  error?: string
  /** The relay's id, once it accepted the message. */
  serverId?: string
}

export async function saveMessages(
  platform: Platform,
  messages: StoredMessage[],
  masterKey: Uint8Array
): Promise<void> {
  const capped =
    messages.length > MAX_STORED_MESSAGES ? messages.slice(-MAX_STORED_MESSAGES) : messages
  await platform.kv.set(VAULT_KEYS.CHATS, encryptWithKey(JSON.stringify(capped), masterKey))
}

export async function loadMessages(
  platform: Platform,
  masterKey: Uint8Array
): Promise<StoredMessage[]> {
  const record = await platform.kv.get<EncryptedRecord>(VAULT_KEYS.CHATS)
  if (!record) return []
  const plaintext = decryptWithKey(record, masterKey)
  if (!plaintext) return []
  const parsed = JSON.parse(plaintext) as unknown
  return Array.isArray(parsed) ? (parsed as StoredMessage[]) : []
}

/** True once an identity has been stored — drives "setup" vs "unlock" routing. */
export async function hasAccount(platform: Platform): Promise<boolean> {
  return (await platform.kv.get(VAULT_KEYS.IDENTITY)) !== undefined
}

export type UnlockResult =
  | { ok: true; identity: IdentityKeys; masterKey: Uint8Array }
  | { ok: false; reason: 'no-account' | 'wrong-pin' | 'corrupt' }

/**
 * Open the vault with a PIN. Fails closed: a wrong PIN and a damaged vault are
 * reported as distinct outcomes so the UI never offers to wipe over a typo, and
 * never presents corruption as a bad PIN.
 */
export async function unlock(platform: Platform, pin: string): Promise<UnlockResult> {
  if (!(await hasAccount(platform))) return { ok: false, reason: 'no-account' }

  const masterKey = await deriveMasterKey(platform, pin)
  if (!(await verifyPinToken(platform, masterKey))) {
    masterKey.fill(0)
    return { ok: false, reason: 'wrong-pin' }
  }

  const identity = await loadIdentityKeys(platform, masterKey)
  if (!identity) {
    // The sentinel opened, so the key is right — the identity record itself is damaged.
    masterKey.fill(0)
    return { ok: false, reason: 'corrupt' }
  }
  return { ok: true, identity, masterKey }
}

/** Erase the vault and the device secret. Used by account deletion / panic wipe. */
export async function wipeVault(platform: Platform): Promise<void> {
  await platform.kv.clear()
  await platform.secure.deleteSecret(DEVICE_SECRET_KEY)
}
