// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Безопасное локальное хранилище
 * Использует IndexedDB с шифрованием для хранения ключей
 */

import { get, set, del, clear } from "idb-keyval";
import nacl from "tweetnacl";
import { z } from "zod";
import { encodeBase64, decodeBase64 } from "tweetnacl-util";
import type { IdentityKeys, KeyPair } from "./keys";
import type { SerializedSession } from "./ratchet";
import type { Chat, Message } from "@/stores";

const STORAGE_KEYS = {
  IDENTITY: "identity_keys",
  CONTACTS: "contacts",
  CHATS: "chats",
  SESSIONS: "sessions",
  PREKEYS: "prekeys",
  SETTINGS: "settings",
  PIN_HASH: "pin_hash",
  ENCRYPTION_SALT: "encryption_salt",
  HIDDEN_CHAT_PIN: "hidden_chat_pin",
  LOCKOUT: "lockout_state",
  CHANGEPIN_BACKUP: "changepin_backup",
  GROUP_MESSAGES: "group_messages",
  ATTACHMENT_KEYS: "attachment_keys",
} as const;

interface EncryptedDataV1 {
  ciphertext: string;
  nonce: string;
  salt: string;
}

interface EncryptedDataV2 {
  v: 2;
  ciphertext: string;
  nonce: string;
}

type EncryptedData = EncryptedDataV1 | EncryptedDataV2;

interface BackupEnvelopeV1 {
  v: 1;
  salt: string;
  nonce: string;
  ciphertext: string;
}

interface BackupEnvelopeV2 {
  v: 2;
  salt: string;
  nonce: string;
  ciphertext: string;
  iterations: number;
}

type BackupEnvelope = BackupEnvelopeV1 | BackupEnvelopeV2;

/**
 * PBKDF2 iterations for backup envelope encryption.
 * 600,000 per OWASP 2023 recommendation for PBKDF2-SHA256.
 * Backups are exported/imported infrequently, so higher cost is acceptable.
 */
const BACKUP_PBKDF2_ITERATIONS = 600_000;

/**
 * Legacy iteration count used by BackupEnvelope v1.
 * Kept for backward-compatible import of old backups.
 */
const LEGACY_PBKDF2_ITERATIONS = 100_000;

/**
 * Accepted range for the `iterations` value read from an imported backup envelope.
 * The value is unauthenticated metadata, so it must be bounded before it reaches
 * the KDF — too high hangs the thread, too low weakens the derivation. The range
 * spans the legacy 100k floor to headroom above the current 600k. SEC-20260721-006.
 */
const MIN_BACKUP_ITERATIONS = LEGACY_PBKDF2_ITERATIONS;
const MAX_BACKUP_ITERATIONS = 1_000_000;

/**
 * Structural schema for a decrypted backup payload. Validated BEFORE the store is
 * wiped, so a backup that decrypts cleanly but is truncated (e.g. `{"identity":null}`)
 * is rejected while the pre-existing data is still intact. SEC-20260721-006.
 */
export const BackupPayloadSchema = z.object({
  identity: z.union([z.object({}).passthrough(), z.null()]),
  contacts: z.array(z.unknown()),
  chats: z.array(z.unknown()),
  sessions: z.record(z.string(), z.unknown()),
  prekeys: z.union([z.object({}).passthrough(), z.null()]).optional(),
  settings: z.object({}).passthrough(),
});

/**
 * Derives an encryption key from a PIN with a specific iteration count.
 * Used for backup envelope encryption where iteration count may differ
 * from the main deriveKeyFromPin (which uses 100k for UX reasons).
 */
async function deriveKeyFromPinWithIterations(
  pin: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const pinBytes = stringToUint8Array(pin);

  const pinBuffer = new ArrayBuffer(pinBytes.length);
  new Uint8Array(pinBuffer).set(pinBytes);

  const saltBuffer = new ArrayBuffer(salt.length);
  new Uint8Array(saltBuffer).set(salt);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    pinBuffer,
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );

  return new Uint8Array(derivedBits);
}

// Helper functions for UTF8 encoding/decoding
function stringToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function uint8ArrayToString(arr: Uint8Array): string {
  return new TextDecoder().decode(arr);
}

/**
 * Генерирует ключ шифрования из PIN или пароля
 */
async function deriveKeyFromPin(
  pin: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const pinBytes = stringToUint8Array(pin);

  // Create ArrayBuffer copies to avoid SharedArrayBuffer type issues
  const pinBuffer = new ArrayBuffer(pinBytes.length);
  new Uint8Array(pinBuffer).set(pinBytes);

  const saltBuffer = new ArrayBuffer(salt.length);
  new Uint8Array(saltBuffer).set(salt);

  // Используем PBKDF2 через Web Crypto API
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    pinBuffer,
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations: 600000,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );

  return new Uint8Array(derivedBits);
}

/**
 * Расшифровывает данные с использованием PIN
 */
async function decryptWithPin(
  encrypted: EncryptedDataV1,
  pin: string,
): Promise<string | null> {
  const salt = decodeBase64(encrypted.salt);
  const key = await deriveKeyFromPin(pin, salt);
  const nonce = decodeBase64(encrypted.nonce);
  const ciphertext = decodeBase64(encrypted.ciphertext);

  const decrypted = nacl.secretbox.open(ciphertext, nonce, key);

  if (!decrypted) {
    return null;
  }

  return uint8ArrayToString(decrypted);
}

/**
 * Returns the salt the store was encrypted with, minting one only on a genuine
 * first run.
 *
 * The salt feeds key derivation, so a fresh one turns the correct PIN into a
 * different master key and makes every existing record undecryptable — with no
 * server copy and no mnemonic path back (SEC-20260721-010). Regenerating it
 * over an existing store is therefore never a recovery; it is the loss.
 *
 * "First run" is decided by whether an identity record exists, not by whether
 * the salt does. A missing salt beside a present identity means the salt was
 * lost, and the only safe response is to refuse.
 */
async function getOrCreateEncryptionSalt(): Promise<Uint8Array> {
  const existing = await get<string>(STORAGE_KEYS.ENCRYPTION_SALT);

  if (existing) {
    try {
      const decoded = decodeBase64(existing);
      if (decoded.length === 16) return decoded;
    } catch {
      // Falls through to the guard below — a malformed salt over an existing
      // store is the same condition as a missing one, and equally unsafe to
      // paper over.
    }
  }

  const storeExists = (await get(STORAGE_KEYS.IDENTITY)) !== undefined;
  if (storeExists) {
    raiseIntegrityFailure(STORAGE_KEYS.ENCRYPTION_SALT, "salt-missing");
  }

  const salt = nacl.randomBytes(16);
  await set(STORAGE_KEYS.ENCRYPTION_SALT, encodeBase64(salt));
  return salt;
}

/**
 * The master-key cache was removed (SEC-20260721-014). It was keyed by an
 * unsalted SHA-512 of the PIN — a value orders of magnitude cheaper to brute-force
 * than the 600k-iteration KDF, sitting in memory as a PIN oracle, and (being a JS
 * string) impossible to wipe. Any fast cache guard that distinguishes PINs with
 * all inputs in memory is such an oracle, so the cache is gone rather than
 * reworked. `deriveMasterKeyFromPin` now re-derives on every call; every caller is
 * a one-shot user action (setup / unlock / recover / change-PIN / hidden-account /
 * delete), so there is no hot path that needed caching.
 *
 * Kept as an exported no-op because `vaultClear()` and tests still call it, and
 * the master key itself now lives only in the key vault.
 */
export function clearCachedMasterKey(): void {
  // Intentionally empty — nothing is cached here any more. SEC-20260721-014.
}

/**
 * Derives and returns the master encryption key from a PIN.
 * Re-derives on every call (no cache — SEC-20260721-014).
 * This is the ONLY function that should accept a raw PIN for key derivation.
 */
// While a panic wipe is in progress, persistence is disabled so pending or
// in-flight debounced writes cannot re-create cleared data. It is reset when a
// fresh session derives its master key (setup/unlock). SEC-20260621-016.
let wipeInProgress = false;

/**
 * Raised when a record exists but cannot be turned back into data — the
 * ciphertext failed to open, or it opened and the payload did not parse.
 *
 * This is deliberately NOT the same condition as "nothing stored". Treating the
 * two alike is what SEC-20260721-002 describes: a failed load read as an empty
 * state, which the next write then makes true. Ratchet state is recoverable
 * from neither the server (blind relay) nor the mnemonic (identity only), so
 * that write is final.
 */
export class StorageIntegrityError extends Error {
  constructor(
    /** Which record failed, for the caller to report — never its contents. */
    readonly record: string,
    readonly reason: "undecryptable" | "unparseable" | "salt-missing",
  ) {
    super(`Stored record "${record}" is ${reason}`);
    this.name = "StorageIntegrityError";
  }
}

/**
 * Latched on the first integrity failure of a session; blocks every write for
 * the rest of it.
 *
 * The throw above is the signal, but a caller that swallows it must not be able
 * to cause the loss anyway. This latch is what makes the guarantee independent
 * of caller discipline: while it is set, no save can overwrite the ciphertext
 * that failed to load. Same mechanism as `wipeInProgress`, opposite trigger.
 *
 * Cleared only by `deriveMasterKeyFromPin` — a new unlock is the one event that
 * can legitimately mean the previous failure no longer applies (different PIN,
 * hence a different master key).
 */
let integrityFailure = false;

function raiseIntegrityFailure(
  record: string,
  reason: "undecryptable" | "unparseable" | "salt-missing",
): never {
  integrityFailure = true;
  throw new StorageIntegrityError(record, reason);
}

/** True once a load has failed in this session; persistence is disabled. */
export function hasStorageIntegrityFailure(): boolean {
  return integrityFailure;
}

/** Writes are refused while a wipe is running or after an integrity failure. */
function persistenceBlocked(): boolean {
  return wipeInProgress || integrityFailure;
}

export async function deriveMasterKeyFromPin(pin: string): Promise<Uint8Array> {
  wipeInProgress = false;
  integrityFailure = false;
  // Purge any orphaned change-PIN snapshot (old-key-encrypted material left by an
  // interrupted changePin before the snapshot mechanism was removed). SEC-20260721-009.
  await del(STORAGE_KEYS.CHANGEPIN_BACKUP);
  const salt = await getOrCreateEncryptionSalt();
  return deriveKeyFromPin(pin, salt);
}

/**
 * Internal helper: returns the master key. Accepts the already-derived key directly.
 * All storage functions now use this instead of raw PINs.
 */
function resolveMasterKey(masterKey: Uint8Array): Uint8Array {
  return masterKey;
}

function encryptWithKey(
  data: string,
  masterKey: Uint8Array,
): EncryptedDataV2 {
  const key = resolveMasterKey(masterKey);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const messageBytes = stringToUint8Array(data);
  const ciphertext = nacl.secretbox(messageBytes, nonce, key);

  return {
    v: 2,
    ciphertext: encodeBase64(ciphertext),
    nonce: encodeBase64(nonce),
  };
}

async function decryptFromStorage(
  encrypted: EncryptedData,
  masterKey: Uint8Array,
): Promise<string | null> {
  if ((encrypted as EncryptedDataV2).v === 2) {
    const key = resolveMasterKey(masterKey);
    const nonce = decodeBase64((encrypted as EncryptedDataV2).nonce);
    const ciphertext = decodeBase64((encrypted as EncryptedDataV2).ciphertext);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    return decrypted ? uint8ArrayToString(decrypted) : null;
  }

  // v1 legacy records contain their own embedded salt and require a raw PIN
  // to derive the key. This path is only reachable during migration (first unlock
  // after upgrade). Callers that may encounter v1 data must pass `legacyPin` via
  // the dedicated `decryptFromStorageV1Compat` helper.
  return null;
}

/**
 * Сохраняет ключи идентификации (encrypted with master key).
 */
export async function saveIdentityKeys(
  keys: IdentityKeys,
  masterKey: Uint8Array,
): Promise<void> {
  const data = JSON.stringify(keys);
  const encrypted = encryptWithKey(data, masterKey);
  await set(STORAGE_KEYS.IDENTITY, encrypted);

  // Store a PIN verification hash so we can validate PINs at unlock.
  // The hash is already stored by deriveMasterKeyFromPin callers.
}

/**
 * Save PIN verification token (called at setup / unlock time).
 * Derives a key via PBKDF2 (600K iterations) and encrypts a known sentinel.
 * Verification: derive key from candidate PIN, try to decrypt. Success = correct PIN.
 */
export async function savePinHash(pin: string): Promise<void> {
  const salt = nacl.randomBytes(16);
  const key = await deriveKeyFromPinWithIterations(pin, salt, 600_000);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const sentinel = stringToUint8Array("LUME_PIN_VERIFY");
  const ciphertext = nacl.secretbox(sentinel, nonce, key);
  const token = JSON.stringify({
    v: 2,
    salt: encodeBase64(salt),
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(ciphertext),
  });
  await set(STORAGE_KEYS.PIN_HASH, token);
}

/**
 * Verifies a PIN against the sentinel token written by `savePinHash`.
 *
 * The token existed but nothing ever read it. It is what makes "wrong PIN"
 * separable from "damaged store": both make `secretbox.open` return null on the
 * identity blob, and only this token can say which happened. Without it, a
 * mistyped PIN and a corrupted record are the same event to the storage layer —
 * the ambiguity SEC-20260721-002 asks to resolve before surfacing anything.
 *
 * Returns `null` when there is no token to check against — an older store, where
 * the question cannot be answered rather than answered wrongly.
 */
async function verifyPinToken(pin: string): Promise<boolean | null> {
  const raw = await get<string>(STORAGE_KEYS.PIN_HASH);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as {
      v?: number;
      salt: string;
      nonce: string;
      ciphertext: string;
    };
    if (parsed.v !== 2) return null;

    const key = await deriveKeyFromPinWithIterations(
      pin,
      decodeBase64(parsed.salt),
      600_000,
    );
    const opened = nacl.secretbox.open(
      decodeBase64(parsed.ciphertext),
      decodeBase64(parsed.nonce),
      key,
    );
    key.fill(0);

    return opened !== null && uint8ArrayToString(opened) === "LUME_PIN_VERIFY";
  } catch {
    // A malformed token cannot answer the question either way.
    return null;
  }
}

/**
 * Загружает ключи идентификации.
 * Accepts a derived master key. For v1 legacy data, pass `legacyPin` to allow migration.
 */
export async function loadIdentityKeys(
  masterKey: Uint8Array,
  legacyPin?: string,
): Promise<IdentityKeys | null> {
  const encrypted = await get<EncryptedData>(STORAGE_KEYS.IDENTITY);

  if (!encrypted) {
    return null;
  }

  let decrypted = await decryptFromStorage(encrypted, masterKey);

  // v1 fallback: try legacy PIN-based decryption and re-encrypt as v2
  if (!decrypted && legacyPin && !((encrypted as EncryptedDataV2).v === 2)) {
    decrypted = await decryptWithPin(encrypted as EncryptedDataV1, legacyPin);
    if (decrypted) {
      // Migrate to v2 format
      const reEncrypted = encryptWithKey(decrypted, masterKey);
      await set(STORAGE_KEYS.IDENTITY, reEncrypted);
    }
  }

  if (!decrypted) {
    // A record was present and did not open. Two very different causes produce
    // that: the PIN was wrong, or the blob is damaged. Only the sentinel token
    // can tell them apart, and getting it wrong is costly in both directions —
    // latching on a typo would disable persistence for the session, while
    // reporting corruption as a bad PIN is what let SEC-20260721-002 destroy
    // data quietly.
    //
    // Unlock is the only caller where a wrong PIN is reachable; every other
    // loader runs after this one has succeeded, so their key is already known
    // good and a failure there is unambiguously corruption.
    const pinIsCorrect = legacyPin ? await verifyPinToken(legacyPin) : null;

    if (pinIsCorrect === true) {
      raiseIntegrityFailure(STORAGE_KEYS.IDENTITY, "undecryptable");
    }

    // `false` — wrong PIN, the ordinary case: the caller reports it and the
    // store is untouched. `null` — no usable token, so the question is
    // unanswerable; treat it as a bad PIN rather than latch on a guess.
    return null;
  }

  try {
    return JSON.parse(decrypted) as IdentityKeys;
  } catch {
    // Decryption succeeded, so the PIN and master key were right and the blob
    // was damaged at rest. Deleting the identity and PIN token here — the
    // previous behaviour — destroyed the account for any user who had not kept
    // their mnemonic, in response to a condition that may be repairable by hand
    // (SEC-20260721-012). Preserve the record and surface instead.
    raiseIntegrityFailure(STORAGE_KEYS.IDENTITY, "unparseable");
  }
}

/**
 * Проверяет, существует ли аккаунт
 */
export async function hasAccount(): Promise<boolean> {
  const identity = await get(STORAGE_KEYS.IDENTITY);
  return identity !== undefined;
}

// ==================== Контакты ====================

export interface Contact {
  id: string;
  username: string;
  publicKey: string;
  exchangeKey: string;
  displayName?: string;
  addedAt: number;
  verified?: boolean;
  verifiedAt?: number;
  isHidden?: boolean;
}

/**
 * Сохраняет список контактов
 */
export async function saveContacts(
  contacts: Contact[],
  masterKey: Uint8Array,
): Promise<void> {
  if (persistenceBlocked()) return;
  const data = JSON.stringify(contacts);
  const encrypted = encryptWithKey(data, masterKey);
  await set(STORAGE_KEYS.CONTACTS, encrypted);
}

/**
 * Загружает список контактов
 */
export async function loadContacts(masterKey: Uint8Array): Promise<Contact[]> {
  const encrypted = await get<EncryptedData>(STORAGE_KEYS.CONTACTS);

  if (!encrypted) {
    return [];
  }

  const decrypted = await decryptFromStorage(encrypted, masterKey);

  if (!decrypted) {
    raiseIntegrityFailure(STORAGE_KEYS.CONTACTS, "undecryptable");
  }

  try {
    const parsed = JSON.parse(decrypted) as unknown;
    return Array.isArray(parsed) ? (parsed as Contact[]) : [];
  } catch {
    raiseIntegrityFailure(STORAGE_KEYS.CONTACTS, "unparseable");
  }
}

// ==================== Chats ====================

export async function saveChats(chats: Chat[], masterKey: Uint8Array): Promise<void> {
  if (persistenceBlocked()) return;
  const data = JSON.stringify(chats);
  const encrypted = encryptWithKey(data, masterKey);
  await set(STORAGE_KEYS.CHATS, encrypted);
}

export async function loadChats(masterKey: Uint8Array): Promise<Chat[]> {
  const encrypted = await get<EncryptedData>(STORAGE_KEYS.CHATS);

  if (!encrypted) {
    return [];
  }

  const decrypted = await decryptFromStorage(encrypted, masterKey);

  if (!decrypted) {
    raiseIntegrityFailure(STORAGE_KEYS.CHATS, "undecryptable");
  }

  try {
    const parsed = JSON.parse(decrypted) as unknown;
    return Array.isArray(parsed) ? (parsed as Chat[]) : [];
  } catch {
    raiseIntegrityFailure(STORAGE_KEYS.CHATS, "unparseable");
  }
}

// ==================== Group Messages ====================

export async function saveGroupMessages(
  messagesByGroup: Record<string, Message[]>,
  masterKey: Uint8Array,
): Promise<void> {
  if (persistenceBlocked()) return;
  const data = JSON.stringify(messagesByGroup);
  const encrypted = encryptWithKey(data, masterKey);
  await set(STORAGE_KEYS.GROUP_MESSAGES, encrypted);
}

export async function loadGroupMessages(
  masterKey: Uint8Array,
): Promise<Record<string, Message[]>> {
  const encrypted = await get<EncryptedData>(STORAGE_KEYS.GROUP_MESSAGES);

  if (!encrypted) {
    return {};
  }

  const decrypted = await decryptFromStorage(encrypted, masterKey);

  if (!decrypted) {
    raiseIntegrityFailure(STORAGE_KEYS.GROUP_MESSAGES, "undecryptable");
  }

  try {
    const parsed = JSON.parse(decrypted) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, Message[]>;
    }
    return {};
  } catch {
    raiseIntegrityFailure(STORAGE_KEYS.GROUP_MESSAGES, "unparseable");
  }
}

// ==================== Prekeys (X3DH) ====================

export interface LocalPreKeyMaterial {
  signedPreKey: KeyPair;
  oneTimePreKeys: KeyPair[];
  updatedAt: number;
  /** Timestamp (ms) when the current SPK was generated. Used for rotation checks. */
  spkCreatedAt?: number;
  /** Previous SPK kept during grace period so pending X3DH sessions can still complete. */
  previousSignedPreKey?: KeyPair;
  /** Timestamp (ms) when the previous SPK was retired. */
  previousSpkRetiredAt?: number;
}

export async function savePreKeyMaterial(
  material: LocalPreKeyMaterial,
  masterKey: Uint8Array,
): Promise<void> {
  const data = JSON.stringify(material);
  const encrypted = encryptWithKey(data, masterKey);
  await set(STORAGE_KEYS.PREKEYS, encrypted);
}

export async function loadPreKeyMaterial(
  masterKey: Uint8Array,
): Promise<LocalPreKeyMaterial | null> {
  const encrypted = await get<EncryptedData>(STORAGE_KEYS.PREKEYS);
  if (!encrypted) return null;

  const decrypted = await decryptFromStorage(encrypted, masterKey);
  if (!decrypted) raiseIntegrityFailure(STORAGE_KEYS.PREKEYS, "undecryptable");

  try {
    const parsed = JSON.parse(decrypted) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const material = parsed as LocalPreKeyMaterial;
    if (!material.signedPreKey || !Array.isArray(material.oneTimePreKeys))
      return null;
    return material;
  } catch {
    raiseIntegrityFailure(STORAGE_KEYS.PREKEYS, "unparseable");
  }
}

/**
 * Looks up a one-time prekey by public key WITHOUT consuming it. The OPK must
 * only be deleted after the first X3DH message authenticates, so bogus initial
 * messages cannot deplete the local pool. SEC-20260621-008.
 */
export async function findOneTimePreKey(
  publicKey: string,
  masterKey: Uint8Array,
): Promise<KeyPair | null> {
  const material = await loadPreKeyMaterial(masterKey);
  if (!material) return null;
  const found = material.oneTimePreKeys.find((k) => k.publicKey === publicKey);
  return found ?? null;
}

/** Removes a one-time prekey after it has been successfully used. */
export async function deleteOneTimePreKey(
  publicKey: string,
  masterKey: Uint8Array,
): Promise<void> {
  const material = await loadPreKeyMaterial(masterKey);
  if (!material) return;
  const index = material.oneTimePreKeys.findIndex(
    (k) => k.publicKey === publicKey,
  );
  if (index < 0) return;
  material.oneTimePreKeys.splice(index, 1);
  material.updatedAt = Date.now();
  await savePreKeyMaterial(material, masterKey);
}

/** Looks up and removes a one-time prekey in one step (lookup + delete). */
export async function consumeOneTimePreKey(
  publicKey: string,
  masterKey: Uint8Array,
): Promise<KeyPair | null> {
  const found = await findOneTimePreKey(publicKey, masterKey);
  if (!found) return null;
  await deleteOneTimePreKey(publicKey, masterKey);
  return found;
}

// ==================== Сессии (Double Ratchet) ====================

export type RatchetSessions = Record<string, SerializedSession>;

export async function saveRatchetSessions(
  sessions: RatchetSessions,
  masterKey: Uint8Array,
): Promise<void> {
  if (persistenceBlocked()) return;
  const data = JSON.stringify(sessions);
  const encrypted = encryptWithKey(data, masterKey);
  await set(STORAGE_KEYS.SESSIONS, encrypted);
}

export async function loadRatchetSessions(
  masterKey: Uint8Array,
): Promise<RatchetSessions> {
  const encrypted = await get<EncryptedData>(STORAGE_KEYS.SESSIONS);
  if (!encrypted) return {};

  const decrypted = await decryptFromStorage(encrypted, masterKey);
  if (!decrypted) raiseIntegrityFailure(STORAGE_KEYS.SESSIONS, "undecryptable");

  try {
    const parsed = JSON.parse(decrypted) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return {};
    return parsed as RatchetSessions;
  } catch {
    raiseIntegrityFailure(STORAGE_KEYS.SESSIONS, "unparseable");
  }
}

export async function deleteRatchetSession(
  contactId: string,
  masterKey: Uint8Array,
): Promise<void> {
  const sessions = await loadRatchetSessions(masterKey);
  if (!(contactId in sessions)) return;
  delete sessions[contactId];
  await saveRatchetSessions(sessions, masterKey);
}

// ==================== Attachment decrypt keys ====================
// Per-file decrypt key/nonce, kept out of message/Zustand state and persisted
// encrypted at rest, keyed by fileId. SEC-20260621-004.

export type AttachmentKeys = Record<string, { key: string; nonce: string }>;

export async function saveAttachmentKeys(
  keys: AttachmentKeys,
  masterKey: Uint8Array,
): Promise<void> {
  if (persistenceBlocked()) return;
  const data = JSON.stringify(keys);
  const encrypted = encryptWithKey(data, masterKey);
  await set(STORAGE_KEYS.ATTACHMENT_KEYS, encrypted);
}

export async function loadAttachmentKeys(
  masterKey: Uint8Array,
): Promise<AttachmentKeys> {
  const encrypted = await get<EncryptedData>(STORAGE_KEYS.ATTACHMENT_KEYS);
  if (!encrypted) return {};

  const decrypted = await decryptFromStorage(encrypted, masterKey);
  if (!decrypted) raiseIntegrityFailure(STORAGE_KEYS.ATTACHMENT_KEYS, "undecryptable");

  try {
    const parsed = JSON.parse(decrypted) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    return parsed as AttachmentKeys;
  } catch {
    raiseIntegrityFailure(STORAGE_KEYS.ATTACHMENT_KEYS, "unparseable");
  }
}

// ==================== PIN Brute-force Protection ====================

// PIN-attempt lockout.
//
// This is a UX guard against accidental mistyping, NOT a security control against
// an attacker holding the device. The record lives in the same IndexedDB the
// attacker can read and write, so it can be deleted or reset between guesses, and
// it cannot be cryptographically bound: at a *failed* attempt there is no master
// key yet to authenticate it with (the key is what the attempt is trying to
// derive). The real barrier against brute-force is the entropy of the secret
// itself — see SEC-20260721-020, which raises it to an 8+ character alphanumeric
// passphrase. Owner decision (Bogdan): keep the lockout as a mistype guard and
// document it as such rather than present it as anti-attacker hardening.
// SEC-20260721-008.
let failedPinAttempts = 0;
let lockedUntil = 0;
let lockoutLoaded = false;

const LOCKOUT_THRESHOLDS = [
  { attempts: 3, lockSeconds: 15 },
  { attempts: 5, lockSeconds: 60 },
  { attempts: 8, lockSeconds: 300 },
  { attempts: 12, lockSeconds: 900 },
];

/**
 * Load lockout state from IDB (once). Survives page refresh.
 */
async function loadLockoutState(): Promise<void> {
  if (lockoutLoaded) return;
  lockoutLoaded = true;
  try {
    const state = await get<{ attempts: number; lockedUntil: number }>(STORAGE_KEYS.LOCKOUT);
    if (state) {
      failedPinAttempts = state.attempts;
      lockedUntil = state.lockedUntil;
    }
  } catch {
    // ignore
  }
}

async function persistLockoutState(): Promise<void> {
  try {
    await set(STORAGE_KEYS.LOCKOUT, { attempts: failedPinAttempts, lockedUntil });
  } catch {
    // ignore
  }
}

export async function checkPinLockout(): Promise<void> {
  await loadLockoutState();
  if (lockedUntil > Date.now()) {
    const remaining = Math.ceil((lockedUntil - Date.now()) / 1000);
    throw new Error(`Too many attempts. Try again in ${remaining}s`);
  }
}

export async function recordPinFailure(): Promise<void> {
  failedPinAttempts++;
  for (let i = LOCKOUT_THRESHOLDS.length - 1; i >= 0; i--) {
    const threshold = LOCKOUT_THRESHOLDS[i];
    if (threshold && failedPinAttempts >= threshold.attempts) {
      lockedUntil = Date.now() + threshold.lockSeconds * 1000;
      break;
    }
  }
  await persistLockoutState();
}

export async function resetPinFailures(): Promise<void> {
  failedPinAttempts = 0;
  lockedUntil = 0;
  await persistLockoutState();
}

// ==================== Hidden Chat PIN Hashing ====================

export const HIDDEN_PIN_PBKDF2_ITERATIONS = 600_000; // OWASP 2023 for PBKDF2-SHA256
const LEGACY_HIDDEN_PIN_ITERATIONS = 100_000;

/**
 * Bounds on the iteration count read back from a stored hidden-chat PIN hash.
 *
 * The count is a field inside a string in IndexedDB, so it is untrusted input to
 * this process, not a constant. Unbounded, it is two separate problems:
 *
 *   - **downgrade.** Rewriting the stored hash to `salt:1:hash` makes the PIN
 *     derivation one PBKDF2 round, which is offline-brute-forceable at once. The
 *     floor is the legacy count, so a rewrite can never weaken it below what the
 *     oldest supported format already used.
 *   - **denial of service.** `salt:99999999999:hash` makes the device sit in
 *     `deriveBits` on every unlock attempt.
 *
 * A non-numeric segment parses to NaN, which previously reached `deriveBits`
 * directly.
 */
const MIN_HIDDEN_PIN_ITERATIONS = LEGACY_HIDDEN_PIN_ITERATIONS;
const MAX_HIDDEN_PIN_ITERATIONS = 10_000_000;

/**
 * Constant-time comparison to prevent timing attacks.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    const av = a[i];
    const bv = b[i];
    // Unreachable inside the bound, and deliberately not `?? 0`: two missing
    // bytes would then compare *equal*, which is the wrong direction to fail for
    // a hash check. The early return is independent of the compared values, so
    // for every reachable input the loop still runs in constant time.
    if (av === undefined || bv === undefined) return false;
    diff |= av ^ bv;
  }
  return diff === 0;
}

/**
 * Хеширует PIN скрытых чатов через PBKDF2.
 * Format: "salt:iterations:hash" (base64-encoded salt and hash).
 */
export async function hashHiddenChatPin(pin: string): Promise<string> {
  const salt = nacl.randomBytes(16);
  const key = await deriveKeyFromPinWithIterations(pin, salt, HIDDEN_PIN_PBKDF2_ITERATIONS);
  return `${encodeBase64(salt)}:${HIDDEN_PIN_PBKDF2_ITERATIONS}:${encodeBase64(key)}`;
}

/**
 * Проверяет PIN скрытых чатов против сохранённого хеша.
 * Supports new format "salt:iterations:hash" and legacy "salt:hash" (100k iterations).
 * Uses constant-time comparison to prevent timing attacks.
 */
export async function verifyHiddenChatPin(
  input: string,
  storedHash: string,
): Promise<boolean> {
  const parts = storedHash.split(':');

  let salt: Uint8Array;
  let expectedBytes: Uint8Array;
  let iterations: number;

  // Destructured rather than indexed: a stored hash is untrusted input, and a
  // missing segment must refuse the PIN rather than be asserted away.
  if (parts.length === 3) {
    // New format: "salt:iterations:hash"
    const [saltPart, iterationsPart, hashPart] = parts;
    if (!saltPart || !iterationsPart || !hashPart) return false;
    const parsedIterations = Number.parseInt(iterationsPart, 10);
    if (
      !Number.isInteger(parsedIterations) ||
      parsedIterations < MIN_HIDDEN_PIN_ITERATIONS ||
      parsedIterations > MAX_HIDDEN_PIN_ITERATIONS
    ) {
      return false;
    }
    salt = decodeBase64(saltPart);
    iterations = parsedIterations;
    expectedBytes = decodeBase64(hashPart);
  } else if (parts.length === 2) {
    // Legacy format: "salt:hash" (100k iterations)
    const [saltPart, hashPart] = parts;
    if (!saltPart || !hashPart) return false;
    salt = decodeBase64(saltPart);
    iterations = LEGACY_HIDDEN_PIN_ITERATIONS;
    expectedBytes = decodeBase64(hashPart);
  } else {
    return false;
  }

  const derivedBytes = await deriveKeyFromPinWithIterations(input, salt, iterations);
  return constantTimeEqual(expectedBytes, derivedBytes);
}

/**
 * Checks if stored PIN hash uses the legacy 2-part format and needs re-hashing.
 */
export function isLegacyHiddenPinHash(storedHash: string): boolean {
  return storedHash.split(':').length === 2;
}

/**
 * Checks whether an encrypted hidden chat PIN exists in storage (without decrypting).
 * Useful for consistency checks where masterKey may not be available yet.
 */
export async function hasHiddenChatPin(): Promise<boolean> {
  const raw = await get<EncryptedDataV2 | string>(STORAGE_KEYS.HIDDEN_CHAT_PIN);
  if (!raw) return false;
  if (typeof raw === "string") return raw.length > 0;
  if (typeof raw === "object" && (raw as EncryptedDataV2).v === 2) return true;
  return false;
}

// ==================== Настройки ====================

export interface Settings {
  username?: string;
  userId?: string;
  theme: "light" | "dark" | "system";
  notifications: boolean;
  selfDestructDefault: number | null;
  hiddenChatsEnabled: boolean;
  /** Hashed hidden chat PIN ("salt:iterations:hash" format, legacy: "salt:hash") — never stored in plaintext */
  hiddenChatPinHash?: string;
}

const DEFAULT_SETTINGS: Settings = {
  theme: "system",
  notifications: true,
  selfDestructDefault: null,
  hiddenChatsEnabled: false,
};

/**
 * Сохраняет настройки.
 * The hiddenChatPinHash is stored separately and encrypted with the master key.
 * Non-sensitive fields (theme, notifications, etc.) stay plaintext so they can be read pre-auth.
 *
 * @param masterKey - Required when hiddenChatPinHash is being saved. Optional otherwise
 *                    (e.g. when only toggling theme before unlock).
 */
export async function saveSettings(
  settings: Settings,
  masterKey?: Uint8Array,
): Promise<void> {
  // Strip hiddenChatPinHash from plaintext store
  const { hiddenChatPinHash, ...safeSettings } = settings;
  await set(STORAGE_KEYS.SETTINGS, safeSettings);

  // Persist hidden chat PIN hash encrypted with masterKey. Fail closed: never
  // store the hash unencrypted, even on legacy/migration paths. SEC-20260621-009.
  if (hiddenChatPinHash !== undefined) {
    if (!masterKey) {
      throw new Error('saveSettings: masterKey is required to persist hiddenChatPinHash');
    }
    const encrypted = encryptWithKey(hiddenChatPinHash, masterKey);
    await set(STORAGE_KEYS.HIDDEN_CHAT_PIN, encrypted);
  }
}

/**
 * Загружает настройки.
 * Merges the encrypted hiddenChatPinHash back into the Settings object.
 *
 * @param masterKey - When provided, decrypts the hidden chat PIN hash.
 *                    Without it, hiddenChatPinHash will be omitted (pre-auth reads).
 */
export async function loadSettings(masterKey?: Uint8Array): Promise<Settings> {
  const settings = await get<Settings>(STORAGE_KEYS.SETTINGS);
  const base = settings || DEFAULT_SETTINGS;

  // Merge hidden chat PIN hash from separate encrypted store
  const raw = await get<EncryptedDataV2 | string>(STORAGE_KEYS.HIDDEN_CHAT_PIN);
  if (!raw) return base;

  // Encrypted (v2) format — requires masterKey to decrypt
  if (typeof raw === "object" && (raw as EncryptedDataV2).v === 2) {
    if (!masterKey) {
      // Can't decrypt without masterKey — return base with flag that PIN exists
      return { ...base, hiddenChatsEnabled: base.hiddenChatsEnabled };
    }
    const decrypted = await decryptFromStorage(raw as EncryptedDataV2, masterKey);
    if (decrypted) {
      return { ...base, hiddenChatPinHash: decrypted };
    }
    return base;
  }

  // Legacy plaintext format. Never surface the hash on a pre-auth read: without a
  // master key, omit it entirely (do not migrate, do not return). Only when
  // authenticated do we migrate it to the encrypted store and return it. SEC-20260621-009.
  if (typeof raw === "string" && raw.length > 0) {
    if (!masterKey) {
      return base;
    }
    // Migrate: encrypt and re-save
    const encrypted = encryptWithKey(raw, masterKey);
    await set(STORAGE_KEYS.HIDDEN_CHAT_PIN, encrypted);
    return { ...base, hiddenChatPinHash: raw };
  }

  return base;
}

// ==================== Panic Mode ====================

/**
 * Полностью очищает все данные (Panic Mode)
 */
export async function panicWipe(): Promise<void> {
  // Disable persistence for the rest of this session so any pending/in-flight
  // debounced save cannot re-create the data we are about to clear.
  wipeInProgress = true;
  await clear();

  // Очищаем также localStorage и sessionStorage
  if (typeof localStorage !== "undefined") {
    localStorage.clear();
  }
  if (typeof sessionStorage !== "undefined") {
    sessionStorage.clear();
  }

  // Очищаем Service Worker caches
  if (typeof caches !== "undefined") {
    try {
      const names = await caches.keys();
      await Promise.all(names.map((n) => caches.delete(n)));
    } catch {
      // caches API may be unavailable in some contexts
    }
  }
}

/**
 * Удаляет только ключи (оставляет настройки)
 */
export async function deleteKeys(): Promise<void> {
  await del(STORAGE_KEYS.IDENTITY);
  await del(STORAGE_KEYS.SESSIONS);
  await del(STORAGE_KEYS.PREKEYS);
  await del(STORAGE_KEYS.PIN_HASH);
}

/**
 * Clears every record belonging to the account currently on this device, so a
 * newly created or restored account starts from nothing.
 *
 * Without this, setup keeps the previous account's store and the encryption salt
 * is reused. Two distinct failures follow, both reported from a real device:
 *
 *   - with the SAME pin the derived master key is identical, so the previous
 *     account's contacts and chats decrypt straight into the new one — one
 *     person's conversations shown under another's login;
 *   - with a different pin those records stop opening and the first loader hits
 *     `raiseIntegrityFailure`, which latches persistence off for the session and
 *     surfaces as "не удалось прочитать локальные данные".
 *
 * `deleteKeys()` is not enough (it leaves contacts, chats, settings and the salt)
 * and `panicWipe()` is too much: it latches `wipeInProgress`, which would then
 * discard everything the new account writes.
 */
export async function resetVaultForNewAccount(): Promise<void> {
  for (const key of Object.values(STORAGE_KEYS)) {
    await del(key);
  }
  // A fresh account gets a fresh salt; clearing the record above is what forces
  // `getOrCreateEncryptionSalt` to mint one instead of reusing the old.
  clearCachedMasterKey();
  integrityFailure = false;
}

/**
 * Удаляет контакт и его сессию
 */
export async function deleteContact(
  contactId: string,
  masterKey: Uint8Array,
): Promise<void> {
  const contacts = await loadContacts(masterKey);
  const filtered = contacts.filter((c) => c.id !== contactId);
  await saveContacts(filtered, masterKey);

  await deleteRatchetSession(contactId, masterKey);
}

// ==================== Change PIN ====================

/**
 * Меняет PIN-код: расшифровывает все данные старым ключом, перешифровывает новым.
 * Выбрасывает ошибку если старый PIN неверный.
 * Returns the new master key so the caller can update the store.
 */
export async function changePin(oldPin: string, newPin: string): Promise<Uint8Array> {
  // Brute-force lockout check
  await checkPinLockout();

  // Derive old master key and verify
  const oldMasterKey = await deriveMasterKeyFromPin(oldPin);
  const identity = await loadIdentityKeys(oldMasterKey, oldPin);
  if (!identity) {
    await recordPinFailure();
    throw new Error('Invalid current PIN');
  }

  // PIN verified — reset lockout counter
  await resetPinFailures();

  // Load all encrypted data with old key
  const contacts = await loadContacts(oldMasterKey);
  const chats = await loadChats(oldMasterKey);
  const sessions = await loadRatchetSessions(oldMasterKey);
  const prekeys = await loadPreKeyMaterial(oldMasterKey);
  const settingsData = await loadSettings(oldMasterKey);

  // No pre-change snapshot is taken. The previous CHANGEPIN_BACKUP mechanism was
  // never read by any recovery path, so it added no durability — it only left a
  // copy of every record, still encrypted under the OLD key, in IndexedDB after an
  // interrupted change. Any orphan written before this change is purged on the next
  // unlock (see deriveMasterKeyFromPin). SEC-20260721-009.

  // Generate a new encryption salt for new master key
  const newSalt = nacl.randomBytes(16);
  const newMasterKey = await deriveKeyFromPin(newPin, newSalt);

  // Store the new salt (used by v2 encrypt/decrypt)
  await set(STORAGE_KEYS.ENCRYPTION_SALT, encodeBase64(newSalt));

  // Re-save everything with new master key
  await saveIdentityKeys(identity, newMasterKey);
  await savePinHash(newPin);
  await saveContacts(contacts, newMasterKey);
  await saveChats(chats, newMasterKey);
  await saveRatchetSessions(sessions, newMasterKey);
  if (prekeys) {
    await savePreKeyMaterial(prekeys, newMasterKey);
  }

  // Re-encrypt hidden chat PIN hash with new master key (if set)
  if (settingsData.hiddenChatPinHash) {
    await saveSettings(settingsData, newMasterKey);
  }

  // Zero out old key material
  oldMasterKey.fill(0);

  return newMasterKey;
}

// ==================== Backup / Restore ====================

/**
 * Экспортирует все чувствительные данные (ключи, контакты, чаты, сессии, prekeys, настройки)
 * в один зашифрованный бэкап. Формат: base64(JSON{v, salt, nonce, ciphertext}).
 *
 * Accepts a masterKey (the current session key) plus a PIN for the backup envelope
 * encryption (backup uses its own salt).
 */
export async function exportEncryptedBackup(
  masterKey: Uint8Array,
  pin: string,
): Promise<string> {
  const payload = {
    identity: await loadIdentityKeys(masterKey),
    contacts: await loadContacts(masterKey),
    chats: await loadChats(masterKey),
    sessions: await loadRatchetSessions(masterKey),
    prekeys: await loadPreKeyMaterial(masterKey),
    settings: await loadSettings(masterKey),
  };

  const salt = nacl.randomBytes(16);
  const key = await deriveKeyFromPinWithIterations(pin, salt, BACKUP_PBKDF2_ITERATIONS);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const plaintext = stringToUint8Array(JSON.stringify(payload));
  try {
    const ciphertext = nacl.secretbox(plaintext, nonce, key);

    const envelope: BackupEnvelopeV2 = {
      v: 2,
      salt: encodeBase64(salt),
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(ciphertext),
      iterations: BACKUP_PBKDF2_ITERATIONS,
    };

    return encodeBase64(stringToUint8Array(JSON.stringify(envelope)));
  } finally {
    // Zero the derived backup key and the serialized plaintext (it contains all
    // sensitive data). SEC-20260621-023.
    key.fill(0);
    plaintext.fill(0);
  }
}

/**
 * Импортирует бэкап, созданный exportEncryptedBackup. Полностью очищает локальное хранилище.
 * Returns the new master key derived from the provided PIN so the caller can update the store.
 */
export async function importEncryptedBackup(
  encoded: string,
  pin: string,
): Promise<Uint8Array> {
  let envelope: BackupEnvelope;
  try {
    const json = uint8ArrayToString(decodeBase64(encoded));
    envelope = JSON.parse(json) as BackupEnvelope;
    if (
      (envelope.v !== 1 && envelope.v !== 2) ||
      !envelope.salt ||
      !envelope.nonce ||
      !envelope.ciphertext
    ) {
      throw new Error("Invalid envelope");
    }
  } catch {
    throw new Error("Неверный формат бэкапа");
  }

  const salt = decodeBase64(envelope.salt);
  const nonce = decodeBase64(envelope.nonce);
  const ciphertext = decodeBase64(envelope.ciphertext);

  // v2 envelopes store their iteration count; v1 used the legacy 100k default
  const iterations = envelope.v === 2
    ? (envelope as BackupEnvelopeV2).iterations
    : LEGACY_PBKDF2_ITERATIONS;
  // `iterations` is envelope metadata OUTSIDE the authenticated ciphertext, so it
  // is attacker-controlled before any integrity check. Bound it before it reaches
  // the KDF — a hostile value (e.g. 2e9) would occupy the thread indefinitely,
  // before decryption and before anything is destroyed. SEC-20260721-006.
  if (
    typeof iterations !== "number" ||
    !Number.isInteger(iterations) ||
    iterations < MIN_BACKUP_ITERATIONS ||
    iterations > MAX_BACKUP_ITERATIONS
  ) {
    throw new Error("Неверный формат бэкапа");
  }
  const key = await deriveKeyFromPinWithIterations(pin, salt, iterations);
  const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
  if (!decrypted) {
    throw new Error("Не удалось расшифровать бэкап (PIN?)");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(uint8ArrayToString(decrypted));
  } catch {
    throw new Error("Поврежденное содержимое бэкапа");
  }

  // Validate the structure BEFORE wiping anything. A backup that decrypts cleanly
  // (correct PIN) but is truncated to e.g. {"identity":null} would pass a bare cast,
  // and the panicWipe() below would already have destroyed the real store. Now the
  // pre-existing data survives a malformed payload. SEC-20260721-006.
  const parseResult = BackupPayloadSchema.safeParse(parsed);
  if (!parseResult.success) {
    throw new Error("Поврежденное содержимое бэкапа");
  }
  // Structure is validated above; the deep field types are not, so cast through
  // unknown. This is not the pre-fix bare cast — the wipe below is now guarded.
  const payload = parseResult.data as unknown as {
    identity: IdentityKeys | null;
    contacts: Contact[];
    chats: Chat[];
    sessions: RatchetSessions;
    prekeys: LocalPreKeyMaterial | null;
    settings: Settings;
  };

  // Полная очистка — safe now: the payload is structurally validated.
  await panicWipe();

  // Derive a fresh master key for storage
  const masterKey = await deriveMasterKeyFromPin(pin);

  // Восстановление
  if (payload.identity) {
    await saveIdentityKeys(payload.identity, masterKey);
  }
  await savePinHash(pin);
  if (payload.prekeys) {
    await savePreKeyMaterial(payload.prekeys, masterKey);
  }
  await saveContacts(payload.contacts || [], masterKey);
  await saveChats(payload.chats || [], masterKey);
  await saveRatchetSessions(payload.sessions || {}, masterKey);
  await saveSettings(payload.settings || DEFAULT_SETTINGS, masterKey);

  return masterKey;
}
