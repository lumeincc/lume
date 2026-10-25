// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Shared Zod schemas — atomic building blocks.
 * Every external boundary uses these. No raw string validation anywhere.
 */

import { z } from 'zod'
import { decodeBase64 } from 'tweetnacl-util'

// ── Primitives ──────────────────────────────────────────────

/** UUID v4 format */
export const UuidSchema = z
  .string()
  .trim()
  .regex(
    /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/,
    'Invalid UUID format'
  )

/** Username: 3-32 alphanumeric + underscore */
export const UsernameSchema = z
  .string()
  .trim()
  .min(3, 'Username must be at least 3 characters')
  .max(32, 'Username must be at most 32 characters')
  .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')

/** Base64-encoded key with exact decoded byte length */
export function base64Key(expectedBytes = 32) {
  return z
    .string()
    .min(1, 'Key must not be empty')
    .refine(
      val => {
        try {
          return decodeBase64(val).length === expectedBytes
        } catch {
          return false
        }
      },
      { message: `Key must be exactly ${expectedBytes} bytes when decoded` }
    )
}

/** Ed25519 public key (32 bytes, base64) */
export const IdentityKeySchema = base64Key(32)

/** Ed25519 detached signature (64 bytes, base64) */
export const SignatureSchema = base64Key(64)

/** X25519/Ed25519 signed prekey (32 bytes, base64) */
export const SignedPrekeySchema = base64Key(32)

/** Unix timestamp in seconds or milliseconds */
export const TimestampSchema = z.number().int().positive()

// ── Compound types ──────────────────────────────────────────

/** One-time prekey for X3DH */
export const PrekeySchema = z.object({
  id: z.string().trim().min(1).max(128),
  publicKey: base64Key(32),
})

/** Array of prekeys with uniqueness constraint */
export const PrekeysArraySchema = z
  .array(PrekeySchema)
  .min(1)
  .max(500)
  .refine(
    keys => {
      const ids = keys.map(k => k.id)
      return new Set(ids).size === ids.length
    },
    { message: 'Prekey IDs must be unique' }
  )

/** Array of unique UUIDs (e.g. message IDs for acknowledge) */
export const UuidArraySchema = z
  .array(UuidSchema)
  .min(1)
  .max(500)
  .refine(ids => new Set(ids).size === ids.length, { message: 'IDs must be unique' })

/** Message ID array for read receipts (max 100) */
export const MessageIdsSchema = z
  .array(UuidSchema)
  .min(1)
  .max(100)
  .refine(ids => new Set(ids).size === ids.length, { message: 'Message IDs must be unique' })

// ── Encrypted payload validation ────────────────────────────

/** X3DH init payload */
const X3dhPayloadSchema = z.object({
  senderIdentityKey: base64Key(32),
  senderEphemeralKey: base64Key(32),
  recipientOneTimePreKey: base64Key(32).nullable().optional(),
  recipientSignedPreKey: base64Key(32).optional(),
})

/** Ratchet header */
const RatchetHeaderSchema = z.object({
  publicKey: base64Key(32),
  previousChainLength: z.number().int().nonnegative(),
  messageNumber: z.number().int().nonnegative(),
})

/**
 * Resource bounds the hand-rolled validator in `messages.ts` used to enforce.
 * They live here now that the route validates through this schema, so the Zod
 * schema is the single source of truth for the envelope (SEC-20260721-024).
 */
const MAX_CIPHERTEXT_BYTES = 64 * 1024
const SELF_DESTRUCT_MAX_SECONDS = 7 * 24 * 60 * 60

/** Base64 ciphertext, bounded by its decoded length */
const CiphertextSchema = z
  .string()
  .min(1)
  .refine(
    val => {
      try {
        const len = decodeBase64(val).length
        return len > 0 && len <= MAX_CIPHERTEXT_BYTES
      } catch {
        return false
      }
    },
    { message: `Ciphertext must be valid base64 and at most ${MAX_CIPHERTEXT_BYTES} bytes` }
  )

/** Double Ratchet envelope (v2) */
const RatchetEnvelopeSchema = z.object({
  v: z.literal(2),
  alg: z.literal('lume-ratchet'),
  header: RatchetHeaderSchema,
  ciphertext: CiphertextSchema,
  nonce: base64Key(24),
  timestamp: TimestampSchema,
  selfDestruct: z.number().min(0).max(SELF_DESTRUCT_MAX_SECONDS).nullable().optional(),
  x3dh: X3dhPayloadSchema.optional(),
})

/** Encrypted payload — v2 Double Ratchet only (legacy v1 nacl-box rejected) */
export const EncryptedPayloadSchema = RatchetEnvelopeSchema

/** Validate encrypted payload from raw string (parse JSON first) */
export function parseEncryptedPayload(raw: string): boolean {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 65536) return false
  try {
    const parsed: unknown = JSON.parse(raw)
    return EncryptedPayloadSchema.safeParse(parsed).success
  } catch {
    return false
  }
}

// ── Display name ────────────────────────────────────────────

export const DisplayNameSchema = z.string().trim().max(64).nullable()
