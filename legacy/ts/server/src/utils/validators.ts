// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { decodeBase64 } from 'tweetnacl-util'

const USERNAME_REGEX = /^[a-zA-Z0-9_]{3,32}$/
const UUID_LIKE_REGEX =
  /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/

export function isValidUsername(username: unknown): username is string {
  if (typeof username !== 'string') return false
  const normalized = username.trim()
  return USERNAME_REGEX.test(normalized)
}

export function isValidBase64Key(key: unknown, expectedLength = 32): key is string {
  if (typeof key !== 'string') return false
  try {
    const decoded = decodeBase64(key)
    return decoded.length === expectedLength
  } catch {
    return false
  }
}

export function isValidSignature(signature: unknown): signature is string {
  if (typeof signature !== 'string') return false
  try {
    return decodeBase64(signature).length === 64
  } catch {
    return false
  }
}

export function isValidUuidLike(value: unknown): value is string {
  if (typeof value !== 'string') return false
  return UUID_LIKE_REGEX.test(value.trim())
}

/**
 * Validates an array of messageIds for WebSocket read receipts.
 * Each id must be a non-empty string matching UUID-like format. Max 100 ids.
 */
export function isValidMessageIds(ids: unknown): ids is string[] {
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > 100) {
    return false
  }
  const seen = new Set<string>()
  for (const id of ids) {
    if (typeof id !== 'string') return false
    const trimmed = id.trim()
    if (trimmed.length === 0 || !UUID_LIKE_REGEX.test(trimmed)) return false
    if (seen.has(trimmed)) return false
    seen.add(trimmed)
  }
  return true
}

/**
 * Validates a recipientId field from WebSocket messages.
 */
export function isValidRecipientId(value: unknown): value is string {
  return isValidUuidLike(value)
}

export function isValidPrekeys(
  prekeys: unknown
): prekeys is Array<{ id: string; publicKey: string }> {
  if (!Array.isArray(prekeys) || prekeys.length > 500) {
    return false
  }

  const seen = new Set<string>()
  for (const item of prekeys) {
    if (!item || typeof item !== 'object') return false

    const candidate = item as { id?: unknown; publicKey?: unknown }
    if (
      typeof candidate.id !== 'string' ||
      candidate.id.trim().length === 0 ||
      candidate.id.length > 128
    ) {
      return false
    }
    if (seen.has(candidate.id)) return false

    if (!isValidBase64Key(candidate.publicKey)) {
      return false
    }

    seen.add(candidate.id)
  }

  return true
}
