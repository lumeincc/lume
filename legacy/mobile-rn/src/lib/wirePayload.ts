// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The plaintext that goes inside the ratchet — the wire contract between clients.
 *
 * This is the one shape both clients must agree on, and getting it wrong does not
 * fail loudly: the ratchet decrypts fine and the message simply renders as
 * "[Unable to decrypt message]". That is exactly what happened when this port
 * wrapped the text in `lib/messagePayload.ts` (an extra nacl-box layer): the web
 * client only ever uses that module in its tests, while its real send path emits
 * plain JSON.
 *
 * So the format is fixed here, deliberately small, and locked by a test:
 *
 *     { "content": string, "timestamp": number, ... }
 *
 * Unknown fields are ignored on receive, which is what lets the web add replies,
 * attachments and self-destruct without breaking this client.
 */

export interface WirePayload {
  content: string
  timestamp: number
  selfDestruct?: number | null
  /** Present on group fan-out; the relay never sees it. */
  groupId?: string
  /**
   * Sender-generated id, stable across retries of the same message.
   *
   * A send that times out is ambiguous: the relay may well have stored the
   * message and only the response was lost. The retry therefore has to happen,
   * and it produces a second, perfectly valid ciphertext — the recipient would
   * show the text twice. Carrying the id inside the sealed payload lets the
   * recipient recognise the repeat; the relay cannot see it, so it learns nothing
   * new. Optional in both directions: older senders omit it, and the web ignores
   * fields it does not know.
   */
  clientId?: string
}

export function encodeWirePayload(content: string, timestamp: number, clientId?: string): string {
  return JSON.stringify({ content, timestamp, ...(clientId ? { clientId } : {}) })
}

/** Fails closed: anything that is not a readable payload returns null. */
export function decodeWirePayload(raw: string): WirePayload | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (!parsed || typeof parsed !== 'object') return null

  const record = parsed as Record<string, unknown>
  if (typeof record.content !== 'string') return null

  return {
    content: record.content,
    timestamp: typeof record.timestamp === 'number' ? record.timestamp : Date.now(),
    selfDestruct: typeof record.selfDestruct === 'number' ? record.selfDestruct : null,
    ...(typeof record.groupId === 'string' ? { groupId: record.groupId } : {}),
    ...(typeof record.clientId === 'string' ? { clientId: record.clientId } : {}),
  }
}
