// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import type { EncryptedMessage, MessageHeader } from '@/crypto/ratchet';

export interface X3DHInitPayload {
  senderIdentityKey: string; // X25519 (base64)
  senderEphemeralKey: string; // X25519 (base64)
  recipientOneTimePreKey?: string | null; // X25519 (base64)
  /** Public key of the recipient signed prekey the sender used (current or grace SPK). */
  recipientSignedPreKey?: string; // X25519 (base64)
}

export interface RatchetEnvelopeV2 {
  v: 2;
  alg: 'lume-ratchet';
  header: MessageHeader;
  ciphertext: string;
  nonce: string;
  timestamp: number;
  /** @deprecated selfDestruct moved inside encrypted plaintext; kept for backward compat on receive */
  selfDestruct?: number | null;
  x3dh?: X3DHInitPayload;
}

export function encodeRatchetEnvelope(params: {
  encrypted: EncryptedMessage;
  timestamp: number;
  selfDestruct?: number | null;
  x3dh?: X3DHInitPayload;
}): string {
  const envelope: RatchetEnvelopeV2 = {
    v: 2,
    alg: 'lume-ratchet',
    header: params.encrypted.header,
    ciphertext: params.encrypted.ciphertext,
    nonce: params.encrypted.nonce,
    timestamp: params.timestamp,
    ...(params.x3dh ? { x3dh: params.x3dh } : {}),
  };
  return JSON.stringify(envelope);
}

export function parseRatchetEnvelope(payload: string): RatchetEnvelopeV2 | null {
  if (typeof payload !== 'string' || payload.length === 0) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    return null;
  }

  const candidate = parsed as Partial<RatchetEnvelopeV2>;
  if (candidate.v !== 2 || candidate.alg !== 'lume-ratchet') return null;

  if (
    !candidate.header
    || typeof candidate.ciphertext !== 'string'
    || typeof candidate.nonce !== 'string'
    || typeof candidate.timestamp !== 'number'
  ) {
    return null;
  }

  const header = candidate.header as Partial<MessageHeader>;
  if (
    typeof header.publicKey !== 'string'
    || typeof header.previousChainLength !== 'number'
    || typeof header.messageNumber !== 'number'
  ) {
    return null;
  }

  if (candidate.x3dh !== undefined && candidate.x3dh !== null) {
    const x3dh = candidate.x3dh as Partial<X3DHInitPayload>;
    if (typeof x3dh.senderIdentityKey !== 'string' || typeof x3dh.senderEphemeralKey !== 'string') {
      return null;
    }
    if (x3dh.recipientOneTimePreKey !== undefined && x3dh.recipientOneTimePreKey !== null) {
      if (typeof x3dh.recipientOneTimePreKey !== 'string') return null;
    }
    if (x3dh.recipientSignedPreKey !== undefined && x3dh.recipientSignedPreKey !== null) {
      if (typeof x3dh.recipientSignedPreKey !== 'string') return null;
    }
  }

  return candidate as RatchetEnvelopeV2;
}

