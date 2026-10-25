// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { decrypt as boxDecrypt, encrypt as boxEncrypt } from '@/crypto/keys';

export interface DecodedMessagePayload {
    content: string;
    timestamp: number;
    selfDestruct?: number | null;
}

interface EncryptedEnvelope {
    v: 1;
    alg: 'nacl-box';
    senderExchangeKey: string;
    ciphertext: string;
    nonce: string;
    timestamp: number;
    selfDestruct?: number | null;
}

interface LegacyEnvelope {
    content: string;
    timestamp?: number;
    selfDestruct?: number | null;
}

export function getSenderExchangeKeyFromPayload(payload: string): string | null {
    try {
        const parsed = JSON.parse(payload) as Partial<EncryptedEnvelope>;
        if (typeof parsed.senderExchangeKey === 'string' && parsed.senderExchangeKey.length > 0) {
            return parsed.senderExchangeKey;
        }
    } catch {
        // ignore invalid payloads
    }
    return null;
}

export function encodeMessagePayload(
    content: string,
    timestamp: number,
    selfDestruct: number | null | undefined,
    senderExchangePublicKey: string,
    senderExchangeSecretKey: string,
    recipientExchangePublicKey: string
): string {
    const plaintext = JSON.stringify({
        content,
        timestamp,
        selfDestruct: selfDestruct ?? null,
    });

    const plaintextBytes = new TextEncoder().encode(plaintext);
    const encrypted = boxEncrypt(
        plaintextBytes,
        recipientExchangePublicKey,
        senderExchangeSecretKey
    );

    const envelope: EncryptedEnvelope = {
        v: 1,
        alg: 'nacl-box',
        senderExchangeKey: senderExchangePublicKey,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        timestamp,
    };

    return JSON.stringify(envelope);
}

export function decodeMessagePayload(
    payload: string,
    recipientExchangeSecretKey: string,
    senderExchangePublicKey?: string
): DecodedMessagePayload | null {
    let parsed: unknown;

    try {
        parsed = JSON.parse(payload);
    } catch {
        return null;
    }

    const candidate = parsed as Partial<EncryptedEnvelope>;
    const isEncryptedEnvelope = candidate.alg === 'nacl-box'
        && typeof candidate.ciphertext === 'string'
        && typeof candidate.nonce === 'string';

    if (isEncryptedEnvelope) {
        const senderKey = senderExchangePublicKey || candidate.senderExchangeKey;
        if (typeof senderKey !== 'string' || senderKey.length === 0) {
            return null;
        }

        const decryptedBytes = boxDecrypt(
            candidate.ciphertext as string,
            candidate.nonce as string,
            senderKey,
            recipientExchangeSecretKey
        );

        if (!decryptedBytes) {
            return null;
        }

        try {
            const decrypted = JSON.parse(new TextDecoder().decode(decryptedBytes)) as LegacyEnvelope;
            if (typeof decrypted.content !== 'string') {
                return null;
            }
            return {
                content: decrypted.content,
                timestamp: typeof decrypted.timestamp === 'number'
                    ? decrypted.timestamp
                    : (typeof candidate.timestamp === 'number' ? candidate.timestamp : Date.now()),
                selfDestruct: decrypted.selfDestruct ?? null,
            };
        } catch {
            return null;
        }
    }

    // No plaintext fallback — all messages MUST be encrypted
    return null;
}
