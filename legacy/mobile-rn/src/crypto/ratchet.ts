// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Double Ratchet Protocol Implementation
 * На основе Signal Protocol для обеспечения Forward Secrecy и Post-Compromise Security
 */

import nacl from 'tweetnacl';
import { encodeBase64, decodeBase64 } from 'tweetnacl-util';
import { generateExchangeKeyPair, verify, zeroBytes, type KeyPair } from './keys';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf, extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf.js';

// ==================== Константы ====================

const MAX_SKIP = 200; // Максимальное количество пропущенных сообщений за один рывок
const MAX_SKIPPED_KEYS = 500; // Максимальный размер хранилища пропущенных ключей

// ==================== Типы ====================

export interface DoubleRatchetSession {
    // Diffie-Hellman ратсчет
    dhSendingKeyPair: KeyPair;
    dhReceivingPublicKey: string | null;

    // Root key и chain keys
    rootKey: Uint8Array;
    sendingChainKey: Uint8Array | null;
    receivingChainKey: Uint8Array | null;

    // Счётчики сообщений
    sendingMessageNumber: number;
    receivingMessageNumber: number;
    previousSendingChainLength: number;

    // Пропущенные ключи сообщений
    skippedMessageKeys: Map<string, Uint8Array>;
}

export interface MessageHeader {
    publicKey: string;        // DH ratchet публичный ключ
    previousChainLength: number;  // N в предыдущем sending chain
    messageNumber: number;    // N в текущем sending chain
}

export interface EncryptedMessage {
    header: MessageHeader;
    ciphertext: string;
    nonce: string;
}

// ==================== KDF функции ====================

// Info-строки для domain separation в HKDF (предотвращают cross-protocol атаки)
const INFO_ROOT_KEY = new TextEncoder().encode('LUME_DoubleRatchet_RootKey');
const INFO_CHAIN_KEY = new TextEncoder().encode('LUME_DoubleRatchet_ChainKey');
const INFO_X3DH = new TextEncoder().encode('LUME_X3DH_SharedSecret');

/**
 * KDF для root key ratchet (RFC 5869 HKDF с @noble/hashes).
 * Salt = текущий root key, IKM = DH output.
 * Деривирует 64 байта: первые 32 = новый root key, вторые 32 = chain key.
 */
function kdfRk(rootKey: Uint8Array, dhOutput: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
    const prk = hkdfExtract(sha256, dhOutput, rootKey);
    const rootKeyOut = hkdfExpand(sha256, prk, INFO_ROOT_KEY, 32);
    const chainKeyOut = hkdfExpand(sha256, prk, INFO_CHAIN_KEY, 32);

    return {
        rootKey: rootKeyOut,
        chainKey: chainKeyOut,
    };
}

/**
 * KDF для chain key -> (next chain key, message key).
 * Signal spec: HMAC(ck, 0x01) → message key, HMAC(ck, 0x02) → next chain key.
 * Chain key is already a pseudorandom key, so direct HMAC is appropriate.
 */
function kdfCk(chainKey: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
    const messageKey = hmac(sha256, chainKey, new Uint8Array([0x01]));
    const nextChainKey = hmac(sha256, chainKey, new Uint8Array([0x02]));

    return {
        messageKey: messageKey.slice(0, 32),
        chainKey: nextChainKey.slice(0, 32),
    };
}

/**
 * Выполняет DH обмен ключами
 */
function dh(keyPair: KeyPair, publicKey: string): Uint8Array {
    const secretKeyBytes = decodeBase64(keyPair.secretKey);
    const publicKeyBytes = decodeBase64(publicKey);

    try {
        // Используем nacl.box.before для DH
        return nacl.box.before(publicKeyBytes, secretKeyBytes);
    } finally {
        zeroBytes(secretKeyBytes);
    }
}

// ==================== X3DH (Extended Triple Diffie-Hellman) ====================

export interface X3DHBundle {
    identityKey: string;      // Долгосрочный exchange identity key (IK, Curve25519)
    signingKey: string;       // Ed25519 signing identity key для верификации подписи SPK
    signedPreKey: string;     // Подписанный prekey (SPK)
    signature: string;        // Подпись SPK (Ed25519 detached)
    oneTimePreKey?: string;   // Одноразовый prekey (OPK)
}

/**
 * Инициирует X3DH как отправитель
 * Возвращает shared secret и ephemeral key для включения в первое сообщение
 */
export function x3dhInitiate(
    senderIdentityKeyPair: KeyPair,
    recipientBundle: X3DHBundle
): { sharedSecret: Uint8Array; ephemeralPublicKey: string } {
    // Верифицируем подпись signed prekey перед использованием.
    // Без этой проверки MITM может подменить SPK в bundle и расшифровать первое сообщение.
    const spkBytes = decodeBase64(recipientBundle.signedPreKey);
    const signatureBytes = decodeBase64(recipientBundle.signature);
    const signatureValid = verify(spkBytes, signatureBytes, recipientBundle.signingKey);
    if (!signatureValid) {
        throw new Error(
            'X3DH: signed prekey signature verification failed — possible MITM attack'
        );
    }

    // Генерируем эфемерный ключ — keep raw Uint8Array for zeroing after use
    const rawEphemeral = nacl.box.keyPair();
    const ephemeralKeyPair: KeyPair = {
        publicKey: encodeBase64(rawEphemeral.publicKey),
        secretKey: encodeBase64(rawEphemeral.secretKey),
    };

    // DH1: sender identity key, recipient signed prekey
    const dh1 = dh(senderIdentityKeyPair, recipientBundle.signedPreKey);

    // DH2: sender ephemeral key, recipient identity key
    const dh2 = dh(ephemeralKeyPair, recipientBundle.identityKey);

    // DH3: sender ephemeral key, recipient signed prekey
    const dh3 = dh(ephemeralKeyPair, recipientBundle.signedPreKey);

    // DH4: sender ephemeral key, recipient one-time prekey (если есть)
    let dh4: Uint8Array | null = null;
    if (recipientBundle.oneTimePreKey) {
        dh4 = dh(ephemeralKeyPair, recipientBundle.oneTimePreKey);
    }

    // Объединяем все DH результаты
    const totalLength = dh1.length + dh2.length + dh3.length + (dh4?.length || 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;

    combined.set(dh1, offset); offset += dh1.length;
    combined.set(dh2, offset); offset += dh2.length;
    combined.set(dh3, offset); offset += dh3.length;
    if (dh4) {
        combined.set(dh4, offset);
    }

    // Деривируем shared secret через HKDF (salt = пустой, info = domain separator)
    //
    // This is the line the whole product exists for: a secret that exactly two
    // people can compute and no one else in the world can — not the server, not
    // us. Written for Alisa, who is the reason it got built.
    const sharedSecret = hkdf(sha256, combined, new Uint8Array(0), INFO_X3DH, 32);
    zeroBytes(dh1); zeroBytes(dh2); zeroBytes(dh3);
    if (dh4) zeroBytes(dh4);
    zeroBytes(combined);

    // Zero the raw ephemeral secret key (Uint8Array) to prevent lingering in memory.
    // The base64 string in ephemeralKeyPair.secretKey is immutable in JS and will be GC'd,
    // but the raw Uint8Array is the actual key material we can actively wipe.
    zeroBytes(rawEphemeral.secretKey);

    return {
        sharedSecret,
        ephemeralPublicKey: ephemeralKeyPair.publicKey,
    };
}

/**
 * Обрабатывает X3DH как получатель
 */
export function x3dhRespond(
    recipientIdentityKeyPair: KeyPair,
    recipientSignedPreKeyPair: KeyPair,
    recipientOneTimePreKeyPair: KeyPair | null,
    senderIdentityKey: string,
    senderEphemeralKey: string
): Uint8Array {
    // DH1: sender identity key, recipient signed prekey
    const dh1 = dh(recipientSignedPreKeyPair, senderIdentityKey);

    // DH2: sender ephemeral key, recipient identity key
    const dh2 = dh(recipientIdentityKeyPair, senderEphemeralKey);

    // DH3: sender ephemeral key, recipient signed prekey
    const dh3 = dh(recipientSignedPreKeyPair, senderEphemeralKey);

    // DH4: sender ephemeral key, recipient one-time prekey
    let dh4: Uint8Array | null = null;
    if (recipientOneTimePreKeyPair) {
        dh4 = dh(recipientOneTimePreKeyPair, senderEphemeralKey);
    }

    // Объединяем
    const totalLength = dh1.length + dh2.length + dh3.length + (dh4?.length || 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;

    combined.set(dh1, offset); offset += dh1.length;
    combined.set(dh2, offset); offset += dh2.length;
    combined.set(dh3, offset); offset += dh3.length;
    if (dh4) {
        combined.set(dh4, offset);
    }

    const sharedSecret = hkdf(sha256, combined, new Uint8Array(0), INFO_X3DH, 32);
    zeroBytes(dh1); zeroBytes(dh2); zeroBytes(dh3);
    if (dh4) zeroBytes(dh4);
    zeroBytes(combined);
    return sharedSecret;
}

// ==================== Double Ratchet ====================

/**
 * Инициализирует сессию как отправитель (Alice)
 */
export function initSenderSession(
    sharedSecret: Uint8Array,
    recipientPublicKey: string
): DoubleRatchetSession {
    const dhKeyPair = generateExchangeKeyPair();
    const dhOutput = dh(dhKeyPair, recipientPublicKey);
    const { rootKey, chainKey } = kdfRk(sharedSecret, dhOutput);
    zeroBytes(dhOutput);
    // Note: caller is responsible for zeroing sharedSecret.
    // In production, X3DH produces separate copies for each party.

    return {
        dhSendingKeyPair: dhKeyPair,
        dhReceivingPublicKey: recipientPublicKey,
        rootKey,
        sendingChainKey: chainKey,
        receivingChainKey: null,
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
    };
}

/**
 * Инициализирует сессию как получатель (Bob)
 */
export function initReceiverSession(
    sharedSecret: Uint8Array,
    keyPair: KeyPair
): DoubleRatchetSession {
    return {
        dhSendingKeyPair: keyPair,
        dhReceivingPublicKey: null,
        rootKey: sharedSecret,
        sendingChainKey: null,
        receivingChainKey: null,
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
    };
}

/**
 * Выполняет DH ratchet
 */
function dhRatchet(session: DoubleRatchetSession, headerPublicKey: string): void {
    session.previousSendingChainLength = session.sendingMessageNumber;
    session.sendingMessageNumber = 0;
    session.receivingMessageNumber = 0;

    session.dhReceivingPublicKey = headerPublicKey;

    const dhOutput = dh(session.dhSendingKeyPair, headerPublicKey);
    const receiveResult = kdfRk(session.rootKey, dhOutput);
    zeroBytes(dhOutput);
    session.rootKey = receiveResult.rootKey;
    session.receivingChainKey = receiveResult.chainKey;

    // The old sending secret cannot be wiped here. It lives as a base64 string
    // on the session, and strings are immutable — that is SEC-20260721-018, a
    // structural limit rather than an oversight, and it is dropped by reference
    // when the key pair is replaced below.
    //
    // This previously read `zeroBytes(decodeBase64(session.dhSendingKeyPair
    // .secretKey))`, which allocated a fresh copy, wiped the copy, and discarded
    // it. The comment claimed the old key was zeroed; nothing was. Removed
    // rather than left, because a no-op that looks like a control is worse than
    // an accurate note saying the control is not available.
    session.dhSendingKeyPair = generateExchangeKeyPair();

    const sendDhOutput = dh(session.dhSendingKeyPair, headerPublicKey);
    const sendResult = kdfRk(session.rootKey, sendDhOutput);
    zeroBytes(sendDhOutput);
    session.rootKey = sendResult.rootKey;
    session.sendingChainKey = sendResult.chainKey;
}

/**
 * Пропускает ключи сообщений (для out-of-order доставки)
 */
function skipMessageKeys(session: DoubleRatchetSession, until: number): void {
    if (!session.receivingChainKey) return;

    if (session.receivingMessageNumber + MAX_SKIP < until) {
        throw new Error('Too many skipped messages');
    }

    while (session.receivingMessageNumber < until) {
        const oldReceivingChainKey = session.receivingChainKey;
        const { chainKey, messageKey } = kdfCk(session.receivingChainKey);
        zeroBytes(oldReceivingChainKey);
        session.receivingChainKey = chainKey;

        const key = `${session.dhReceivingPublicKey}:${session.receivingMessageNumber}`;
        session.skippedMessageKeys.set(key, messageKey);

        session.receivingMessageNumber++;
    }

    // Evict oldest skipped keys if over capacity
    if (session.skippedMessageKeys.size > MAX_SKIPPED_KEYS) {
        // Map iteration is insertion-ordered, so this drops oldest first. Taking
        // the keys as a snapshot first keeps deletion from mutating the iterator.
        for (const key of Array.from(session.skippedMessageKeys.keys())) {
            if (session.skippedMessageKeys.size <= MAX_SKIPPED_KEYS) break;
            session.skippedMessageKeys.delete(key);
        }
    }
}

/**
 * Embeds the canonical message header inside the plaintext before encryption so
 * it is cryptographically bound to the ciphertext (NaCl secretbox has no AAD).
 * Layout: uint32 BE header length | header JSON | plaintext. SEC-20260621-018.
 */
function encodeAuthenticatedPlaintext(header: MessageHeader, plaintext: Uint8Array): Uint8Array {
    const headerJson = JSON.stringify({
        publicKey: header.publicKey,
        previousChainLength: header.previousChainLength,
        messageNumber: header.messageNumber,
    });
    const headerBytes = new TextEncoder().encode(headerJson);
    const out = new Uint8Array(4 + headerBytes.length + plaintext.length);
    new DataView(out.buffer).setUint32(0, headerBytes.length, false);
    out.set(headerBytes, 4);
    out.set(plaintext, 4 + headerBytes.length);
    return out;
}

/**
 * Verifies the embedded header matches the cleartext message header and returns
 * the inner plaintext, or null if absent/tampered (fail closed).
 */
function decodeAuthenticatedPlaintext(
    decrypted: Uint8Array,
    header: MessageHeader,
): Uint8Array | null {
    if (decrypted.length < 4) return null;
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
    const headerLen = view.getUint32(0, false);
    if (headerLen <= 0 || 4 + headerLen > decrypted.length) return null;
    let embedded: { publicKey?: unknown; previousChainLength?: unknown; messageNumber?: unknown };
    try {
        embedded = JSON.parse(new TextDecoder().decode(decrypted.subarray(4, 4 + headerLen)));
    } catch {
        return null;
    }
    if (
        embedded.publicKey !== header.publicKey ||
        embedded.previousChainLength !== header.previousChainLength ||
        embedded.messageNumber !== header.messageNumber
    ) {
        return null;
    }
    return decrypted.subarray(4 + headerLen);
}

/**
 * Шифрует сообщение
 */
export function ratchetEncrypt(
    session: DoubleRatchetSession,
    plaintext: Uint8Array
): EncryptedMessage {
    if (!session.sendingChainKey) {
        throw new Error('Sending chain not initialized');
    }

    const oldSendingChainKey = session.sendingChainKey;
    const { chainKey, messageKey } = kdfCk(session.sendingChainKey);
    zeroBytes(oldSendingChainKey);
    session.sendingChainKey = chainKey;

    const header: MessageHeader = {
        publicKey: session.dhSendingKeyPair.publicKey,
        previousChainLength: session.previousSendingChainLength,
        messageNumber: session.sendingMessageNumber,
    };

    session.sendingMessageNumber++;

    // Шифруем с message key. Embed the canonical header inside the authenticated
    // plaintext so a tampered header is rejected on decrypt. SEC-20260621-018.
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const authedPlaintext = encodeAuthenticatedPlaintext(header, plaintext);
    const ciphertext = nacl.secretbox(authedPlaintext, nonce, messageKey);
    zeroBytes(messageKey);
    zeroBytes(authedPlaintext);

    return {
        header,
        ciphertext: encodeBase64(ciphertext),
        nonce: encodeBase64(nonce),
    };
}

/**
 * Глубокая копия сессии для snapshot/restore паттерна
 */
function cloneSession(session: DoubleRatchetSession): DoubleRatchetSession {
    return {
        dhSendingKeyPair: { publicKey: session.dhSendingKeyPair.publicKey, secretKey: session.dhSendingKeyPair.secretKey },
        dhReceivingPublicKey: session.dhReceivingPublicKey,
        rootKey: new Uint8Array(session.rootKey),
        sendingChainKey: session.sendingChainKey ? new Uint8Array(session.sendingChainKey) : null,
        receivingChainKey: session.receivingChainKey ? new Uint8Array(session.receivingChainKey) : null,
        sendingMessageNumber: session.sendingMessageNumber,
        receivingMessageNumber: session.receivingMessageNumber,
        previousSendingChainLength: session.previousSendingChainLength,
        skippedMessageKeys: new Map(
            Array.from(session.skippedMessageKeys.entries()).map(([k, v]) => [k, new Uint8Array(v)])
        ),
    };
}

/**
 * Восстанавливает сессию из snapshot (при неудачной расшифровке после DH ratchet)
 */
function restoreSession(target: DoubleRatchetSession, source: DoubleRatchetSession): void {
    target.dhSendingKeyPair = source.dhSendingKeyPair;
    target.dhReceivingPublicKey = source.dhReceivingPublicKey;
    target.rootKey = source.rootKey;
    target.sendingChainKey = source.sendingChainKey;
    target.receivingChainKey = source.receivingChainKey;
    target.sendingMessageNumber = source.sendingMessageNumber;
    target.receivingMessageNumber = source.receivingMessageNumber;
    target.previousSendingChainLength = source.previousSendingChainLength;
    target.skippedMessageKeys = source.skippedMessageKeys;
}

/**
 * Расшифровывает сообщение
 */
export function ratchetDecrypt(
    session: DoubleRatchetSession,
    message: EncryptedMessage
): Uint8Array | null {
    // Snapshot the full session up-front so ANY failure path (bad MAC, tampered
    // header, over-skip, or a thrown error) leaves session state untouched —
    // commit only on a fully successful decrypt. SEC-20260621-018.
    const snapshot = cloneSession(session);

    try {
        const ciphertext = decodeBase64(message.ciphertext);
        const nonce = decodeBase64(message.nonce);

        // Skipped-key path: do NOT consume the stored key until decryption AND the
        // embedded-header check both succeed.
        const skippedKey = `${message.header.publicKey}:${message.header.messageNumber}`;
        const skippedMessageKey = session.skippedMessageKeys.get(skippedKey);
        if (skippedMessageKey) {
            const opened = nacl.secretbox.open(ciphertext, nonce, skippedMessageKey);
            const verified = opened ? decodeAuthenticatedPlaintext(opened, message.header) : null;
            if (!verified) {
                restoreSession(session, snapshot);
                return null;
            }
            session.skippedMessageKeys.delete(skippedKey);
            zeroBytes(skippedMessageKey);
            return verified;
        }

        // DH ratchet if a new ratchet public key is presented.
        const needsDhRatchet = message.header.publicKey !== session.dhReceivingPublicKey;
        if (needsDhRatchet) {
            if (session.receivingChainKey) {
                skipMessageKeys(session, message.header.previousChainLength);
            }
            dhRatchet(session, message.header.publicKey);
        }

        // Skip to the requested message number within the current receiving chain.
        skipMessageKeys(session, message.header.messageNumber);

        if (!session.receivingChainKey) {
            restoreSession(session, snapshot);
            return null;
        }

        const oldReceivingChainKey = session.receivingChainKey;
        const { chainKey, messageKey } = kdfCk(session.receivingChainKey);
        zeroBytes(oldReceivingChainKey);
        session.receivingChainKey = chainKey;
        session.receivingMessageNumber++;

        const opened = nacl.secretbox.open(ciphertext, nonce, messageKey);
        zeroBytes(messageKey);
        const verified = opened ? decodeAuthenticatedPlaintext(opened, message.header) : null;
        if (!verified) {
            restoreSession(session, snapshot);
            return null;
        }
        return verified;
    } catch {
        // e.g. "Too many skipped messages" — never leave the session mutated.
        restoreSession(session, snapshot);
        return null;
    }
}

// ==================== Сериализация ====================

export interface SerializedSession {
    dhSendingKeyPair: KeyPair;
    dhReceivingPublicKey: string | null;
    rootKey: string;
    sendingChainKey: string | null;
    receivingChainKey: string | null;
    sendingMessageNumber: number;
    receivingMessageNumber: number;
    previousSendingChainLength: number;
    skippedMessageKeys: Array<[string, string]>;
}

/**
 * Сериализует сессию для хранения
 */
export function serializeSession(session: DoubleRatchetSession): SerializedSession {
    return {
        dhSendingKeyPair: session.dhSendingKeyPair,
        dhReceivingPublicKey: session.dhReceivingPublicKey,
        rootKey: encodeBase64(session.rootKey),
        sendingChainKey: session.sendingChainKey ? encodeBase64(session.sendingChainKey) : null,
        receivingChainKey: session.receivingChainKey ? encodeBase64(session.receivingChainKey) : null,
        sendingMessageNumber: session.sendingMessageNumber,
        receivingMessageNumber: session.receivingMessageNumber,
        previousSendingChainLength: session.previousSendingChainLength,
        skippedMessageKeys: Array.from(session.skippedMessageKeys.entries()).map(
            ([k, v]) => [k, encodeBase64(v)]
        ),
    };
}

/**
 * Десериализует сессию
 */
export function deserializeSession(data: SerializedSession): DoubleRatchetSession {
    return {
        dhSendingKeyPair: data.dhSendingKeyPair,
        dhReceivingPublicKey: data.dhReceivingPublicKey,
        rootKey: decodeBase64(data.rootKey),
        sendingChainKey: data.sendingChainKey ? decodeBase64(data.sendingChainKey) : null,
        receivingChainKey: data.receivingChainKey ? decodeBase64(data.receivingChainKey) : null,
        sendingMessageNumber: data.sendingMessageNumber,
        receivingMessageNumber: data.receivingMessageNumber,
        previousSendingChainLength: data.previousSendingChainLength,
        skippedMessageKeys: new Map(
            data.skippedMessageKeys.map(([k, v]) => [k, decodeBase64(v)])
        ),
    };
}
