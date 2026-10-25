// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * BIP39 Мнемоническая фраза для восстановления аккаунта
 * Генерирует 12-24 слова, из которых детерминированно создаются ключи
 */

import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { zeroBytes, type IdentityKeys } from './keys';

/**
 * Lazy-loads the bip39 library (~50KB) to keep it out of the initial bundle.
 * Only needed during signup/recovery flows.
 */
async function loadBip39() {
    return import('bip39');
}

/**
 * Генерирует новую мнемоническую фразу (12 слов по умолчанию)
 */
export async function generateMnemonic(strength: 128 | 256 = 128): Promise<string> {
    // 128 бит = 12 слов, 256 бит = 24 слова
    const bip39 = await loadBip39();
    return bip39.generateMnemonic(strength);
}

/**
 * Проверяет валидность мнемонической фразы
 */
export async function validateMnemonic(mnemonic: string): Promise<boolean> {
    const bip39 = await loadBip39();
    return bip39.validateMnemonic(mnemonic);
}

/**
 * Преобразует мнемоническую фразу в seed (512 бит)
 */
export async function mnemonicToSeed(mnemonic: string, passphrase: string = ''): Promise<Uint8Array> {
    const bip39 = await loadBip39();
    const seedBuffer = await bip39.mnemonicToSeed(mnemonic, passphrase);
    return new Uint8Array(seedBuffer);
}

/**
 * Генерирует детерминированную пару ключей Ed25519 из seed
 */
function deriveSigningKeyPair(seed: Uint8Array): { publicKey: string; secretKey: string } {
    // Используем первые 32 байта seed для генерации ключей подписи
    const signingSeed = seed.slice(0, 32);
    // The seed slice was already zeroed here; the 64-byte secret NaCl returns
    // was not, and it is the more valuable of the two — this is where the
    // mnemonic becomes the long-term identity. SEC-20260721-029.
    let keyPair: nacl.SignKeyPair | null = null;
    try {
        keyPair = nacl.sign.keyPair.fromSeed(signingSeed);

        return {
            publicKey: encodeBase64(keyPair.publicKey),
            secretKey: encodeBase64(keyPair.secretKey),
        };
    } finally {
        zeroBytes(signingSeed);
        // Runs after the return value is computed, so the base64 copy is
        // already made and only the raw buffer is wiped.
        if (keyPair) zeroBytes(keyPair.secretKey);
    }
}

/**
 * Генерирует детерминированную пару ключей X25519 из seed
 */
function deriveExchangeKeyPair(seed: Uint8Array): { publicKey: string; secretKey: string } {
    // Используем следующие 32 байта seed для ключей обмена
    const exchangeSeed = seed.slice(32, 64);
    const keyPair = nacl.box.keyPair.fromSecretKey(exchangeSeed);
    exchangeSeed.fill(0);

    const encoded = {
        publicKey: encodeBase64(keyPair.publicKey),
        secretKey: encodeBase64(keyPair.secretKey),
    };
    // Same omission as the signing helper: the seed slice was wiped, the raw
    // secret was not. SEC-20260721-029.
    zeroBytes(keyPair.secretKey);

    return encoded;
}

/**
 * Восстанавливает ключи идентификации из мнемонической фразы
 */
export async function recoverIdentityFromMnemonic(
    mnemonic: string,
    passphrase: string = ''
): Promise<IdentityKeys> {
    if (!(await validateMnemonic(mnemonic))) {
        throw new Error('Invalid mnemonic phrase');
    }

    const seed = await mnemonicToSeed(mnemonic, passphrase);

    const result = {
        signing: deriveSigningKeyPair(seed),
        exchange: deriveExchangeKeyPair(seed),
    };
    seed.fill(0);
    return result;
}

/**
 * Создает новый аккаунт с мнемонической фразой
 */
export async function createAccountWithMnemonic(
    strength: 128 | 256 = 128,
    passphrase: string = ''
): Promise<{
    mnemonic: string;
    identity: IdentityKeys;
}> {
    const mnemonic = await generateMnemonic(strength);
    const identity = await recoverIdentityFromMnemonic(mnemonic, passphrase);

    return {
        mnemonic,
        identity,
    };
}

/**
 * Маскирует мнемоническую фразу для безопасного отображения
 * Показывает только первые и последние слова
 */
export function maskMnemonic(mnemonic: string): string {
    const words = mnemonic.split(' ');
    if (words.length <= 4) {
        return words.map(() => '****').join(' ');
    }

    return [
        words[0],
        '****',
        '****',
        '...',
        '****',
        words[words.length - 1],
    ].join(' ');
}

/**
 * Разбивает мнемоническую фразу на слова для проверки пользователем
 */
export function getMnemonicWords(mnemonic: string): string[] {
    return mnemonic.split(' ');
}

/**
 * Проверяет, что пользователь правильно ввел слова из мнемоники
 * Запрашивает случайные позиции слов
 */
export function getRandomWordPositions(wordCount: number, checkCount: number = 3): number[] {
    const positions: number[] = [];
    const available = Array.from({ length: wordCount }, (_, i) => i);

    for (let i = 0; i < Math.min(checkCount, wordCount); i++) {
        if (available.length === 0) break;

        const randomBytes = new Uint32Array(1);
        crypto.getRandomValues(randomBytes);
        const randomValue = randomBytes[0];
        if (randomValue === undefined) {
            // Unreachable for a one-element Uint32Array, but falling back to a
            // default here would silently bias which words the user is asked to
            // confirm. Fail closed instead.
            throw new Error('Mnemonic check: CSPRNG returned no value');
        }

        // splice returns what it removed, so the position is read and taken in
        // one step — the previous version indexed, asserted, then spliced.
        const [position] = available.splice(randomValue % available.length, 1);
        if (position === undefined) break;
        positions.push(position);
    }

    return positions.sort((a, b) => a - b);
}

/**
 * Проверяет ответы пользователя на слова мнемоники
 */
export function verifyMnemonicWords(
    mnemonic: string,
    positions: number[],
    answers: string[]
): boolean {
    const words = getMnemonicWords(mnemonic);

    return positions.every((pos, index) => {
        const expected = words[pos]?.toLowerCase().trim();
        const actual = answers[index]?.toLowerCase().trim();
        return expected === actual;
    });
}
