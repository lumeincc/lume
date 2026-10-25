// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Криптографическое ядро - Генерация и управление ключами
 * Использует Ed25519 для подписей и X25519 для обмена ключами
 */

import nacl from "tweetnacl";
import { encodeBase64, decodeBase64 } from "tweetnacl-util";

export interface KeyPair {
  publicKey: string; // Base64
  secretKey: string; // Base64
}

export interface SigningKeyPair {
  publicKey: string; // Base64
  secretKey: string; // Base64
}

export interface IdentityKeys {
  signing: SigningKeyPair; // Ed25519 для подписей
  exchange: KeyPair; // X25519 для шифрования
}

/**
 * Генерирует новую пару ключей Ed25519 для подписей
 */
export function generateSigningKeyPair(): SigningKeyPair {
  const keyPair = nacl.sign.keyPair();
  return {
    publicKey: encodeBase64(keyPair.publicKey),
    secretKey: encodeBase64(keyPair.secretKey),
  };
}

/**
 * Генерирует новую пару ключей X25519 для обмена ключами (Diffie-Hellman)
 */
export function generateExchangeKeyPair(): KeyPair {
  const keyPair = nacl.box.keyPair();
  return {
    publicKey: encodeBase64(keyPair.publicKey),
    secretKey: encodeBase64(keyPair.secretKey),
  };
}

/**
 * Генерирует полный набор ключей идентификации
 */
export function generateIdentityKeys(): IdentityKeys {
  return {
    signing: generateSigningKeyPair(),
    exchange: generateExchangeKeyPair(),
  };
}

/**
 * Подписывает сообщение приватным ключом Ed25519
 */
export function sign(message: Uint8Array, secretKey: string): Uint8Array {
  const secretKeyBytes = decodeBase64(secretKey);
  try {
    return nacl.sign.detached(message, secretKeyBytes);
  } finally {
    zeroBytes(secretKeyBytes);
  }
}

/**
 * Проверяет подпись сообщения
 */
export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: string,
): boolean {
  const publicKeyBytes = decodeBase64(publicKey);
  return nacl.sign.detached.verify(message, signature, publicKeyBytes);
}

/**
 * Шифрует сообщение для получателя (box)
 */
export function encrypt(
  message: Uint8Array,
  recipientPublicKey: string,
  senderSecretKey: string,
): { ciphertext: string; nonce: string } {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const recipientPubKeyBytes = decodeBase64(recipientPublicKey);
  const senderSecKeyBytes = decodeBase64(senderSecretKey);

  try {
    const ciphertext = nacl.box(
      message,
      nonce,
      recipientPubKeyBytes,
      senderSecKeyBytes,
    );

    return {
      ciphertext: encodeBase64(ciphertext),
      nonce: encodeBase64(nonce),
    };
  } finally {
    zeroBytes(senderSecKeyBytes);
  }
}

/**
 * Расшифровывает сообщение от отправителя
 */
export function decrypt(
  ciphertext: string,
  nonce: string,
  senderPublicKey: string,
  recipientSecretKey: string,
): Uint8Array | null {
  const ciphertextBytes = decodeBase64(ciphertext);
  const nonceBytes = decodeBase64(nonce);
  const senderPubKeyBytes = decodeBase64(senderPublicKey);
  const recipientSecKeyBytes = decodeBase64(recipientSecretKey);

  try {
    return nacl.box.open(
      ciphertextBytes,
      nonceBytes,
      senderPubKeyBytes,
      recipientSecKeyBytes,
    );
  } finally {
    zeroBytes(recipientSecKeyBytes);
  }
}

/**
 * Генерирует prekey bundle для X3DH
 * @param exchangeKey - X25519 ключ для обмена
 * @param signingKey - Ed25519 ключ для подписи
 * @param count - количество одноразовых prekeys
 */
export function generatePreKeyBundle(
  exchangeKey: KeyPair,
  signingKey: SigningKeyPair,
  count: number = 100,
): {
  identityKey: string;
  signedPreKey: KeyPair;
  signature: string;
  oneTimePreKeys: KeyPair[];
} {
  // Generate a dedicated signed prekey (X25519) and keep the secret locally.
  // This enables proper X3DH without reusing the long-term X25519 identity key for everything.
  const signedPreKey = generateExchangeKeyPair();

  // Подписываем signedPreKey с Ed25519 ключом. Decode the signing secret into a
  // local buffer so it can be zeroed immediately after signing. SEC-20260621-023.
  const signedPreKeyBytes = decodeBase64(signedPreKey.publicKey);
  const signingSecret = decodeBase64(signingKey.secretKey);
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = nacl.sign.detached(signedPreKeyBytes, signingSecret);
  } finally {
    zeroBytes(signingSecret);
  }

  // Генерируем одноразовые prekeys
  const oneTimePreKeys: KeyPair[] = [];
  for (let i = 0; i < count; i++) {
    oneTimePreKeys.push(generateExchangeKeyPair());
  }

  return {
    identityKey: exchangeKey.publicKey,
    signedPreKey,
    signature: encodeBase64(signatureBytes),
    oneTimePreKeys,
  };
}

/**
 * Генерирует новый Signed PreKey (SPK) и подписывает его Ed25519 ключом.
 * Используется при ротации SPK в X3DH.
 */
export function generateSignedPreKey(signingKey: SigningKeyPair): {
  signedPreKey: KeyPair;
  signature: string;
} {
  const signedPreKey = generateExchangeKeyPair();
  const signedPreKeyBytes = decodeBase64(signedPreKey.publicKey);

  // Bind the decoded signing secret so it can be zeroed. Passing
  // `decodeBase64(...)` inline leaves the buffer unreachable and therefore
  // un-zeroable — the same defect `generatePreKeyBundle` above already fixed,
  // left standing in this function. SEC-20260721-003.
  //
  // This is the SPK rotation path, so it runs every 7 days for every user: the
  // long-term identity secret was being re-exposed on a schedule.
  const signingSecret = decodeBase64(signingKey.secretKey);
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = nacl.sign.detached(signedPreKeyBytes, signingSecret);
  } finally {
    zeroBytes(signingSecret);
  }

  return {
    signedPreKey,
    signature: encodeBase64(signatureBytes),
  };
}

/** Zero out a Uint8Array to prevent key material from lingering in memory. */
export function zeroBytes(arr: Uint8Array): void {
  arr.fill(0);
}

/**
 * Генерирует случайные байты
 */
export function randomBytes(length: number): Uint8Array {
  return nacl.randomBytes(length);
}

/**
 * Хеширует данные (SHA-512)
 */
export function hash(data: Uint8Array): Uint8Array {
  return nacl.hash(data);
}
