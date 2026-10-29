// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync } from "node:fs";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { join } from "node:path";

const rotl = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;

const hchacha20 = (key, nonce) => {
  const state = new Uint32Array(16);
  state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let index = 0; index < 8; index += 1) state[4 + index] = key.readUInt32LE(4 * index);
  for (let index = 0; index < 4; index += 1) state[12 + index] = nonce.readUInt32LE(4 * index);
  const quarter = (a, b, c, d) => {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl(state[b] ^ state[c], 7);
  };
  for (let round = 0; round < 10; round += 1) {
    quarter(0, 4, 8, 12);
    quarter(1, 5, 9, 13);
    quarter(2, 6, 10, 14);
    quarter(3, 7, 11, 15);
    quarter(0, 5, 10, 15);
    quarter(1, 6, 11, 12);
    quarter(2, 7, 8, 13);
    quarter(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((word, index) => out.writeUInt32LE(state[word], 4 * index));
  return out;
};

const chachaParameters = (key, nonce) => [hchacha20(key, nonce.subarray(0, 16)), Buffer.concat([Buffer.alloc(4), nonce.subarray(16)])];

export const aeadEncrypt = (key, nonce, associatedData, plaintext) => {
  const [subkey, iv] = chachaParameters(key, nonce);
  const cipher = createCipheriv("chacha20-poly1305", subkey, iv, { authTagLength: 16 });
  cipher.setAAD(associatedData, { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
};

const decipherOf = (key, nonce, associatedData, ciphertext) => {
  const [subkey, iv] = chachaParameters(key, nonce);
  const decipher = createDecipheriv("chacha20-poly1305", subkey, iv, { authTagLength: 16 });
  decipher.setAAD(associatedData, { plaintextLength: ciphertext.length - 16 });
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  return [decipher, decipher.update(ciphertext.subarray(0, ciphertext.length - 16))];
};

export const aeadDecrypt = (key, nonce, associatedData, ciphertext) => {
  if (ciphertext.length < 16) return null;
  const [decipher, plaintext] = decipherOf(key, nonce, associatedData, ciphertext);
  try {
    return Buffer.concat([plaintext, decipher.final()]);
  } catch {
    return null;
  }
};

export const decryptIgnoringTheTag = (key, nonce, associatedData, ciphertext) => {
  if (ciphertext.length < 16) return null;
  return decipherOf(key, nonce, associatedData, ciphertext)[1];
};

export const checkAgainstWycheproof = (wycheproofDir) => {
  const tests = JSON.parse(readFileSync(join(wycheproofDir, "xchacha20_poly1305_test.json"), "utf8")).testGroups
    .filter((group) => group.keySize === 256 && group.ivSize === 192 && group.tagSize === 128)
    .flatMap((group) => group.tests);
  for (const test of tests) {
    const [key, iv, aad, message, ciphertext, tag] = [test.key, test.iv, test.aad, test.msg, test.ct, test.tag]
      .map((value) => Buffer.from(value, "hex"));
    const opened = aeadDecrypt(key, iv, aad, Buffer.concat([ciphertext, tag]));
    if (test.result === "valid") {
      const sealed = aeadEncrypt(key, iv, aad, message).toString("hex");
      if (sealed !== test.ct + test.tag || !opened || !opened.equals(message)) {
        throw new Error(`the XChaCha20-Poly1305 construction disagrees with Wycheproof case ${test.tcId}`);
      }
    } else if (opened) {
      throw new Error(`the XChaCha20-Poly1305 construction opens Wycheproof's invalid case ${test.tcId}`);
    }
  }
  if (tests.length === 0) throw new Error("no Wycheproof XChaCha20-Poly1305 case was checked");
  return tests.length;
};
