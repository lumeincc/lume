// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Web Worker for offloading heavy crypto operations from the main thread.
 * Handles file encryption (NaCl secretbox) and decryption.
 */

import nacl from 'tweetnacl';
import { encodeBase64, decodeBase64 } from 'tweetnacl-util';

export type CryptoWorkerRequest =
  | {
      id: number;
      type: 'encrypt';
      data: Uint8Array;
    }
  | {
      id: number;
      type: 'decrypt';
      ciphertext: string;
      nonce: string;
      key: string;
    };

export type CryptoWorkerResponse =
  | {
      id: number;
      type: 'encrypt';
      ciphertext: string;
      nonce: string;
      key: string;
    }
  | {
      id: number;
      type: 'decrypt';
      data: Uint8Array | null;
    }
  | {
      id: number;
      type: 'error';
      message: string;
    };

self.onmessage = (e: MessageEvent<CryptoWorkerRequest>) => {
  const msg = e.data;

  try {
    if (msg.type === 'encrypt') {
      const key = nacl.randomBytes(nacl.secretbox.keyLength);
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      const ciphertext = nacl.secretbox(msg.data, nonce, key);

      const response: CryptoWorkerResponse = {
        id: msg.id,
        type: 'encrypt',
        ciphertext: encodeBase64(ciphertext),
        nonce: encodeBase64(nonce),
        key: encodeBase64(key),
      };
      self.postMessage(response);
      key.fill(0); // SEC-20260621-023: zero the raw key after its base64 copy is sent
    } else if (msg.type === 'decrypt') {
      const ciphertext = decodeBase64(msg.ciphertext);
      const nonce = decodeBase64(msg.nonce);
      const key = decodeBase64(msg.key);
      const plaintext = nacl.secretbox.open(ciphertext, nonce, key);
      key.fill(0); // SEC-20260621-023: zero the raw key after use

      const response: CryptoWorkerResponse = {
        id: msg.id,
        type: 'decrypt',
        data: plaintext ?? null,
      };
      // Transfer the buffer to avoid copying
      if (plaintext) {
        self.postMessage(response, { transfer: [plaintext.buffer as ArrayBuffer] });
      } else {
        self.postMessage(response);
      }
    }
  } catch (err) {
    const response: CryptoWorkerResponse = {
      id: msg.id,
      type: 'error',
      message: err instanceof Error ? err.message : 'Unknown error',
    };
    self.postMessage(response);
  }
};
