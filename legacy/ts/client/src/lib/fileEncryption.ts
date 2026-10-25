// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Client-side file encryption for E2E encrypted attachments.
 * Files are encrypted with a random key using XSalsa20-Poly1305 (NaCl secretbox).
 * The key is then shared via the message payload (already encrypted by the ratchet).
 *
 * Heavy crypto is offloaded to a Web Worker when available to keep the UI responsive.
 */

import nacl from 'tweetnacl';
import { encodeBase64, decodeBase64 } from 'tweetnacl-util';
import type { CryptoWorkerRequest, CryptoWorkerResponse } from './cryptoWorker';

// ── Worker management ───────────────────────────────────────────

let worker: Worker | null = null;
let requestId = 0;
const pending = new Map<number, {
  resolve: (v: CryptoWorkerResponse) => void;
  reject: (e: Error) => void;
}>();

function getWorker(): Worker | null {
  if (worker) return worker;
  if (typeof window === 'undefined' || typeof Worker === 'undefined') return null;

  try {
    worker = new Worker(new URL('./cryptoWorker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (e: MessageEvent<CryptoWorkerResponse>) => {
      const p = pending.get(e.data.id);
      if (p) {
        pending.delete(e.data.id);
        p.resolve(e.data);
      }
    };
    worker.onerror = () => {
      // Worker failed — disable and fall back to main thread
      worker?.terminate();
      worker = null;
      for (const p of pending.values()) {
        p.reject(new Error('Worker crashed'));
      }
      pending.clear();
    };
    return worker;
  } catch {
    return null;
  }
}

function postToWorker(msg: Record<string, unknown>, transfer?: Transferable[]): Promise<CryptoWorkerResponse> {
  const w = getWorker();
  if (!w) return Promise.reject(new Error('No worker'));

  const id = ++requestId;
  const full = { ...msg, id } as CryptoWorkerRequest;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    if (transfer) {
      w.postMessage(full, transfer);
    } else {
      w.postMessage(full);
    }
  });
}

// ── Fallback: main-thread yield ─────────────────────────────────

async function yieldThread(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 0));
}

// ── Public API ──────────────────────────────────────────────────

export interface EncryptedFile {
  /** Base64-encoded encrypted data */
  ciphertext: string;
  /** Base64-encoded nonce */
  nonce: string;
  /** Base64-encoded symmetric key (to be sent via message payload) */
  key: string;
  /** Original MIME type */
  mimeType: string;
  /** Original file name */
  fileName: string;
  /** Original file size in bytes */
  originalSize: number;
}

export interface DecryptedFile {
  data: Uint8Array;
  mimeType: string;
  fileName: string;
}

/**
 * Encrypt a file for upload.
 * Returns the encrypted data + a symmetric key that must be sent in the message.
 */
export async function encryptFile(
  data: Uint8Array,
  mimeType: string,
  fileName: string
): Promise<EncryptedFile> {
  // Try Web Worker first
  try {
    const copy = new Uint8Array(data);
    const resp = await postToWorker(
      { type: 'encrypt', data: copy },
      [copy.buffer as ArrayBuffer],
    );
    if (resp.type === 'encrypt') {
      return {
        ciphertext: resp.ciphertext,
        nonce: resp.nonce,
        key: resp.key,
        mimeType,
        fileName,
        originalSize: data.length,
      };
    }
  } catch {
    // Fall through to main thread
  }

  // Fallback: main thread with yield
  const key = nacl.randomBytes(nacl.secretbox.keyLength);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  try {
    await yieldThread();
    const ciphertext = nacl.secretbox(data, nonce, key);
    await yieldThread();

    return {
      ciphertext: encodeBase64(ciphertext),
      nonce: encodeBase64(nonce),
      key: encodeBase64(key),
      mimeType,
      fileName,
      originalSize: data.length,
    };
  } finally {
    // Zero the raw secret key; the base64 copy in the return value is what the
    // caller keeps. SEC-20260621-023.
    key.fill(0);
  }
}

/**
 * Decrypt a downloaded file using the key from the message payload.
 */
export async function decryptFile(
  ciphertextBase64: string,
  nonceBase64: string,
  keyBase64: string,
  mimeType: string,
  fileName: string
): Promise<DecryptedFile | null> {
  // Try Web Worker first
  try {
    const resp = await postToWorker({
      type: 'decrypt',
      ciphertext: ciphertextBase64,
      nonce: nonceBase64,
      key: keyBase64,
    });
    if (resp.type === 'decrypt') {
      if (!resp.data) return null;
      return { data: resp.data, mimeType, fileName };
    }
  } catch {
    // Fall through to main thread
  }

  // Fallback: main thread with yield
  let key: Uint8Array | undefined;
  try {
    const ciphertext = decodeBase64(ciphertextBase64);
    const nonce = decodeBase64(nonceBase64);
    key = decodeBase64(keyBase64);

    await yieldThread();
    const plaintext = nacl.secretbox.open(ciphertext, nonce, key);
    await yieldThread();

    if (!plaintext) return null;

    return { data: plaintext, mimeType, fileName };
  } catch {
    return null;
  } finally {
    // Zero the raw secret key (the decrypted plaintext is returned to the caller).
    // SEC-20260621-023.
    if (key) key.fill(0);
  }
}

/**
 * Read a File object into a Uint8Array.
 */
export function readFileAsUint8Array(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(new Uint8Array(reader.result));
      } else {
        reject(new Error('Unexpected result type'));
      }
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Create an object URL from decrypted file data.
 */
export function createFileUrl(data: Uint8Array, mimeType: string): string {
  const blob = new Blob([data.buffer as ArrayBuffer], { type: mimeType });
  return URL.createObjectURL(blob);
}

/**
 * Format file size for display.
 */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Max file size: 5MB */
export const MAX_FILE_SIZE = 5 * 1024 * 1024;

/** Allowed image MIME types */
export const IMAGE_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

/** Check if a MIME type is an image */
export function isImageMime(mime: string): boolean {
  return IMAGE_MIME_TYPES.includes(mime);
}
