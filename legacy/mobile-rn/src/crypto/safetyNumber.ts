// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';

// Hash rounds for the safety-number derivation. Fixed and documented so it does
// not drift; matches Signal's fingerprint hardening. SEC-20260721-028.
const SAFETY_NUMBER_ITERATIONS = 5200;

/**
 * Byte at `index`, or a thrown error.
 *
 * Fails closed on purpose. Substituting a default for a missing byte would let a
 * short digest produce a *weaker* safety number — one that two different
 * identities could share — which is the single thing this file must never do.
 * A safety number that is wrong is worse than one that fails to render.
 */
function byteAt(bytes: Uint8Array, index: number): number {
  const value = bytes[index];
  if (value === undefined) {
    throw new Error(`Safety number: no byte at index ${index} of ${bytes.length}`);
  }
  return value;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    // Read once each: the previous version indexed both arrays twice per
    // differing byte, and asserted non-undefined on the second read.
    const av = byteAt(a, i);
    const bv = byteAt(b, i);
    if (av !== bv) return av < bv ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function sortPair(a: Uint8Array, b: Uint8Array): [Uint8Array, Uint8Array] {
  return compareBytes(a, b) <= 0 ? [a, b] : [b, a];
}

export function computeSafetyNumber(params: {
  mySigningPublicKey: string;
  myExchangeIdentityPublicKey: string;
  theirSigningPublicKey: string;
  theirExchangeIdentityPublicKey: string;
}): string {
  const mySign = decodeBase64(params.mySigningPublicKey);
  const theirSign = decodeBase64(params.theirSigningPublicKey);
  const myExchange = decodeBase64(params.myExchangeIdentityPublicKey);
  const theirExchange = decodeBase64(params.theirExchangeIdentityPublicKey);

  const [signA, signB] = sortPair(mySign, theirSign);
  const [exA, exB] = sortPair(myExchange, theirExchange);

  // V2 derivation. Two changes from V1 (SEC-20260721-028), so the displayed
  // number changes — the version tag records that:
  //   - iterate the hash so grinding a keypair toward a matching visible prefix
  //     costs SAFETY_NUMBER_ITERATIONS hashes per trial, not one (Signal does the
  //     same with its 5200-round fingerprint);
  //   - read 3 bytes per group so every group spans the full 0–99999, instead of
  //     2 bytes capped at 65535 with a `% 100000` that never fired.
  const prefix = new TextEncoder().encode('LUME-SAFETY-V2');
  const input = concatBytes(prefix, signA, signB, exA, exB);

  let digest = nacl.hash(input); // 64 bytes (SHA-512)
  for (let i = 1; i < SAFETY_NUMBER_ITERATIONS; i++) {
    digest = nacl.hash(concatBytes(digest, input));
  }

  // 10 groups of 5 digits (50-digit "safety number"), 3 bytes each (30 bytes).
  const groups: string[] = [];
  for (let i = 0; i < 10; i++) {
    const b0 = byteAt(digest, i * 3);
    const b1 = byteAt(digest, i * 3 + 1);
    const b2 = byteAt(digest, i * 3 + 2);
    const value = ((b0 << 16) | (b1 << 8) | b2) % 100000;
    groups.push(value.toString().padStart(5, '0'));
  }
  return groups.join(' ');
}

