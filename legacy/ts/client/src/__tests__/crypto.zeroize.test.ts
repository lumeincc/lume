// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260621-023 — temporary key material is zeroed after use. These tests
 * confirm the zeroing (in `finally` blocks) does not break correctness: the
 * base64 copies callers keep are captured before the raw buffers are wiped.
 */

import { describe, it, expect } from 'vitest';
import { decodeBase64, encodeBase64 } from 'tweetnacl-util';

import { generateIdentityKeys, generatePreKeyBundle, generateSignedPreKey, verify } from '@/crypto/keys';
import { generateMnemonic, recoverIdentityFromMnemonic } from '@/crypto/mnemonic';
import { encryptFile, decryptFile } from '@/lib/fileEncryption';

describe('memory hygiene — correctness preserved after zeroing (SEC-20260621-023)', () => {
  it('generatePreKeyBundle still yields a verifiable signature after zeroing the signing secret', () => {
    const identity = generateIdentityKeys();
    const bundle = generatePreKeyBundle(identity.exchange, identity.signing, 2);

    const ok = verify(
      decodeBase64(bundle.signedPreKey.publicKey),
      decodeBase64(bundle.signature),
      identity.signing.publicKey,
    );
    expect(ok).toBe(true);
    expect(bundle.oneTimePreKeys).toHaveLength(2);
  });

  it('file encrypt -> decrypt round-trips after the raw keys are zeroed', async () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const enc = await encryptFile(data, 'application/octet-stream', 'f.bin');
    const dec = await decryptFile(enc.ciphertext, enc.nonce, enc.key, enc.mimeType, enc.fileName);

    expect(dec).not.toBeNull();
    expect(Array.from(dec!.data)).toEqual(Array.from(data));
  });
});

/**
 * SEC-20260721-003 and -029 — the same omission in two places: a decoded secret
 * left unbound and unwipeable, and a raw NaCl secret abandoned after encoding.
 *
 * These cannot observe a wiped buffer from outside, so they assert the property
 * that breaks if the wipe lands in the wrong place: zero too early and the
 * returned base64 is a string of zeroes, or the signature stops verifying.
 */
describe('memory hygiene — SPK rotation and mnemonic derivation (SEC-20260721-003, -029)', () => {
  const ZEROED_32 = encodeBase64(new Uint8Array(32));
  const ZEROED_64 = encodeBase64(new Uint8Array(64));

  it('generateSignedPreKey still signs verifiably after zeroing the signing secret', () => {
    const identity = generateIdentityKeys();
    const rotated = generateSignedPreKey(identity.signing);

    const ok = verify(
      decodeBase64(rotated.signedPreKey.publicKey),
      decodeBase64(rotated.signature),
      identity.signing.publicKey,
    );
    expect(ok).toBe(true);
  });

  it('rotating twice from the same identity produces distinct, valid prekeys', () => {
    // The wipe is in a `finally`, so a second call would fail if the first had
    // damaged the caller's copy of the identity secret.
    const identity = generateIdentityKeys();
    const first = generateSignedPreKey(identity.signing);
    const second = generateSignedPreKey(identity.signing);

    expect(first.signedPreKey.publicKey).not.toBe(second.signedPreKey.publicKey);
    for (const rotated of [first, second]) {
      expect(
        verify(
          decodeBase64(rotated.signedPreKey.publicKey),
          decodeBase64(rotated.signature),
          identity.signing.publicKey,
        ),
      ).toBe(true);
    }
  });

  it('mnemonic recovery returns real keys, not the buffers it wiped', async () => {
    const mnemonic = await generateMnemonic();
    const identity = await recoverIdentityFromMnemonic(mnemonic);

    // Zeroing before encoding rather than after would surface exactly here.
    expect(identity.signing.secretKey).not.toBe(ZEROED_64);
    expect(identity.exchange.secretKey).not.toBe(ZEROED_32);
    expect(decodeBase64(identity.signing.secretKey)).toHaveLength(64);
    expect(decodeBase64(identity.exchange.secretKey)).toHaveLength(32);
  });

  it('recovery stays deterministic — the same phrase yields the same identity', async () => {
    // The property the whole recovery path rests on: if a wipe corrupted
    // derivation, a user restoring on a new device would get a different
    // identity and every safety number would change.
    const mnemonic = await generateMnemonic();
    const first = await recoverIdentityFromMnemonic(mnemonic);
    const second = await recoverIdentityFromMnemonic(mnemonic);

    expect(second.signing.publicKey).toBe(first.signing.publicKey);
    expect(second.signing.secretKey).toBe(first.signing.secretKey);
    expect(second.exchange.publicKey).toBe(first.exchange.publicKey);
    expect(second.exchange.secretKey).toBe(first.exchange.secretKey);
  });

  it('a recovered signing key still signs verifiably', async () => {
    const identity = await recoverIdentityFromMnemonic(await generateMnemonic());
    const rotated = generateSignedPreKey(identity.signing);

    expect(
      verify(
        decodeBase64(rotated.signedPreKey.publicKey),
        decodeBase64(rotated.signature),
        identity.signing.publicKey,
      ),
    ).toBe(true);
  });
});
