// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, expect, it } from 'vitest';
import { encodeBase64 } from 'tweetnacl-util';
import nacl from 'tweetnacl';

import {
  isValidBase64Key,
  isValidPrekeys,
  isValidSignature,
  isValidUsername,
  isValidUuidLike,
} from '../src/utils/validators';

describe('validators', () => {
  it('accepts valid usernames and rejects invalid ones', () => {
    expect(isValidUsername('alice_01')).toBe(true);
    expect(isValidUsername('a')).toBe(false);
    expect(isValidUsername('with space')).toBe(false);
  });

  it('validates base64 keys of expected length', () => {
    const key = encodeBase64(nacl.randomBytes(32));
    expect(isValidBase64Key(key)).toBe(true);
    expect(isValidBase64Key('not-base64')).toBe(false);
    expect(isValidBase64Key(encodeBase64(nacl.randomBytes(16)))).toBe(false);
  });

  it('validates detached signatures', () => {
    const signature = encodeBase64(nacl.randomBytes(64));
    expect(isValidSignature(signature)).toBe(true);
    expect(isValidSignature('abc')).toBe(false);
  });

  it('validates uuid-like identifiers', () => {
    expect(isValidUuidLike('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
    expect(isValidUuidLike('too-short')).toBe(false);
  });

  it('validates prekey payloads with uniqueness and size limits', () => {
    const valid = [
      { id: 'k1', publicKey: encodeBase64(nacl.randomBytes(32)) },
      { id: 'k2', publicKey: encodeBase64(nacl.randomBytes(32)) },
    ];
    expect(isValidPrekeys(valid)).toBe(true);
    expect(isValidPrekeys([{ id: 'k1', publicKey: 'bad' }])).toBe(false);
    expect(isValidPrekeys([{ id: 'dup', publicKey: encodeBase64(nacl.randomBytes(32)) }, { id: 'dup', publicKey: encodeBase64(nacl.randomBytes(32)) }])).toBe(false);
  });
});
