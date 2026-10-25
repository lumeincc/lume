// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-021 — the profile and push limiters must not key on an identity
 * key that `requireSignature` never proved is registered.
 *
 * The attack is free: generate a fresh Ed25519 keypair per request and sign it
 * correctly. Under the old key generator (`req.user?.identityKey || req.ip`)
 * every fresh key is its own bucket, so the 30/min and 20/min ceilings never
 * apply. The fix resolves an unregistered key to no user and falls back to the
 * IP bucket, so a single-host flood of fresh keys shares one counter and trips.
 *
 * Both tests fail against the old key generator (no 429 ever appears) and pass
 * against the fix — verified by reverting the change and re-running.
 */

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);

import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { describe, it, expect } from 'vitest';

import profileRoutes from '../src/routes/profile';
import pushRoutes from '../src/routes/push';

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/profile', profileRoutes);
  app.use('/api/push', pushRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

function signHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
  const timestamp = Date.now().toString();
  const nonce = `idk-${crypto.randomUUID()}`;
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const bodyString = body && Object.keys(body as object).length > 0 ? JSON.stringify(body) : '';
  const msg = `${timestamp}.${nonce}.${method.toUpperCase()}.${normalizedPath}.${bodyString}`;
  const sig = nacl.sign.detached(new TextEncoder().encode(msg), keyPair.secretKey);
  return {
    'X-Lume-Identity-Key': encodeBase64(keyPair.publicKey),
    'X-Lume-Signature': encodeBase64(sig),
    'X-Lume-Timestamp': timestamp,
    'X-Lume-Nonce': nonce,
    'X-Lume-Path': normalizedPath,
  };
}

const app = buildApp();

describe('SEC-20260721-021 — limiters must not key on an unverified identity key', () => {
  it('profile: a flood signed by fresh unregistered keys shares one IP bucket and 429s', async () => {
    // profileLimiter allows 30/min. Forty requests, each a different fresh key
    // from the same host, must cross it once they collapse into the IP bucket.
    let got429 = false;
    for (let i = 0; i < 40; i++) {
      const freshKey = nacl.sign.keyPair();
      const userId = crypto.randomUUID();
      const headers = signHeaders('GET', `/profile/${userId}`, {}, freshKey);
      const res = await request(app).get(`/api/profile/${userId}`).set(headers);
      if (res.status === 429) {
        got429 = true;
        break;
      }
    }
    expect(got429).toBe(true);
  });

  it('push: a flood signed by fresh unregistered keys shares one IP bucket and 429s', async () => {
    // pushLimiter allows 20/min. Same shape as above against the tighter bound.
    let got429 = false;
    for (let i = 0; i < 30; i++) {
      const freshKey = nacl.sign.keyPair();
      const body = { userId: crypto.randomUUID() };
      const headers = signHeaders('POST', '/push/unsubscribe', body, freshKey);
      const res = await request(app).post('/api/push/unsubscribe').set(headers).send(body);
      if (res.status === 429) {
        got429 = true;
        break;
      }
    }
    expect(got429).toBe(true);
  });
});
