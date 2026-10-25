// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);

import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { describe, it, expect } from 'vitest';

import authRoutes from '../src/routes/auth';
import groupRoutes from '../src/routes/groups';
import pushRoutes from '../src/routes/push';

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/auth', authRoutes);
  app.use('/api/groups', groupRoutes);
  app.use('/api/push', pushRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

function signHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
  const timestamp = Date.now().toString();
  const nonce = `rl-${crypto.randomUUID()}`;
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

async function registerUser(app: express.Express, prefix: string) {
  const username = `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const idKey = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  await request(app)
    .post('/api/auth/register')
    .send({
      username,
      identityKey: encodeBase64(idKey.publicKey),
      exchangeIdentityKey: encodeBase64(idKey.publicKey),
      signedPrekey: encodeBase64(spk.publicKey),
      signedPrekeySignature: encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey)),
    });
  return { username, idKey };
}

const app = buildApp();

describe('rate limits on previously-unlimited endpoints (SEC-20260621-010)', () => {
  it('429s GET /push/vapid-key after the per-IP threshold', async () => {
    let got429 = false;
    for (let i = 0; i < 25; i++) {
      const res = await request(app).get('/api/push/vapid-key');
      if (res.status === 429) {
        got429 = true;
        break;
      }
    }
    expect(got429).toBe(true);
  });

  it('429s GET /groups after the per-user threshold', async () => {
    const user = await registerUser(app, 'rl');
    let got429 = false;
    for (let i = 0; i < 70; i++) {
      const headers = signHeaders('GET', '/groups', {}, user.idKey);
      const res = await request(app).get('/api/groups').set(headers);
      if (res.status === 429) {
        got429 = true;
        break;
      }
    }
    expect(got429).toBe(true);
  });

  it('429s POST /auth/block after the per-user write threshold', async () => {
    const user = await registerUser(app, 'rlblk');
    let got429 = false;
    for (let i = 0; i < 30; i++) {
      const body = { blockedId: crypto.randomUUID() };
      const headers = signHeaders('POST', '/auth/block', body, user.idKey);
      const res = await request(app).post('/api/auth/block').set(headers).send(body);
      if (res.status === 429) {
        got429 = true;
        break;
      }
    }
    expect(got429).toBe(true);
  });
});
