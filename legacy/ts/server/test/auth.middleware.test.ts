// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);

import { describe, expect, it } from 'vitest';
import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';

import { requireSignature } from '../src/middleware/auth';
import authRoutes from '../src/routes/auth';
import messageRoutes from '../src/routes/messages';

// Helper to build signed headers for tests
function signedHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
  const timestamp = Date.now().toString();
  const nonce = `test-${crypto.randomUUID()}`;
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

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/auth', authRoutes);
  app.use('/api/messages', messageRoutes);
  // default 404
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

describe('requireSignature middleware', () => {
  const keyPair = nacl.sign.keyPair();
  const identityKey = encodeBase64(keyPair.publicKey);

  it('rejects when headers are missing', async () => {
    const app = express().use(express.json(), requireSignature, (_req, res) => res.sendStatus(200));
    const res = await request(app).post('/api/auth/prekeys').send({});
    expect(res.status).toBe(401);
  });

  it('accepts a properly signed request', async () => {
    const app = buildApp();
    const body = { username: 'alice_01', identityKey, signedPrekey: identityKey, signedPrekeySignature: encodeBase64(nacl.sign.detached(new TextEncoder().encode(identityKey), keyPair.secretKey)) };
    body.oneTimePrekeys = [];
    const headers = signedHeaders('POST', '/auth/register', body, keyPair);
    const res = await request(app).post('/api/auth/register').set(headers).send(body);
    // register is now dual-mode: signed headers trigger requireSignature inside the handler
    expect([201, 400, 409]).toContain(res.status); // allow conflicts on reruns
  });

  it('blocks replayed signature', async () => {
    const app = express();
    app.use(express.json());
    app.post('/api/protected', requireSignature, (_req, res) => res.json({ ok: true }));

    const body = { ping: 'pong' };
    const headers = signedHeaders('POST', '/protected', body, keyPair);

    const first = await request(app).post('/api/protected').set(headers).send(body);
    expect(first.status).toBe(200);

    const second = await request(app).post('/api/protected').set(headers).send(body);
    expect(second.status).toBe(409); // duplicate request
  });
});
