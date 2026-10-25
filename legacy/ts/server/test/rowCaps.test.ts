// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);
process.env.MAX_GROUPS_PER_USER = '2';

import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { describe, it, expect } from 'vitest';

import authRoutes from '../src/routes/auth';
import groupRoutes from '../src/routes/groups';
import database from '../src/db/database';

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/auth', authRoutes);
  app.use('/api/groups', groupRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

function signHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
  const timestamp = Date.now().toString();
  const nonce = `cap-${crypto.randomUUID()}`;
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

function makeDbUser(prefix: string): string {
  const id = crypto.randomUUID();
  const idk = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  database.createUser(
    id,
    `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`,
    encodeBase64(idk.publicKey),
    encodeBase64(idk.publicKey),
    encodeBase64(spk.publicKey),
    encodeBase64(nacl.sign.detached(spk.publicKey, idk.secretKey)),
  );
  return id;
}

async function registerUser(app: express.Express, prefix: string) {
  const idKey = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  await request(app)
    .post('/api/auth/register')
    .send({
      username: `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`,
      identityKey: encodeBase64(idKey.publicKey),
      exchangeIdentityKey: encodeBase64(idKey.publicKey),
      signedPrekey: encodeBase64(spk.publicKey),
      signedPrekeySignature: encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey)),
    });
  return { idKey };
}

const app = buildApp();

describe('row caps (SEC-20260621-020)', () => {
  it('rejects group creation beyond MAX_GROUPS_PER_USER', async () => {
    const user = await registerUser(app, 'cap');
    const memberId = makeDbUser('member'); // CreateGroupBodySchema requires >= 1 member
    for (let i = 0; i < 2; i++) {
      const body = { name: `g${i}`, memberIds: [memberId] };
      const res = await request(app)
        .post('/api/groups/create')
        .set(signHeaders('POST', '/groups/create', body, user.idKey))
        .send(body);
      expect(res.status).toBe(201);
    }
    const body = { name: 'g-over', memberIds: [memberId] };
    const res = await request(app)
      .post('/api/groups/create')
      .set(signHeaders('POST', '/groups/create', body, user.idKey))
      .send(body);
    expect(res.status).toBe(429);
  });

  it('count helpers reflect rows (idempotent blocks)', () => {
    const a = makeDbUser('a');
    const b = makeDbUser('b');
    const c = makeDbUser('c');

    expect(database.countBlockedByUser(a)).toBe(0);
    database.blockUser(a, b);
    database.blockUser(a, c);
    database.blockUser(a, b); // INSERT OR IGNORE — no new row
    expect(database.countBlockedByUser(a)).toBe(2);

    expect(database.countGroupsByCreator(a)).toBe(0);
    database.createGroup(crypto.randomUUID(), 'x', a);
    expect(database.countGroupsByCreator(a)).toBe(1);
  });
});
