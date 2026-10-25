// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);
process.env.UPLOAD_DIR = `./data/test-uploads-${Date.now()}`;

import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { describe, it, expect, afterAll } from 'vitest';
import fs from 'fs';

import authRoutes from '../src/routes/auth';
import fileRoutes from '../src/routes/files';

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '8mb' }));
  app.use('/api/auth', authRoutes);
  app.use('/api/files', fileRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

function signHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
  const timestamp = Date.now().toString();
  const nonce = `acl-${crypto.randomUUID()}`;
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
  const idKey = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  const res = await request(app)
    .post('/api/auth/register')
    .send({
      username: `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`,
      identityKey: encodeBase64(idKey.publicKey),
      exchangeIdentityKey: encodeBase64(idKey.publicKey),
      signedPrekey: encodeBase64(spk.publicKey),
      signedPrekeySignature: encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey)),
    });
  return { id: res.body.id as string, idKey };
}

const app = buildApp();
const blob = Buffer.from('secret-blob-contents').toString('base64');

function upload(idKey: nacl.SignKeyPair, extra: Record<string, unknown>) {
  const body = { data: blob, mimeHint: 'application/octet-stream', ...extra };
  return request(app)
    .post('/api/files/upload')
    .set(signHeaders('POST', '/files/upload', body, idKey))
    .send(body);
}

function download(idKey: nacl.SignKeyPair, fileId: string) {
  return request(app)
    .get(`/api/files/${fileId}/raw`)
    .set(signHeaders('GET', `/files/${fileId}/raw`, {}, idKey));
}

afterAll(() => {
  try {
    fs.rmSync(process.env.UPLOAD_DIR as string, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('file download ACL — deny by default (SEC-20260621-006 / 005)', () => {
  it('allows uploader and designated recipient, forbids third parties', async () => {
    const alice = await registerUser(app, 'fa');
    const bob = await registerUser(app, 'fb');
    const eve = await registerUser(app, 'fe');

    const up = await upload(alice.idKey, { recipientId: bob.id });
    expect(up.status).toBe(201);
    const fileId = up.body.fileId as string;

    expect((await download(alice.idKey, fileId)).status).toBe(200); // uploader
    expect((await download(bob.idKey, fileId)).status).toBe(200); // recipient
    expect((await download(eve.idKey, fileId)).status).toBe(403); // third party
  });

  it('forbids third parties for a null-recipient, non-public file (legacy)', async () => {
    const alice = await registerUser(app, 'ga');
    const eve = await registerUser(app, 'ge');

    const up = await upload(alice.idKey, {});
    const fileId = up.body.fileId as string;

    expect((await download(alice.idKey, fileId)).status).toBe(200); // uploader
    expect((await download(eve.idKey, fileId)).status).toBe(403); // third party (was 200 before SEC-006)
  });

  it('allows any authenticated user to download an explicitly public file (avatars)', async () => {
    const alice = await registerUser(app, 'ha');
    const eve = await registerUser(app, 'he');

    const up = await upload(alice.idKey, { isPublic: true });
    const fileId = up.body.fileId as string;

    expect((await download(eve.idKey, fileId)).status).toBe(200);
  });
});
