// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-023 — a non-discoverable user must not be added to a group by
 * someone else, since GET /groups/:id would then disclose their username to
 * co-members without their consent.
 */

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);

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
  const nonce = `gp-${crypto.randomUUID()}`;
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

/** Creates a user directly; returns id + keypair. discoverable defaults to true. */
function makeUser(prefix: string, discoverable = true): { id: string; idKey: nacl.SignKeyPair } {
  const id = crypto.randomUUID();
  const idKey = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  database.createUser(
    id,
    `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`,
    encodeBase64(idKey.publicKey),
    encodeBase64(idKey.publicKey),
    encodeBase64(spk.publicKey),
    encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey)),
  );
  if (!discoverable) database.setDiscoverable(id, false);
  return { id, idKey };
}

const app = buildApp();

describe('SEC-20260721-023 — group adds honour discoverable', () => {
  it('does not add a non-discoverable user passed in memberIds at creation', async () => {
    const admin = makeUser('admin');
    const hidden = makeUser('hidden', false);

    const body = { name: 'g', memberIds: [hidden.id] };
    const res = await request(app)
      .post('/api/groups/create')
      .set(signHeaders('POST', '/groups/create', body, admin.idKey))
      .send(body);

    expect(res.status).toBe(201);
    const memberIds = (res.body.members as Array<{ user_id: string }>).map(m => m.user_id);
    expect(memberIds).toContain(admin.id); // creator is in
    expect(memberIds).not.toContain(hidden.id); // non-discoverable filtered out
  });

  it('adds a discoverable user but rejects a non-discoverable one via add-member', async () => {
    const admin = makeUser('admin2');
    const visible = makeUser('visible');
    const hidden = makeUser('hidden2', false);

    const createBody = { name: 'g2', memberIds: [visible.id] };
    const created = await request(app)
      .post('/api/groups/create')
      .set(signHeaders('POST', '/groups/create', createBody, admin.idKey))
      .send(createBody);
    expect(created.status).toBe(201);
    const groupId = created.body.id as string;

    // Discoverable user adds fine.
    const okBody = { userId: visible.id };
    const okRes = await request(app)
      .post(`/api/groups/${groupId}/members`)
      .set(signHeaders('POST', `/groups/${groupId}/members`, okBody, admin.idKey))
      .send(okBody);
    expect(okRes.status).toBe(200);

    // Non-discoverable user is treated as not-found.
    const hiddenBody = { userId: hidden.id };
    const hiddenRes = await request(app)
      .post(`/api/groups/${groupId}/members`)
      .set(signHeaders('POST', `/groups/${groupId}/members`, hiddenBody, admin.idKey))
      .send(hiddenBody);
    expect(hiddenRes.status).toBe(404);
  });
});
