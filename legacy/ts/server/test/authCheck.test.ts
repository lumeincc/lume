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
import database from '../src/db/database';

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/auth', authRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

const app = buildApp();

// Regression for the non-ledger correctness mismatch: the client calls
// /auth/check/:username during setup before any signing keys exist, so the
// endpoint must be callable without auth headers (PROTOCOL.md: Auth = No).
describe('GET /auth/check/:username (unauthenticated)', () => {
  it('returns availability without any auth headers (not 401)', async () => {
    const res = await request(app).get('/api/auth/check/unused_name_xyz123');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('available');
    expect(res.body.available).toBe(true);
  });

  it('still validates the username format', async () => {
    const res = await request(app).get('/api/auth/check/ab'); // too short
    expect(res.status).toBe(400);
  });

  // SEC-20260721-015: check must agree with register. A taken username is
  // unavailable even when its owner is non-discoverable — the old
  // `available: !user || !user.discoverable` reported it as available and, since
  // register still 409s, that contradiction proved the account existed.
  it('reports a taken non-discoverable username as unavailable', async () => {
    const idk = nacl.sign.keyPair();
    const spk = nacl.sign.keyPair();
    const username = `hidden_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
    const id = crypto.randomUUID();
    database.createUser(
      id,
      username,
      encodeBase64(idk.publicKey),
      encodeBase64(idk.publicKey),
      encodeBase64(spk.publicKey),
      encodeBase64(nacl.sign.detached(spk.publicKey, idk.secretKey)),
    );
    database.setDiscoverable(id, false);

    const res = await request(app).get(`/api/auth/check/${username}`);
    expect(res.status).toBe(200);
    expect(res.body.available).toBe(false);
  });
});
