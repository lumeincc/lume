// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-001 — the global registration bucket must not be exhaustible by
 * one source, and identity rebind must survive a flood.
 *
 * The route carries two limiters: a per-IP one, and a fleet-wide ceiling that
 * every caller shares. The shared bucket is the hazard — whatever can fill it
 * denies registration to everyone — so these tests pin the two properties that
 * keep it out of one attacker's reach.
 */

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);

import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { describe, it, expect } from 'vitest';

import authRoutes from '../src/routes/auth';

/**
 * `trust proxy` is what makes `X-Forwarded-For` drive `req.ip`, which is how the
 * per-IP limiter distinguishes callers. Production runs the same way
 * (`TRUST_PROXY=1` in render.yaml), so without it these tests would exercise a
 * configuration we do not ship.
 */
function buildApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/auth', authRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

function signHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
  const timestamp = Date.now().toString();
  const nonce = `rlim-${crypto.randomUUID()}`;
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

function makeRegistration(prefix: string) {
  // Usernames cap at 32 characters, so the random part is sized to fit.
  const username = `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 10)}`.slice(0, 32);
  const idKey = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  return {
    username,
    idKey,
    body: {
      username,
      identityKey: encodeBase64(idKey.publicKey),
      exchangeIdentityKey: encodeBase64(idKey.publicKey),
      signedPrekey: encodeBase64(spk.publicKey),
      signedPrekeySignature: encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey)),
    },
  };
}

/**
 * Junk that fails validation — the cheap ammunition the finding describes.
 *
 * Spread across addresses on purpose. The per-IP limiter caps one address at 30
 * per 10 minutes and short-circuits before the shared bucket, so a single-source
 * flood cannot drain the ceiling inside a test; the finding's own timeline says
 * it takes ~35 minutes across several per-IP windows. Rotating the source is the
 * same pressure without the wall clock, and it is also the stronger attack.
 */
async function floodSharedBucket(app: express.Express, count: number) {
  for (let i = 0; i < count; i++) {
    await request(app)
      .post('/api/auth/register')
      .set('X-Forwarded-For', `203.0.113.${(i % 250) + 1}`)
      .send({ username: '', identityKey: 'not-a-key' });
  }
}

describe('SEC-20260721-001 — global registration bucket', () => {
  it('rejected requests do not deny registration to an unrelated address', async () => {
    const app = buildApp();

    // Twice the old ceiling, none of it valid.
    await floodSharedBucket(app, 200);

    const victim = makeRegistration('victim');
    const res = await request(app)
      .post('/api/auth/register')
      .set('X-Forwarded-For', '198.51.100.20')
      .send(victim.body);

    expect(res.status).not.toBe(429);
    expect(res.status).toBe(201);
  });

  it('identity rebind stays reachable while an attacker floods /register', async () => {
    const app = buildApp();

    // An existing account, registered before the flood.
    const user = makeRegistration('rbnd');
    const created = await request(app)
      .post('/api/auth/register')
      .set('X-Forwarded-For', '198.51.100.30')
      .send(user.body);
    expect(created.status).toBe(201);
    const originalId = created.body.id as string;

    await floodSharedBucket(app, 200);

    // Rebind is a recovery path for an account that already exists: it creates
    // nothing, so a ceiling on account creation must not apply to it. This is
    // the escalation the finding calls out — a user whose server row was reset
    // could not get back in while the bucket was drained.
    const newSpk = nacl.sign.keyPair();
    const rebindBody = {
      username: user.username,
      identityKey: user.body.identityKey,
      exchangeIdentityKey: user.body.exchangeIdentityKey,
      signedPrekey: encodeBase64(newSpk.publicKey),
      signedPrekeySignature: encodeBase64(
        nacl.sign.detached(newSpk.publicKey, user.idKey.secretKey),
      ),
    };
    const headers = signHeaders('POST', '/auth/register', rebindBody, user.idKey);

    const rebind = await request(app)
      .post('/api/auth/register')
      .set('X-Forwarded-For', '198.51.100.31')
      .set(headers)
      .send(rebindBody);

    expect(rebind.status).not.toBe(429);
    expect(rebind.status).toBe(201);
    expect(rebind.body.id).toBe(originalId);
    expect(rebind.body.message).toBe('Rebind successful');
  });

  it('failed registrations do not consume the shared ceiling', async () => {
    const app = buildApp();

    // Spread junk across many addresses so the per-IP limiter never fires and
    // only the shared bucket is under test. 200 rejects is twice the ceiling the
    // finding describes; under the old behaviour they would all have counted.
    for (let i = 0; i < 200; i++) {
      await request(app)
        .post('/api/auth/register')
        .set('X-Forwarded-For', `203.0.113.${(i % 250) + 1}`)
        .send({ username: '', identityKey: 'not-a-key' });
    }

    const legit = makeRegistration('after_junk');
    const res = await request(app)
      .post('/api/auth/register')
      .set('X-Forwarded-For', '198.51.100.40')
      .send(legit.body);

    expect(res.status).toBe(201);
  });
});
