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
import messageRoutes from '../src/routes/messages';

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/auth', authRoutes);
  app.use('/api/messages', messageRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

function signHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
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

function makeUser(username: string) {
  const idKey = nacl.sign.keyPair();
  const exchangeKey = nacl.box.keyPair();
  const spk = nacl.sign.keyPair();
  const signedPrekeySig = nacl.sign.detached(spk.publicKey, idKey.secretKey);
  return {
    username,
    idKey,
    exchangeKey,
    idPublic: encodeBase64(idKey.publicKey),
    exchangePublic: encodeBase64(exchangeKey.publicKey),
    signedPrekey: encodeBase64(spk.publicKey),
    signedPrekeySignature: encodeBase64(signedPrekeySig),
  };
}

function registerBody(user: ReturnType<typeof makeUser>, opks: Array<{ id: string; publicKey: string }> = []) {
  return {
    username: user.username,
    identityKey: user.idPublic,
    exchangeIdentityKey: user.exchangePublic,
    signedPrekey: user.signedPrekey,
    signedPrekeySignature: user.signedPrekeySignature,
    oneTimePrekeys: opks,
  };
}

describe('auth rebind: POST /auth/register dual-mode', () => {
  const app = buildApp();

  // ── Step 1: Happy-path rebind ───────────────────────────────────────────────
  it('rebinds silently when signed headers match existing identityKey', async () => {
    const user = makeUser('rebind_happy_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    // Register unsigned (first-time setup)
    const firstBody = registerBody(user);
    const firstRes = await request(app).post('/api/auth/register').send(firstBody);
    expect(firstRes.status).toBe(201);
    const originalId = firstRes.body.id;
    expect(originalId).toBeTruthy();

    // Generate new SPK and OPKs for the rebind
    const newSpk = nacl.sign.keyPair();
    const newSpkSig = nacl.sign.detached(newSpk.publicKey, user.idKey.secretKey);
    const newOPKs = [
      { id: `${user.username}-opk-${Date.now()}-0`, publicKey: encodeBase64(nacl.box.keyPair().publicKey) },
      { id: `${user.username}-opk-${Date.now()}-1`, publicKey: encodeBase64(nacl.box.keyPair().publicKey) },
    ];

    const rebindBody = {
      username: user.username,
      identityKey: user.idPublic,
      exchangeIdentityKey: user.exchangePublic,
      signedPrekey: encodeBase64(newSpk.publicKey),
      signedPrekeySignature: encodeBase64(newSpkSig),
      oneTimePrekeys: newOPKs,
    };

    const headers = signHeaders('POST', '/auth/register', rebindBody, user.idKey);
    const rebindRes = await request(app).post('/api/auth/register').set(headers).send(rebindBody);

    expect(rebindRes.status).toBe(201);
    expect(rebindRes.body.id).toBe(originalId);
    expect(rebindRes.body.message).toBe('Rebind successful');
  });

  // ── Step 2: Signed register for missing row + identity mismatch → 403 ──────
  it('creates user when signed register targets non-existent username', async () => {
    const user = makeUser('rebind_new_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const body = registerBody(user);

    const headers = signHeaders('POST', '/auth/register', body, user.idKey);
    const res = await request(app).post('/api/auth/register').set(headers).send(body);

    expect(res.status).toBe(201);
    expect(res.body.id).toBeTruthy();
    expect(res.body.username).toBe(user.username);
  });

  it('rejects signed register when header identityKey differs from body identityKey (403)', async () => {
    const user = makeUser('rebind_mismatch_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    // Sign with one key pair but put a DIFFERENT identityKey in the body
    const otherIdKey = nacl.sign.keyPair();
    const otherSpk = nacl.sign.keyPair();
    const otherSpkSig = nacl.sign.detached(otherSpk.publicKey, otherIdKey.secretKey);

    const body = {
      username: user.username,
      identityKey: encodeBase64(otherIdKey.publicKey), // different from signing key
      exchangeIdentityKey: user.exchangePublic,
      signedPrekey: encodeBase64(otherSpk.publicKey),
      signedPrekeySignature: encodeBase64(otherSpkSig),
      oneTimePrekeys: [],
    };

    // Sign headers with user.idKey (K1) but body has otherIdKey (K2)
    const headers = signHeaders('POST', '/auth/register', body, user.idKey);
    const res = await request(app).post('/api/auth/register').set(headers).send(body);

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Identity key mismatch');
  });

  // ── Step 3: Adversarial rebind rejected ─────────────────────────────────────
  it('rejects signed register with different identityKey for existing username (409)', async () => {
    const user = makeUser('rebind_adv_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    // Register unsigned with identityKey K1
    const firstBody = registerBody(user);
    const firstRes = await request(app).post('/api/auth/register').send(firstBody);
    expect(firstRes.status).toBe(201);

    // Attacker tries to rebind with a different identityKey K2
    const attackerIdKey = nacl.sign.keyPair();
    const attackerExchangeKey = nacl.box.keyPair();
    const attackerSpk = nacl.sign.keyPair();
    const attackerSpkSig = nacl.sign.detached(attackerSpk.publicKey, attackerIdKey.secretKey);

    const attackBody = {
      username: user.username,
      identityKey: encodeBase64(attackerIdKey.publicKey),
      exchangeIdentityKey: encodeBase64(attackerExchangeKey.publicKey),
      signedPrekey: encodeBase64(attackerSpk.publicKey),
      signedPrekeySignature: encodeBase64(attackerSpkSig),
      oneTimePrekeys: [],
    };

    const headers = signHeaders('POST', '/auth/register', attackBody, attackerIdKey);
    const res = await request(app).post('/api/auth/register').set(headers).send(attackBody);

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('Username already taken');
  });

  // ── Step 4: Unsigned first-time register still works ────────────────────────
  it('allows unsigned first-time register for a fresh username', async () => {
    const user = makeUser('rebind_unsigned_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const body = registerBody(user);

    const res = await request(app).post('/api/auth/register').send(body);

    expect(res.status).toBe(201);
    expect(res.body.id).toBeTruthy();
    expect(res.body.username).toBe(user.username);
    expect(res.body.message).toBe('Registration successful');
  });
});
