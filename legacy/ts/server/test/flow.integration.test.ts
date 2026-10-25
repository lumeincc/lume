// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);

import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { decodeBase64, encodeBase64 } from 'tweetnacl-util';
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
  const spk = nacl.sign.keyPair();
  const signedPrekeySig = nacl.sign.detached(spk.publicKey, idKey.secretKey);
  return {
    username,
    idKey,
    idPublic: encodeBase64(idKey.publicKey),
    signedPrekey: encodeBase64(spk.publicKey),
    signedPrekeySignature: encodeBase64(signedPrekeySig),
  };
}

describe('integration: auth + messages flow', () => {
  const app = buildApp();

  it('register -> block -> blocked list -> bundle -> send -> pending -> ack -> unblock', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    let res = await request(app).post('/api/auth/register').send({
      username: alice.username,
      identityKey: alice.idPublic,
      signedPrekey: alice.signedPrekey,
      signedPrekeySignature: alice.signedPrekeySignature,
      oneTimePrekeys: [],
    });
    expect([201, 409]).toContain(res.status);
    const aliceId = res.body.id || res.body?.userId || res.body?.message || 'alice-id';

    res = await request(app).post('/api/auth/register').send({
      username: bob.username,
      identityKey: bob.idPublic,
      signedPrekey: bob.signedPrekey,
      signedPrekeySignature: bob.signedPrekeySignature,
      oneTimePrekeys: [],
    });
    expect([201, 409]).toContain(res.status);
    const bobId = res.body.id || res.body?.userId || res.body?.message || 'bob-id';

    const blockedBeforeHeaders = signHeaders('GET', '/auth/blocked', {}, alice.idKey);
    res = await request(app).get('/api/auth/blocked').set(blockedBeforeHeaders);
    expect(res.status).toBe(200);
    expect(res.body.blockedIds).not.toContain(bobId);

    const blockBody = { blockedId: bobId };
    const blockHeaders = signHeaders('POST', '/auth/block', blockBody, alice.idKey);
    res = await request(app).post('/api/auth/block').set(blockHeaders).send(blockBody);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    const blockedHeaders = signHeaders('GET', '/auth/blocked', {}, alice.idKey);
    res = await request(app).get('/api/auth/blocked').set(blockedHeaders);
    expect(res.status).toBe(200);
    expect(res.body.blockedIds).toContain(bobId);

    const bundleHeaders = signHeaders('POST', '/auth/bundle', { username: bob.username }, alice.idKey);
    res = await request(app).post('/api/auth/bundle').set(bundleHeaders).send({ username: bob.username });
    expect(res.status).toBe(200);

    const payload = JSON.stringify({
      v: 2,
      alg: 'lume-ratchet',
      header: {
        publicKey: encodeBase64(nacl.randomBytes(32)),
        previousChainLength: 0,
        messageNumber: 0,
      },
      ciphertext: encodeBase64(nacl.randomBytes(48)),
      nonce: encodeBase64(nacl.randomBytes(nacl.secretbox.nonceLength)),
      timestamp: Date.now(),
    });
    const sendBody = { senderId: aliceId, recipientId: bobId, encryptedPayload: payload };
    const sendHeaders = signHeaders('POST', '/messages/send', sendBody, alice.idKey);
    res = await request(app).post('/api/messages/send').set(sendHeaders).send(sendBody);
    expect(res.status).toBe(201);
    const messageId = res.body.messageId;

    const pendingHeaders = signHeaders('GET', `/messages/pending/${bobId}`, {}, bob.idKey);
    res = await request(app).get(`/api/messages/pending/${bobId}`).set(pendingHeaders);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBeGreaterThan(0);

    const ackHeaders = signHeaders('DELETE', `/messages/${messageId}`, {}, bob.idKey);
    res = await request(app).delete(`/api/messages/${messageId}`).set(ackHeaders);
    expect(res.status).toBe(200);

    const unblockBody = { blockedId: bobId };
    const unblockHeaders = signHeaders('POST', '/auth/unblock', unblockBody, alice.idKey);
    res = await request(app).post('/api/auth/unblock').set(unblockHeaders).send(unblockBody);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    const blockedAfterUnblockHeaders = signHeaders('GET', '/auth/blocked', {}, alice.idKey);
    res = await request(app).get('/api/auth/blocked').set(blockedAfterUnblockHeaders);
    expect(res.status).toBe(200);
    expect(res.body.blockedIds).not.toContain(bobId);
  });

  it('returns 404 when trying to block unknown user id', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    let res = await request(app).post('/api/auth/register').send({
      username: alice.username,
      identityKey: alice.idPublic,
      signedPrekey: alice.signedPrekey,
      signedPrekeySignature: alice.signedPrekeySignature,
      oneTimePrekeys: [],
    });
    expect([201, 409]).toContain(res.status);

    const unknownUserId = '00000000-0000-4000-8000-000000000000';
    const blockBody = { blockedId: unknownUserId };
    const blockHeaders = signHeaders('POST', '/auth/block', blockBody, alice.idKey);
    res = await request(app).post('/api/auth/block').set(blockHeaders).send(blockBody);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found');
  });

  it('rejects block with invalid blockedId format', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    let res = await request(app).post('/api/auth/register').send({
      username: alice.username,
      identityKey: alice.idPublic,
      signedPrekey: alice.signedPrekey,
      signedPrekeySignature: alice.signedPrekeySignature,
      oneTimePrekeys: [],
    });
    expect([201, 409]).toContain(res.status);

    const blockBody = { blockedId: 'not-a-uuid' };
    const blockHeaders = signHeaders('POST', '/auth/block', blockBody, alice.idKey);
    res = await request(app).post('/api/auth/block').set(blockHeaders).send(blockBody);
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid UUID format');
  });

  it('rejects self-block attempts', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    let res = await request(app).post('/api/auth/register').send({
      username: alice.username,
      identityKey: alice.idPublic,
      signedPrekey: alice.signedPrekey,
      signedPrekeySignature: alice.signedPrekeySignature,
      oneTimePrekeys: [],
    });
    expect([201, 409]).toContain(res.status);
    const aliceId = res.body.id || res.body?.userId || res.body?.message || 'alice-id';

    const blockBody = { blockedId: aliceId };
    const blockHeaders = signHeaders('POST', '/auth/block', blockBody, alice.idKey);
    res = await request(app).post('/api/auth/block').set(blockHeaders).send(blockBody);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Cannot block yourself');
  });

  it('rejects blocked list request without auth headers', async () => {
    const res = await request(app).get('/api/auth/blocked');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Missing authentication headers');
  });

  it('rejects blocked list request with invalid signature', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));

    let res = await request(app).post('/api/auth/register').send({
      username: alice.username,
      identityKey: alice.idPublic,
      signedPrekey: alice.signedPrekey,
      signedPrekeySignature: alice.signedPrekeySignature,
      oneTimePrekeys: [],
    });
    expect([201, 409]).toContain(res.status);

    const headers = signHeaders('GET', '/auth/blocked', {}, alice.idKey);
    const signatureBytes = decodeBase64(headers['X-Lume-Signature']);
    signatureBytes[0] ^= 1;
    headers['X-Lume-Signature'] = encodeBase64(signatureBytes);

    res = await request(app).get('/api/auth/blocked').set(headers);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Invalid signature');
  });

  it('rejects blocked list request from unknown signer identity', async () => {
    const ghost = nacl.sign.keyPair();
    const headers = signHeaders('GET', '/auth/blocked', {}, ghost);

    const res = await request(app).get('/api/auth/blocked').set(headers);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Unauthorized');
  });
});

// =============================================================================
// Account Deletion Lifecycle — DELETE /auth/user/:userId
//
// NOTE: The route is DELETE /auth/user/:userId (NOT /auth/account).
//
// Panic Wipe — server-side note:
// Panic wipe in LUME is a purely client-side feature. The client deletes all
// local keys, messages and state stored on the device. There is no dedicated
// server-side "panic wipe" route. From the server's perspective, a panic wipe
// is indistinguishable from a normal account deletion followed by local data
// erasure. These tests cover the server side of that scenario via the account
// deletion path.
// =============================================================================

describe('integration: account deletion lifecycle', () => {
  const app = buildApp();

  async function registerUser(user: ReturnType<typeof makeUser>) {
    const res = await request(app).post('/api/auth/register').send({
      username: user.username,
      identityKey: user.idPublic,
      signedPrekey: user.signedPrekey,
      signedPrekeySignature: user.signedPrekeySignature,
      oneTimePrekeys: [],
    });
    expect(res.status).toBe(201);
    return res.body.id as string;
  }

  async function sendMessage(
    sender: ReturnType<typeof makeUser>,
    senderId: string,
    recipientId: string,
  ) {
    const payload = JSON.stringify({
      v: 2,
      alg: 'lume-ratchet',
      header: {
        publicKey: encodeBase64(nacl.randomBytes(32)),
        previousChainLength: 0,
        messageNumber: 0,
      },
      ciphertext: encodeBase64(nacl.randomBytes(48)),
      nonce: encodeBase64(nacl.randomBytes(nacl.secretbox.nonceLength)),
      timestamp: Date.now(),
    });
    const body = { senderId, recipientId, encryptedPayload: payload };
    const headers = signHeaders('POST', '/messages/send', body, sender.idKey);
    const res = await request(app).post('/api/messages/send').set(headers).send(body);
    expect(res.status).toBe(201);
    return res.body.messageId as string;
  }

  it('successful account deletion returns 200', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);

    const headers = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    const res = await request(app).delete(`/api/auth/user/${aliceId}`).set(headers);

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Account deleted');
  });

  it('after deletion, session token request returns 404', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);

    const deleteHeaders = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    await request(app).delete(`/api/auth/user/${aliceId}`).set(deleteHeaders);

    const body = { userId: aliceId };
    const sessionHeaders = signHeaders('POST', '/auth/session', body, alice.idKey);
    const res = await request(app).post('/api/auth/session').set(sessionHeaders).send(body);

    expect([403, 404]).toContain(res.status);
  });

  it('after deletion, fetching pending messages returns 403', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);
    const bobId = await registerUser(bob);

    await sendMessage(bob, bobId, aliceId);

    const deleteHeaders = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    await request(app).delete(`/api/auth/user/${aliceId}`).set(deleteHeaders);

    const pendingHeaders = signHeaders('GET', `/messages/pending/${aliceId}`, {}, alice.idKey);
    const res = await request(app).get(`/api/messages/pending/${aliceId}`).set(pendingHeaders);

    expect([403, 404]).toContain(res.status);
  });

  it('after deletion, fetching the deleted user prekey bundle returns 404', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);
    await registerUser(bob);

    const deleteHeaders = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    await request(app).delete(`/api/auth/user/${aliceId}`).set(deleteHeaders);

    const bundleHeaders = signHeaders('POST', '/auth/bundle', { username: alice.username }, bob.idKey);
    const res = await request(app)
      .post('/api/auth/bundle')
      .set(bundleHeaders)
      .send({ username: alice.username });

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found');
  });

  it('after deletion, GET /auth/user/:username returns 404', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);
    await registerUser(bob);

    const deleteHeaders = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    await request(app).delete(`/api/auth/user/${aliceId}`).set(deleteHeaders);

    const getUserHeaders = signHeaders('GET', `/auth/user/${alice.username}`, {}, bob.idKey);
    const res = await request(app).get(`/api/auth/user/${alice.username}`).set(getUserHeaders);
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found');
  });

  it('GET /auth/user/:username without auth returns 401', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    await registerUser(alice);

    const res = await request(app).get(`/api/auth/user/${alice.username}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Missing authentication headers');
  });

  it('after deletion, username becomes available for re-registration', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);

    const checkBeforeHeaders = signHeaders('GET', `/auth/check/${alice.username}`, {}, alice.idKey);
    const checkBefore = await request(app).get(`/api/auth/check/${alice.username}`).set(checkBeforeHeaders);
    expect(checkBefore.body.available).toBe(false);

    const deleteHeaders = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    await request(app).delete(`/api/auth/user/${aliceId}`).set(deleteHeaders);

    const checkAfterHeaders = signHeaders('GET', `/auth/check/${alice.username}`, {}, alice.idKey);
    const checkAfter = await request(app).get(`/api/auth/check/${alice.username}`).set(checkAfterHeaders);
    expect(checkAfter.status).toBe(200);
    expect(checkAfter.body.available).toBe(true);
  });

  it('deleting a non-existent userId returns 404', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    await registerUser(alice);

    const nonExistentId = '00000000-0000-4000-8000-000000000099';
    const headers = signHeaders('DELETE', `/auth/user/${nonExistentId}`, {}, alice.idKey);
    const res = await request(app).delete(`/api/auth/user/${nonExistentId}`).set(headers);

    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found');
  });

  it('deleting an already-deleted account returns a non-200 error', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);

    const headers = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    const first = await request(app).delete(`/api/auth/user/${aliceId}`).set(headers);
    expect(first.status).toBe(200);

    const secondHeaders = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    const second = await request(app).delete(`/api/auth/user/${aliceId}`).set(secondHeaders);
    expect(second.status).not.toBe(200);
  });

  it('cross-user deletion is rejected with 403', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    await registerUser(alice);
    const bobId = await registerUser(bob);

    const headers = signHeaders('DELETE', `/auth/user/${bobId}`, {}, alice.idKey);
    const res = await request(app).delete(`/api/auth/user/${bobId}`).set(headers);

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Unauthorized: Identity key mismatch');
  });

  it('delete with malformed userId returns 400', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    await registerUser(alice);

    const malformedId = 'not-a-valid-uuid!!!';
    const headers = signHeaders('DELETE', `/auth/user/${malformedId}`, {}, alice.idKey);
    const res = await request(app).delete(`/api/auth/user/${malformedId}`).set(headers);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Invalid UUID format');
  });

  it('delete without auth headers returns 401', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);

    const res = await request(app).delete(`/api/auth/user/${aliceId}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Missing authentication headers');
  });

  it('panic wipe: all server-side data is inaccessible after account deletion', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = await registerUser(alice);
    const bobId = await registerUser(bob);

    await sendMessage(alice, aliceId, bobId);
    await sendMessage(bob, bobId, aliceId);

    // Server-side deletion (client panic wipe erases local keys/messages)
    const deleteHeaders = signHeaders('DELETE', `/auth/user/${aliceId}`, {}, alice.idKey);
    const deleteRes = await request(app).delete(`/api/auth/user/${aliceId}`).set(deleteHeaders);
    expect(deleteRes.status).toBe(200);

    // User lookup gone (authenticated request via bob)
    const userLookupHeaders = signHeaders('GET', `/auth/user/${alice.username}`, {}, bob.idKey);
    const userLookup = await request(app).get(`/api/auth/user/${alice.username}`).set(userLookupHeaders);
    expect(userLookup.status).toBe(404);

    // Prekey bundle gone
    const bundleHeaders = signHeaders('POST', '/auth/bundle', { username: alice.username }, bob.idKey);
    const bundleRes = await request(app)
      .post('/api/auth/bundle')
      .set(bundleHeaders)
      .send({ username: alice.username });
    expect(bundleRes.status).toBe(404);

    // Username available again
    const checkHeaders = signHeaders('GET', `/auth/check/${alice.username}`, {}, bob.idKey);
    const checkRes = await request(app).get(`/api/auth/check/${alice.username}`).set(checkHeaders);
    expect(checkRes.status).toBe(200);
    expect(checkRes.body.available).toBe(true);

    // Session endpoint rejects deleted identity
    const sessionBody = { userId: aliceId };
    const sessionHeaders = signHeaders('POST', '/auth/session', sessionBody, alice.idKey);
    const sessionRes = await request(app)
      .post('/api/auth/session')
      .set(sessionHeaders)
      .send(sessionBody);
    expect([403, 404]).toContain(sessionRes.status);
  });
});
