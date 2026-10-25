// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);
process.env.SKIP_ORIGIN_CHECK = '1';

import { createServer } from 'http';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import jwt from 'jsonwebtoken';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import authRoutes from '../src/routes/auth';
import { initWebSocket } from '../src/websocket/handler';
import database from '../src/db/database';

let server: ReturnType<typeof createServer>;
let wss: WebSocketServer;
let port: number;

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

function registerInDb(user: ReturnType<typeof makeUser>): string {
  const id = crypto.randomUUID();
  database.createUser(id, user.username, user.idPublic, user.signedPrekey, user.signedPrekey, user.signedPrekeySignature);
  return id;
}

function makeToken(userId: string): string {
  return jwt.sign({ sub: userId }, process.env.WS_JWT_SECRET as string, {
    algorithm: 'HS256',
    expiresIn: '10m',
    issuer: 'lume',
    audience: 'lume-ws',
  });
}

function connectWs(token: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, ['lume', `auth.${token}`]);
    const timeout = setTimeout(() => reject(new Error('WS connect timeout')), 5000);
    ws.on('open', () => { clearTimeout(timeout); resolve(ws); });
    ws.on('error', (err) => { clearTimeout(timeout); reject(err); });
  });
}

function delay(ms: number) { return new Promise(r => setTimeout(r, ms)); }

function waitForMessage(ws: WebSocket, timeoutMs = 3000): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('WS message timeout')), timeoutMs);
    ws.once('message', (data: Buffer) => {
      clearTimeout(timeout);
      resolve(JSON.parse(data.toString()));
    });
  });
}

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRoutes);
  server = createServer(app);
  wss = new WebSocketServer({ server, path: '/ws' });
  initWebSocket(wss);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve();
    });
  });
});

afterAll(async () => {
  // Force close all connected clients
  for (const client of wss.clients) {
    client.terminate();
  }
  wss.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}, 10000);

describe('WebSocket read receipts', () => {
  it('delivers read receipt, ping/pong, and typing between two users', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = registerInDb(alice);
    const bobId = registerInDb(bob);

    const aliceWs = await connectWs(makeToken(aliceId));
    const bobWs = await connectWs(makeToken(bobId));
    await delay(100);

    // Ping/pong
    const pongPromise = waitForMessage(aliceWs);
    aliceWs.send(JSON.stringify({ type: 'ping' }));
    const pong = await pongPromise;
    expect(pong.type).toBe('pong');
    expect(pong.timestamp).toBeGreaterThan(0);

    // Read receipt: bob → alice
    const readPromise = waitForMessage(aliceWs);
    bobWs.send(JSON.stringify({
      type: 'read',
      recipientId: aliceId,
      messageIds: ['aaaa1111-0000-0000-0000-000000000001', 'aaaa1111-0000-0000-0000-000000000002'],
    }));
    const readMsg = await readPromise;
    expect(readMsg.type).toBe('read');
    expect(readMsg.senderId).toBe(bobId);
    expect(readMsg.messageIds).toEqual(['aaaa1111-0000-0000-0000-000000000001', 'aaaa1111-0000-0000-0000-000000000002']);

    // Typing indicator: bob → alice
    const typingPromise = waitForMessage(aliceWs);
    bobWs.send(JSON.stringify({
      type: 'typing',
      recipientId: aliceId,
      isTyping: true,
    }));
    const typingMsg = await typingPromise;
    expect(typingMsg.type).toBe('typing');
    expect(typingMsg.senderId).toBe(bobId);
    expect(typingMsg.isTyping).toBe(true);

    aliceWs.close();
    bobWs.close();
  });

  it('read receipt to offline user returns no error (fire-and-forget)', async () => {
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bobId = registerInDb(bob);

    const bobWs = await connectWs(makeToken(bobId));
    bobWs.send(JSON.stringify({
      type: 'read',
      recipientId: crypto.randomUUID(),
      messageIds: ['aaaa1111-0000-0000-0000-000000000001'],
    }));

    await delay(200);
    expect(bobWs.readyState).toBe(WebSocket.OPEN);
    bobWs.close();
  });

  it('rejects self-receipt and unknown message types', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = registerInDb(alice);
    const aliceWs = await connectWs(makeToken(aliceId));

    // Self-receipt dropped
    aliceWs.send(JSON.stringify({
      type: 'read',
      recipientId: aliceId,
      messageIds: ['aaaa1111-0000-0000-0000-000000000001'],
    }));
    const selfResult = await waitForMessage(aliceWs, 500).catch(() => null);
    expect(selfResult).toBeNull();

    // Unknown type dropped
    aliceWs.send(JSON.stringify({ type: 'delivery', messageId: 'x' }));
    const unknownResult = await waitForMessage(aliceWs, 500).catch(() => null);
    expect(unknownResult).toBeNull();

    aliceWs.close();
  });

  it('delivers read receipt to multiple devices of same user', async () => {
    const alice = makeUser('alice_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('bob_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = registerInDb(alice);
    const bobId = registerInDb(bob);

    const aliceWs1 = await connectWs(makeToken(aliceId));
    const aliceWs2 = await connectWs(makeToken(aliceId));
    const bobWs = await connectWs(makeToken(bobId));
    await delay(100);

    const p1 = waitForMessage(aliceWs1);
    const p2 = waitForMessage(aliceWs2);

    bobWs.send(JSON.stringify({
      type: 'read',
      recipientId: aliceId,
      messageIds: ['aaaa1111-0000-0000-0000-000000000003'],
    }));

    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1.type).toBe('read');
    expect(r2.type).toBe('read');
    expect(r1.messageIds).toEqual(['aaaa1111-0000-0000-0000-000000000003']);
    expect(r2.messageIds).toEqual(['aaaa1111-0000-0000-0000-000000000003']);

    aliceWs1.close();
    aliceWs2.close();
    bobWs.close();
  });
});

describe('WebSocket group membership authorization (SEC-20260621-013)', () => {
  it('relays group typing between members but drops a non-member sender', async () => {
    const alice = makeUser('ga_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const bob = makeUser('gb_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const eve = makeUser('ge_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = registerInDb(alice);
    const bobId = registerInDb(bob);
    const eveId = registerInDb(eve);

    const groupId = crypto.randomUUID();
    database.createGroup(groupId, 'g', aliceId); // alice is admin member
    database.addGroupMember(groupId, bobId); // bob is a member; eve is NOT

    const aliceWs = await connectWs(makeToken(aliceId));
    const bobWs = await connectWs(makeToken(bobId));
    const eveWs = await connectWs(makeToken(eveId));
    await delay(100);

    // Member → member: relayed
    const okPromise = waitForMessage(aliceWs);
    bobWs.send(JSON.stringify({ type: 'typing', recipientId: aliceId, isTyping: true, groupId }));
    const ok = await okPromise;
    expect(ok.type).toBe('typing');
    expect(ok.senderId).toBe(bobId);

    // Non-member sender (eve) → member (alice): dropped
    const evePromise = waitForMessage(aliceWs, 500).catch(() => null);
    eveWs.send(JSON.stringify({ type: 'typing', recipientId: aliceId, isTyping: true, groupId }));
    expect(await evePromise).toBeNull();

    aliceWs.close();
    bobWs.close();
    eveWs.close();
  });

  it('drops group read receipts addressed to a non-member recipient', async () => {
    const alice = makeUser('ha_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const eve = makeUser('he_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12));
    const aliceId = registerInDb(alice);
    const eveId = registerInDb(eve);

    const groupId = crypto.randomUUID();
    database.createGroup(groupId, 'g', aliceId); // eve is NOT a member

    const aliceWs = await connectWs(makeToken(aliceId));
    const eveWs = await connectWs(makeToken(eveId));
    await delay(100);

    // Member (alice) → non-member recipient (eve): dropped
    const evePromise = waitForMessage(eveWs, 500).catch(() => null);
    aliceWs.send(
      JSON.stringify({
        type: 'read',
        recipientId: eveId,
        messageIds: ['aaaa1111-0000-0000-0000-000000000009'],
        groupId,
      }),
    );
    expect(await evePromise).toBeNull();

    aliceWs.close();
    eveWs.close();
  });
});
