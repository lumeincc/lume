// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-004 — the handshake limiter must not key on a header the client
 * controls, and SEC-20260721-005 — inbound frames must be bounded per socket.
 *
 * Both defects share a shape: a limiter that is present in the code and does
 * not bound anything.
 */

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);
process.env.SKIP_ORIGIN_CHECK = '1';
// The finding's scenario is the intended production setting behind Render.
process.env.TRUST_PROXY = '1';

import { createServer, type Server } from 'http';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import jwt from 'jsonwebtoken';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { initWebSocket } from '../src/websocket/handler';
import database from '../src/db/database';

let server: Server;
let wss: WebSocketServer;
let port = 0;

function registerUser(prefix: string): string {
  const id = crypto.randomUUID();
  const idKey = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  database.createUser(
    id,
    `${prefix}_${id.slice(0, 8)}`,
    encodeBase64(idKey.publicKey),
    encodeBase64(idKey.publicKey),
    encodeBase64(spk.publicKey),
    encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey)),
  );
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

/** Opens a socket, optionally claiming an address via X-Forwarded-For. */
function connect(token: string, forwardedFor?: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, ['lume', `auth.${token}`], {
      headers: forwardedFor ? { 'X-Forwarded-For': forwardedFor } : {},
    });
    const timeout = setTimeout(() => reject(new Error('WS connect timeout')), 5000);
    ws.on('open', () => {
      clearTimeout(timeout);
      resolve(ws);
    });
    ws.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

/** Resolves with the close code, or null if the socket stayed open. */
function closeCodeWithin(ws: WebSocket, ms: number): Promise<number | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), ms);
    ws.on('close', (code: number) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

beforeAll(async () => {
  const app = express();
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
  for (const client of wss.clients) client.terminate();
  wss.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('SEC-20260721-004 — handshake limiter keying', () => {
  it('a prepended X-Forwarded-For entry does not create a fresh bucket', async () => {
    // The limiter allows 10 handshakes per minute per address. Under the old
    // leftmost read, each of these claimed a different client address and so
    // landed in its own bucket — the limiter never fired.
    //
    // The rightmost entry is the one a trusted proxy appended. supertest is not
    // in play here: `ws` sends the header verbatim, and there is no real proxy,
    // so the whole header is client-supplied and every entry should be ignored
    // in favour of the socket peer.
    // The limiter refuses *after* the handshake, with `ws.close(4006)` — the
    // connection opens and is then dropped — so a refusal is a close code, not
    // a failed connect.
    const sockets: WebSocket[] = [];
    const closeCodes: Array<Promise<number | null>> = [];

    try {
      for (let i = 0; i < 14; i++) {
        const userId = registerUser('xff');
        const ws = await connect(makeToken(userId), `10.1.1.${i}, 203.0.113.9`);
        sockets.push(ws);
        closeCodes.push(closeCodeWithin(ws, 1500));
      }

      const refused = (await Promise.all(closeCodes)).filter((code) => code === 4006).length;

      // All 14 share one rightmost entry, so they share one bucket and the 11th
      // onward must be refused — despite each claiming a different leftmost
      // address, which is what used to make every one of them its own bucket.
      expect(refused).toBeGreaterThan(0);
    } finally {
      for (const ws of sockets) ws.terminate();
    }
  });
});

describe('SEC-20260721-005 — inbound frame budget', () => {
  it('a socket flooding ping is closed with a policy-violation code', async () => {
    const ws = await connect(makeToken(registerUser('flood')));
    const closed = closeCodeWithin(ws, 8000);

    // Past the flood threshold (3x the per-window allowance).
    for (let i = 0; i < 500; i++) {
      if (ws.readyState !== WebSocket.OPEN) break;
      ws.send(JSON.stringify({ type: 'ping' }));
    }

    expect(await closed).toBe(1008);
  });

  it('a normal client is unaffected by the budget', async () => {
    const ws = await connect(makeToken(registerUser('normal')));
    const closed = closeCodeWithin(ws, 2000);

    // A heartbeat cadence plus a burst on opening a chat — well inside 120/10s.
    for (let i = 0; i < 12; i++) {
      ws.send(JSON.stringify({ type: 'ping' }));
      await delay(20);
    }

    expect(await closed).toBeNull();
    expect(ws.readyState).toBe(WebSocket.OPEN);
    ws.terminate();
  });

  it('rejects a read receipt carrying more ids than the schema allows', async () => {
    // The handler already refused >100, but only after Zod had parsed the
    // array. The schema now bounds it, so the frame is dropped at validation
    // and the socket is otherwise unaffected.
    const ws = await connect(makeToken(registerUser('bigread')));
    const closed = closeCodeWithin(ws, 1500);

    ws.send(
      JSON.stringify({
        type: 'read',
        recipientId: crypto.randomUUID(),
        messageIds: Array.from({ length: 5000 }, () => crypto.randomUUID()),
      }),
    );

    expect(await closed).toBeNull();
    expect(ws.readyState).toBe(WebSocket.OPEN);
    ws.terminate();
  });
});
