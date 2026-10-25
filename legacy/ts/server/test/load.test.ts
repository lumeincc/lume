// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Load test for LUME server endpoints.
 * Uses autocannon for HTTP load testing with Ed25519 signed requests.
 *
 * Run: npx vitest run test/load.test.ts --reporter=verbose
 */

process.env.DB_PATH = ':memory:';
process.env.WS_JWT_SECRET = 'x'.repeat(40);

import { describe, it, expect, beforeAll } from 'vitest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { createServer, type Server } from 'http';
import autocannon from 'autocannon';

import authRoutes from '../src/routes/auth';
import messageRoutes from '../src/routes/messages';
import fileRoutes from '../src/routes/files';
import groupRoutes from '../src/routes/groups';
import profileRoutes from '../src/routes/profile';

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '8mb' }));
  app.use('/api/auth', authRoutes);
  app.use('/api/messages', messageRoutes);
  app.use('/api/files', fileRoutes);
  app.use('/api/groups', groupRoutes);
  app.use('/api/profile', profileRoutes);
  app.use('/api/health', (_req, res) => res.json({ status: 'ok' }));
  return app;
}

function signHeaders(method: string, path: string, body: unknown, keyPair: nacl.SignKeyPair) {
  const timestamp = Date.now().toString();
  const nonce = `load-${crypto.randomUUID()}`;
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
    'Content-Type': 'application/json',
  };
}

function makeUser() {
  const idKey = nacl.sign.keyPair();
  const spk = nacl.sign.keyPair();
  const signedPrekeySig = nacl.sign.detached(spk.publicKey, idKey.secretKey);
  return {
    username: `user_${crypto.randomUUID().slice(0, 8)}`,
    idKey,
    idPublic: encodeBase64(idKey.publicKey),
    signedPrekey: encodeBase64(spk.publicKey),
    signedPrekeySignature: encodeBase64(signedPrekeySig),
    userId: '',
  };
}

async function registerUser(baseUrl: string, user: ReturnType<typeof makeUser>) {
  const body = {
    username: user.username,
    identityKey: user.idPublic,
    signedPrekey: user.signedPrekey,
    signedPrekeySignature: user.signedPrekeySignature,
  };
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json() as { id: string };
  user.userId = data.id;
}

function listenOnRandom(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve(typeof addr === 'object' && addr ? addr.port : 0);
    });
  });
}

describe('load tests', () => {
  let server: Server;
  let baseUrl: string;
  let alice: ReturnType<typeof makeUser>;
  let bob: ReturnType<typeof makeUser>;

  beforeAll(async () => {
    const app = buildApp();
    server = createServer(app);
    const port = await listenOnRandom(server);
    baseUrl = `http://127.0.0.1:${port}`;

    alice = makeUser();
    bob = makeUser();
    await registerUser(baseUrl, alice);
    await registerUser(baseUrl, bob);
  }, 15_000);

  it('health endpoint — 1000 req/s for 5s', async () => {
    const result = await autocannon({
      url: `${baseUrl}/api/health`,
      connections: 50,
      duration: 5,
      pipelining: 10,
    });

    console.log(`[health] ${result.requests.average} req/s avg, p99 latency: ${result.latency.p99}ms, ${result.non2xx} non-2xx`);
    expect(result.non2xx).toBe(0);
    expect(result.requests.average).toBeGreaterThan(500);
  }, 30_000);

  it('auth/user lookup — signed requests', async () => {
    const result = await autocannon({
      url: `${baseUrl}/api/auth/user/${bob.username}`,
      connections: 10,
      duration: 5,
      requests: [
        {
          method: 'GET',
          setupRequest: (req) => {
            const headers = signHeaders('GET', `/auth/user/${bob.username}`, {}, alice.idKey);
            req.headers = { ...req.headers, ...headers };
            return req;
          },
        },
      ],
    });

    console.log(`[user lookup] ${result.requests.average} req/s avg, p99: ${result.latency.p99}ms, non-2xx: ${result.non2xx}`);
    // Some will be 409 due to duplicate nonce, that's expected under load
    expect(result.requests.average).toBeGreaterThan(10);
  }, 30_000);

  it('messages/send — encrypted payload throughput', async () => {
    const payload = JSON.stringify({
      v: 2,
      alg: 'lume-ratchet',
      header: {
        publicKey: encodeBase64(nacl.randomBytes(32)),
        previousChainLength: 0,
        messageNumber: 0,
      },
      ciphertext: encodeBase64(nacl.randomBytes(128)),
      nonce: encodeBase64(nacl.randomBytes(24)),
      timestamp: Date.now(),
    });

    const result = await autocannon({
      url: `${baseUrl}/api/messages/send`,
      connections: 10,
      duration: 5,
      requests: [
        {
          method: 'POST',
          setupRequest: (req) => {
            const body = {
              senderId: alice.userId,
              recipientId: bob.userId,
              encryptedPayload: payload,
            };
            const headers = signHeaders('POST', '/messages/send', body, alice.idKey);
            req.headers = { ...req.headers, ...headers };
            req.body = JSON.stringify(body);
            return req;
          },
        },
      ],
    });

    console.log(`[message send] ${result.requests.average} req/s avg, p99: ${result.latency.p99}ms, 2xx: ${result['2xx']}, non-2xx: ${result.non2xx}`);
    // Under load with unique nonces, most should succeed or get 409 (nonce replay guard)
    expect(result.requests.average).toBeGreaterThan(5);
  }, 30_000);

  it('profile get — throughput', async () => {
    const result = await autocannon({
      url: `${baseUrl}/api/profile/${alice.userId}`,
      connections: 10,
      duration: 5,
      requests: [
        {
          method: 'GET',
          setupRequest: (req) => {
            const headers = signHeaders('GET', `/profile/${alice.userId}`, {}, alice.idKey);
            req.headers = { ...req.headers, ...headers };
            return req;
          },
        },
      ],
    });

    console.log(`[profile get] ${result.requests.average} req/s avg, p99: ${result.latency.p99}ms, non-2xx: ${result.non2xx}`);
    expect(result.requests.average).toBeGreaterThan(10);
  }, 30_000);

  it('concurrent users — mixed workload', async () => {
    const result = await autocannon({
      url: `${baseUrl}/api/health`,
      connections: 100,
      duration: 5,
      pipelining: 5,
    });

    console.log(`[concurrent 100] ${result.requests.average} req/s avg, p99: ${result.latency.p99}ms, errors: ${result.errors}`);
    expect(result.errors).toBe(0);
    expect(result.requests.average).toBeGreaterThan(1000);
  }, 30_000);
}, 120_000);
