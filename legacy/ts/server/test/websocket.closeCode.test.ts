// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260805-004 — a handshake rejection must reach the client as its own
 * close code.
 *
 * `close()` queues a frame; `terminate()` destroys the socket at once. Called
 * back to back, the frame never leaves and the client sees a bare 1006, which is
 * indistinguishable from the network dying. That cost real debugging time once:
 * sockets died at a consistent 21 seconds and looked like an idle timeout while
 * actually being an Origin rejection — neither Node nor React Native sends an
 * Origin header at handshake, only browsers do.
 *
 * A security control that cannot explain itself gets misdiagnosed, and
 * eventually switched off by someone who assumes it is broken.
 *
 * WHAT THIS SUITE DOES AND DOES NOT PROVE. It asserts the contract: a rejected
 * client observes 4007. It does NOT reproduce the race the fix addresses —
 * over loopback the close frame flushes before `terminate()` lands, so these
 * tests pass against the unfixed code too (checked by reverting the fix and
 * re-running). The race needs a slow link to show itself.
 *
 * So this is a guard against the code changing to stop sending 4007 at all, not
 * evidence that the flush ordering is right. That part rests on routing through
 * the same `abort()` helper the authenticated paths already use.
 */

import { createServer, type Server } from 'http';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';

// The handler builds ORIGIN_ALLOWLIST at module load, and ESM hoists imports
// above plain assignments — so the environment has to be set in a hoisted block
// or the allowlist is already built from the wrong value by the time we get here.
vi.hoisted(() => {
  process.env.DB_PATH = ':memory:';
  process.env.WS_JWT_SECRET = 'x'.repeat(40);
  // Deliberately NOT set: this suite exists to exercise the origin check.
  delete process.env.SKIP_ORIGIN_CHECK;
  process.env.CLIENT_ORIGIN = 'https://allowed.example';
});

import { initWebSocket } from '../src/websocket/handler';

let server: Server;
let wss: WebSocketServer;
let port = 0;

/** Resolves with the close code the client actually observed. */
function closeCodeFor(origin?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, ['lume', 'auth.irrelevant'], {
      headers: origin ? { Origin: origin } : {},
    });
    const timer = setTimeout(() => reject(new Error('no close within 5s')), 5000);
    ws.on('close', (code: number) => {
      clearTimeout(timer);
      resolve(code);
    });
    ws.on('error', () => {
      // A rejected handshake also surfaces as an error; the close code is what
      // this test is about, so let the close handler settle it.
    });
  });
}

beforeAll(async () => {
  const app = express();
  server = createServer(app);
  wss = new WebSocketServer({ server, path: '/ws' });
  initWebSocket(wss);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as { port: number }).port;
});

afterAll(async () => {
  wss.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('handshake rejections keep their close code', () => {
  it('a disallowed origin is told 4007, not a bare 1006', async () => {
    const code = await closeCodeFor('https://evil.example');
    expect(code).toBe(4007);
  });

  it('a missing origin is told 4007 as well', async () => {
    // This is the case that cost the debugging time: non-browser clients send no
    // Origin at all, and an empty origin is not on any allowlist.
    const code = await closeCodeFor(undefined);
    expect(code).toBe(4007);
  });

  it('an allowed origin gets past the origin check', async () => {
    // The token is nonsense, so this must be refused — but for the *auth*
    // reason, which proves the origin gate let it through.
    const code = await closeCodeFor('https://allowed.example');
    expect(code).not.toBe(4007);
    expect([4001, 4002, 4003]).toContain(code);
  });
});
