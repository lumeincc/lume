// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-011 — the pending-message cap must bound a queue per
 * sender-recipient pair, not only per recipient, so one sender cannot lock out
 * every other sender.
 * SEC-20260721-013 — bulk deletes must run PRAGMA incremental_vacuum, or freed
 * pages sit on the freelist forever and the file only ever grows.
 */

import { vi, describe, it, expect, afterAll } from 'vitest';

// The database module opens its DB at import time, so DB_PATH must be set before
// that import runs. Plain top-level assignments happen *after* hoisted imports
// in ESM; vi.hoisted runs before them. A dedicated file (not :memory:) is
// required because auto_vacuum only sticks on a fresh file created before its
// first table — on :memory: it stays NONE and incremental_vacuum no-ops, so the
// test could not tell a real reclaim from a broken one.
vi.hoisted(() => {
  process.env.DB_PATH = `./data/test-storage-${Date.now()}-${Math.floor(Math.random() * 1e9)}.db`;
  process.env.WS_JWT_SECRET = 'x'.repeat(40);
});

import path from 'path';
import fs from 'fs';
import request from 'supertest';
import express from 'express';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';

import messagesRoutes from '../src/routes/messages';
import database from '../src/db/database';

const dbFile = path.resolve(process.env.DB_PATH as string);

afterAll(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      fs.unlinkSync(dbFile + suffix);
    } catch {
      /* best effort */
    }
  }
});

function buildApp() {
  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api/messages', messagesRoutes);
  app.use((_req, res) => res.sendStatus(404));
  return app;
}

function makeUser(prefix: string): { id: string; idKey: nacl.SignKeyPair } {
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
  return { id, idKey };
}

function validEnvelope(): string {
  const key = encodeBase64(nacl.randomBytes(32));
  return JSON.stringify({
    v: 2,
    alg: 'lume-ratchet',
    header: { publicKey: key, previousChainLength: 0, messageNumber: 1 },
    ciphertext: encodeBase64(nacl.randomBytes(96)),
    nonce: encodeBase64(nacl.randomBytes(nacl.secretbox.nonceLength)),
    timestamp: Date.now(),
  });
}

function signedSend(from: nacl.SignKeyPair, senderId: string, recipientId: string) {
  const body = { senderId, recipientId, encryptedPayload: validEnvelope() };
  const timestamp = Date.now().toString();
  const nonce = `sb-${crypto.randomUUID()}`;
  const bodyString = JSON.stringify(body);
  const msg = `${timestamp}.${nonce}.POST./messages/send.${bodyString}`;
  const sig = nacl.sign.detached(new TextEncoder().encode(msg), from.secretKey);
  return {
    body,
    headers: {
      'X-Lume-Identity-Key': encodeBase64(from.publicKey),
      'X-Lume-Signature': encodeBase64(sig),
      'X-Lume-Timestamp': timestamp,
      'X-Lume-Nonce': nonce,
      'X-Lume-Path': '/messages/send',
    },
  };
}

const app = buildApp();

describe('SEC-20260721-011 — per sender-recipient inbox cap', () => {
  it('cuts off a flooding sender while a second sender still delivers', async () => {
    const recipient = makeUser('rcpt');
    const flooder = makeUser('flood');
    const other = makeUser('other');

    // Seed the flooder's pair right up to the 1000 cap (direct inserts, fast).
    for (let i = 0; i < 1000; i++) {
      database.queueMessage(crypto.randomUUID(), flooder.id, recipient.id, 'seed');
    }

    const floodReq = signedSend(flooder.idKey, flooder.id, recipient.id);
    const floodRes = await request(app)
      .post('/api/messages/send')
      .set(floodReq.headers)
      .send(floodReq.body);
    expect(floodRes.status).toBe(429);

    // A different sender to the same recipient is unaffected — that is the whole
    // point: one sender's volume must not silence others.
    const otherReq = signedSend(other.idKey, other.id, recipient.id);
    const otherRes = await request(app)
      .post('/api/messages/send')
      .set(otherReq.headers)
      .send(otherReq.body);
    expect(otherRes.status).toBe(201);
  });

  it('counts pending per pair, not globally', () => {
    const recipient = makeUser('rc2');
    const a = makeUser('sa');
    const b = makeUser('sb');
    for (let i = 0; i < 5; i++) {
      database.queueMessage(crypto.randomUUID(), a.id, recipient.id, 'x');
    }
    expect(database.getPendingMessageCountFromSender(recipient.id, a.id)).toBe(5);
    expect(database.getPendingMessageCountFromSender(recipient.id, b.id)).toBe(0);
  });
});

describe('SEC-20260721-013 — bulk deletes reclaim free pages', () => {
  it('a bulk delete drops the page count and clears the freelist', () => {
    const recipient = makeUser('vac');
    const sender = makeUser('vacs');
    const payload = 'p'.repeat(2048);
    for (let i = 0; i < 2000; i++) {
      database.queueMessage(crypto.randomUUID(), sender.id, recipient.id, payload);
    }

    const full = database.getStoragePageStats();

    // Reclaim only works when auto_vacuum is INCREMENTAL (2); a 0 here means the
    // pragma order regressed and incremental_vacuum would silently no-op.
    expect(full.autoVacuum).toBe(2);

    // deleteAllMessages runs the delete and then incremental_vacuum.
    database.deleteAllMessages(recipient.id);

    const after = database.getStoragePageStats();

    // Without the pragma the freed pages would stay on the freelist and the page
    // count would not drop; with it the count falls and the freelist is empty.
    expect(after.pageCount).toBeLessThan(full.pageCount);
    expect(after.freelistPageCount).toBe(0);
  });
});
