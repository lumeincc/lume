// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from "node:crypto";
import { aeadDecrypt, aeadEncrypt, checkAgainstWycheproof } from "./xchacha20poly1305.mjs";

const [handshakeFile, wycheproofDir, outputFile] = process.argv.slice(2);

const bytes = (text) => Buffer.from(text, "hex");
const hex = (value) => Buffer.from(value).toString("hex");
const u32 = (value) => {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
};
const u64 = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
};
const label = (name) => {
  const text = Buffer.from(`LUME/v1/${name}`, "ascii");
  return Buffer.concat([u32(text.length), text]);
};

const sealed = (key, associatedData, plaintext, random) => {
  const nonce = random(24);
  return Buffer.concat([nonce, aeadEncrypt(key, nonce, associatedData, plaintext)]);
};
const opened = (key, associatedData, value) => aeadDecrypt(key, value.subarray(0, 24), associatedData, value.subarray(24));

checkAgainstWycheproof(wycheproofDir);

const randomStream = (seed) => {
  let counter = 0;
  let pool = Buffer.alloc(0);
  return (length) => {
    while (pool.length < length) {
      pool = Buffer.concat([pool, createHash("sha256").update(Buffer.from(seed, "ascii")).update(u64(counter)).digest()]);
      counter += 1;
    }
    const out = pool.subarray(0, length);
    pool = pool.subarray(length);
    return Buffer.from(out);
  };
};

const x25519Private = (secret) => createPrivateKey({ key: Buffer.concat([bytes("302e020100300506032b656e04220420"), secret]), format: "der", type: "pkcs8" });
const keyPair = (secret) => ({ secret, public: createPublicKey(x25519Private(secret)).export({ format: "der", type: "spki" }).subarray(-32) });
const dh = (secret, peer) => diffieHellman({
  privateKey: x25519Private(secret),
  publicKey: createPublicKey({ key: Buffer.concat([bytes("302a300506032b656e032100"), peer]), format: "der", type: "spki" }),
});
const kdfRoot = (rootKey, shared) => {
  const output = Buffer.from(hkdfSync("sha256", shared, rootKey, label("ratchet/root"), 96));
  return [output.subarray(0, 32), output.subarray(32, 64), output.subarray(64, 96)];
};
const kdfChain = (chainKey) => [
  createHmac("sha256", chainKey).update(Buffer.from([0x02])).digest(),
  createHmac("sha256", chainKey).update(Buffer.from([0x01])).digest(),
];
const encodeHeader = (ratchetKey, previous, number) => Buffer.concat([ratchetKey, u32(previous), u32(number)]);
const decodeHeader = (value) => ({ dh: value.subarray(0, 32), pn: value.readUInt32BE(32), n: value.readUInt32BE(36) });

const encrypt = (state, plaintext) => {
  const [chainKey, messageKey] = kdfChain(state.CKs);
  const header = sealed(state.HKs, state.AD, encodeHeader(state.DHs.public, state.PN, state.Ns), state.random);
  const body = sealed(messageKey, Buffer.concat([state.AD, header]), plaintext, state.random);
  state.CKs = chainKey;
  state.Ns += 1;
  return { header, body };
};

const maxSkip = 256;
let keysStoredAtADhStep = 0;

const skipTo = (state, until) => {
  if (!state.CKr) return;
  if (until > state.Nr && until - state.Nr > maxSkip) throw new Error("too_many_skipped");
  while (state.Nr < until) {
    const [chainKey, messageKey] = kdfChain(state.CKr);
    state.skipped.push({ hk: state.HKr, dh: state.DHr, n: state.Nr, mk: messageKey });
    state.CKr = chainKey;
    state.Nr += 1;
  }
};

const decrypt = (state, message) => {
  const bodyData = Buffer.concat([state.AD, message.header]);
  for (const entry of state.skipped) {
    const plain = opened(entry.hk, state.AD, message.header);
    if (!plain) continue;
    const header = decodeHeader(plain);
    const found = state.skipped.findIndex((candidate) => candidate.hk.equals(entry.hk) && candidate.dh.equals(header.dh) && candidate.n === header.n);
    if (found < 0) break;
    const [{ mk }] = state.skipped.splice(found, 1);
    return opened(mk, bodyData, message.body);
  }
  let plain = state.HKr ? opened(state.HKr, state.AD, message.header) : null;
  let header;
  if (plain) {
    header = decodeHeader(plain);
    if (!header.dh.equals(state.DHr)) throw new Error("unknown_header");
    if (header.n < state.Nr) throw new Error("old_or_duplicate");
  } else {
    plain = opened(state.NHKr, state.AD, message.header);
    if (!plain) throw new Error("unknown_header");
    header = decodeHeader(plain);
    if (header.n > maxSkip) throw new Error("too_many_skipped");
    if (state.CKr && header.pn > state.Nr) keysStoredAtADhStep += header.pn - state.Nr;
    skipTo(state, header.pn);
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.HKs = state.NHKs;
    state.HKr = state.NHKr;
    state.DHr = header.dh;
    [state.RK, state.CKr, state.NHKr] = kdfRoot(state.RK, dh(state.DHs.secret, state.DHr));
    state.DHs = keyPair(state.random(32));
    [state.RK, state.CKs, state.NHKs] = kdfRoot(state.RK, dh(state.DHs.secret, state.DHr));
  }
  skipTo(state, header.n);
  const [chainKey, messageKey] = kdfChain(state.CKr);
  state.CKr = chainKey;
  state.Nr += 1;
  return opened(messageKey, bodyData, message.body);
};

const handshake = JSON.parse(readFileSync(handshakeFile, "utf8")).cases[0];
const sessionKeys = {
  root: bytes(handshake.root_key),
  headerAlice: bytes(handshake.header_key_alice),
  nextHeaderBob: bytes(handshake.next_header_key_bob),
  associatedData: bytes(handshake.associated_data),
};
const signedPrekey = keyPair(bytes(handshake.signed_prekey.secret));

const alice = { random: randomStream("LUME ratchet vector alice"), AD: sessionKeys.associatedData, skipped: [], Ns: 0, Nr: 0, PN: 0 };
alice.DHs = keyPair(alice.random(32));
alice.DHr = signedPrekey.public;
[alice.RK, alice.CKs, alice.NHKs] = kdfRoot(sessionKeys.root, dh(alice.DHs.secret, alice.DHr));
alice.HKs = sessionKeys.headerAlice;
alice.NHKr = sessionKeys.nextHeaderBob;

const bob = {
  random: randomStream("LUME ratchet vector bob"), AD: sessionKeys.associatedData, skipped: [], Ns: 0, Nr: 0, PN: 0,
  DHs: signedPrekey, RK: sessionKeys.root, NHKs: sessionKeys.nextHeaderBob, NHKr: sessionKeys.headerAlice,
};

const parties = { alice, bob };
const messages = {};
const script = [
  ["send", "alice", "A0"], ["send", "alice", "A1"], ["send", "alice", "A2"],
  ["receive", "bob", "A0"], ["receive", "bob", "A2"],
  ["send", "bob", "B0"], ["send", "bob", "B1"],
  ["receive", "alice", "B1"], ["receive", "alice", "B0"],
  ["send", "alice", "A3"],
  ["receive", "bob", "A1"], ["receive", "bob", "A3"],
  ["send", "bob", "B2"], ["receive", "alice", "B2"],
  ["send", "alice", "A4"], ["send", "alice", "A5"],
  ["receive", "bob", "A4"],
  ["send", "bob", "B3"], ["receive", "alice", "B3"],
  ["send", "alice", "A6"],
  ["receive", "bob", "A6"], ["receive", "bob", "A5"],
  ["replay", "bob", "A6"], ["replay", "bob", "A5"],
];

const refusal = (party, id) => {
  try {
    decrypt(parties[party], messages[id]);
  } catch (error) {
    return error.message;
  }
  throw new Error(`${party} opened ${id} a second time`);
};

const steps = script.map(([action, party, id]) => {
  if (action === "send") {
    const plaintext = Buffer.from(`message ${id} from ${party}`, "ascii");
    messages[id] = encrypt(parties[party], plaintext);
    return { action, party, id, plaintext: hex(plaintext), encrypted_header: hex(messages[id].header), body: hex(messages[id].body) };
  }
  if (action === "replay") return { action, party, id, error: refusal(party, id) };
  const plaintext = decrypt(parties[party], messages[id]);
  if (!plaintext) throw new Error(`${party} could not open ${id}`);
  return { action, party, id, plaintext: hex(plaintext) };
});

if (keysStoredAtADhStep === 0) throw new Error("no step stores skipped keys at a DH step");

const document = {
  description: "LUME Double Ratchet with header encryption, CRYPTO.md section 6, computed with Node.js crypto (OpenSSL) and a JavaScript HChaCha20; the session keys are case 0 of handshake.json, and every random draw comes from SHA-256(seed || u64 counter) in the order the steps make them; a replay step must be refused with the error it names and change nothing",
  generator: "core/tools/generate_ratchet_vectors.mjs",
  random_seeds: { alice: "LUME ratchet vector alice", bob: "LUME ratchet vector bob" },
  steps,
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log(`wrote ${steps.length} ratchet steps`);
