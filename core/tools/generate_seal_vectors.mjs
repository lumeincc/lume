// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from "node:crypto";
import { join } from "node:path";

const [handshakeFile, ratchetFile, wycheproofDir, outputFile] = process.argv.slice(2);

const bytes = (text) => Buffer.from(text, "hex");
const hex = (value) => Buffer.from(value).toString("hex");
const u8 = (value) => Buffer.from([value]);
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

const rotl = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;

const hchacha20 = (key, nonce) => {
  const state = new Uint32Array(16);
  state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let index = 0; index < 8; index += 1) state[4 + index] = key.readUInt32LE(4 * index);
  for (let index = 0; index < 4; index += 1) state[12 + index] = nonce.readUInt32LE(4 * index);
  const quarter = (a, b, c, d) => {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl(state[b] ^ state[c], 7);
  };
  for (let round = 0; round < 10; round += 1) {
    quarter(0, 4, 8, 12);
    quarter(1, 5, 9, 13);
    quarter(2, 6, 10, 14);
    quarter(3, 7, 11, 15);
    quarter(0, 5, 10, 15);
    quarter(1, 6, 11, 12);
    quarter(2, 7, 8, 13);
    quarter(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((word, index) => out.writeUInt32LE(state[word], 4 * index));
  return out;
};

const chachaParameters = (key, nonce) => [hchacha20(key, nonce.subarray(0, 16)), Buffer.concat([Buffer.alloc(4), nonce.subarray(16)])];

const aeadEncrypt = (key, nonce, associatedData, plaintext) => {
  const [subkey, iv] = chachaParameters(key, nonce);
  const cipher = createCipheriv("chacha20-poly1305", subkey, iv, { authTagLength: 16 });
  cipher.setAAD(associatedData, { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
};

const aeadDecrypt = (key, nonce, associatedData, ciphertext) => {
  if (ciphertext.length < 16) return null;
  const [subkey, iv] = chachaParameters(key, nonce);
  const decipher = createDecipheriv("chacha20-poly1305", subkey, iv, { authTagLength: 16 });
  decipher.setAAD(associatedData, { plaintextLength: ciphertext.length - 16 });
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  try {
    return Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - 16)), decipher.final()]);
  } catch {
    return null;
  }
};

const xchachaCheck = JSON.parse(readFileSync(join(wycheproofDir, "xchacha20_poly1305_test.json"), "utf8"))
  .testGroups.flatMap((group) => group.tests).find((test) => test.tcId === 1);
const checkCiphertext = aeadEncrypt(bytes(xchachaCheck.key), bytes(xchachaCheck.iv), bytes(xchachaCheck.aad), bytes(xchachaCheck.msg));
if (hex(checkCiphertext) !== xchachaCheck.ct + xchachaCheck.tag) throw new Error("the XChaCha20-Poly1305 construction disagrees with Wycheproof");

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

const fieldPrime = (1n << 255n) - 19n;
const fromLittleEndian = (value) => BigInt(`0x${Buffer.from(value).reverse().toString("hex")}`);
const isCanonical = (key) => fromLittleEndian(key) < fieldPrime;

const buckets = [2048, 4096, 8192, 16384, 32768, 65536, 69632];
const bucketFor = (length) => buckets.find((size) => length < size);
const pad = (message) => {
  const out = Buffer.alloc(bucketFor(message.length));
  message.copy(out);
  out[message.length] = 0x80;
  return out;
};
const unpad = (padded) => {
  if (!buckets.includes(padded.length)) return null;
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end -= 1;
  if (end < 0 || padded[end] !== 0x80 || bucketFor(end) !== padded.length) return null;
  return padded.subarray(0, end);
};

const associatedData = (id, ephemeral, recipient) => Buffer.concat([label("seal/ad"), u8(1), u32(id), ephemeral, recipient]);
const envelopeKey = (shared, ephemeral, recipient) => Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeral, recipient]), label("seal/key"), 32));
const encodeSeal = (id, ephemeral, nonce, box) => Buffer.concat([u8(1), u32(id), ephemeral, nonce, u32(box.length), box]);
const decodeSeal = (envelope) => {
  if (envelope[0] !== 1 || envelope.length !== 65 + envelope.readUInt32BE(61)) throw new Error("not a version 1 seal");
  return { id: envelope.readUInt32BE(1), ephemeral: envelope.subarray(5, 37), nonce: envelope.subarray(37, 61), box: envelope.subarray(65) };
};

const handshake = JSON.parse(readFileSync(handshakeFile, "utf8")).cases[0];
const sealKey = { id: handshake.seal_key.id, ...keyPair(bytes(handshake.seal_key.secret)) };
if (!sealKey.public.equals(bytes(handshake.seal_key.public))) throw new Error("the seal key of handshake.json does not match its secret");

const sealPlaintext = (plaintext, random, id = sealKey.id) => {
  const ephemeral = keyPair(random(32));
  const nonce = random(24);
  const key = envelopeKey(dh(ephemeral.secret, sealKey.public), ephemeral.public, sealKey.public);
  return encodeSeal(id, ephemeral.public, nonce, aeadEncrypt(key, nonce, associatedData(id, ephemeral.public, sealKey.public), plaintext));
};

const decodeInner = (data) => {
  let at = 0;
  const take = (size) => {
    if (at + size > data.length) throw new Error("truncated");
    at += size;
    return data.subarray(at - size, at);
  };
  const present = () => {
    const [flag] = take(1);
    if (flag > 1) throw new Error("non_canonical");
    return flag === 1;
  };
  const sender = take(32);
  let initial = null;
  if (present()) {
    const start = at;
    take(32 + 32 + 64 + 32 + 1088 + 4);
    const [kind] = take(1);
    if (kind !== 2 && kind !== 3) throw new Error("invalid_value");
    take(4);
    if (present()) take(4);
    initial = data.subarray(start, at);
  }
  take(80);
  const length = take(4).readUInt32BE(0);
  if (length > 69000) throw new Error("over_bound");
  take(length);
  if (at !== data.length) throw new Error("trailing_bytes");
  return { sender, initial };
};

const open = (envelope) => {
  const seal = decodeSeal(envelope);
  if (seal.id !== sealKey.id) return { error: "wrong_key" };
  if (!isCanonical(seal.ephemeral)) return { error: "weak_key" };
  let shared;
  try {
    shared = dh(sealKey.secret, seal.ephemeral);
  } catch {
    return { error: "weak_key" };
  }
  if (shared.every((byte) => byte === 0)) return { error: "weak_key" };
  const padded = aeadDecrypt(envelopeKey(shared, seal.ephemeral, sealKey.public), seal.nonce, associatedData(seal.id, seal.ephemeral, sealKey.public), seal.box);
  if (!padded) return { error: "authentication_failed" };
  const inner = unpad(padded);
  if (!inner) return { error: "authentication_failed" };
  try {
    const decoded = decodeInner(inner);
    if (decoded.initial && !decoded.initial.subarray(0, 32).equals(decoded.sender)) return { error: "malformed" };
  } catch {
    return { error: "malformed" };
  }
  return { inner };
};

const sent = Object.fromEntries(JSON.parse(readFileSync(ratchetFile, "utf8")).steps
  .filter((step) => step.action === "send").map((step) => [step.id, step]));
const ratchetMessage = (encryptedHeader, body) => Buffer.concat([encryptedHeader, u32(body.length), body]);
const messageOf = (id) => ratchetMessage(bytes(sent[id].encrypted_header), bytes(sent[id].body));
const encodeInner = (sender, initial, message) => Buffer.concat([sender, initial ? Buffer.concat([u8(1), initial]) : u8(0), message]);

const initialHeader = bytes(handshake.initial_header);
const alice = initialHeader.subarray(0, 32);
const firstMessage = encodeInner(alice, initialHeader, messageOf("A0"));
const laterMessage = encodeInner(alice, null, messageOf("A3"));
const fullBucket = encodeInner(alice, null, ratchetMessage(bytes(sent.A4.encrypted_header), randomStream("LUME seal vector body")(3978)));
if (fullBucket.length !== 4095) throw new Error("the full-bucket case must be one byte short of 4096");

const seedOf = (name) => `LUME seal vector ${name}`;

const cases = [
  ["first_message", "Alice's first message: the initial header of case 0 of handshake.json and step A0 of ratchet.json", firstMessage],
  ["later_message", "a message without an initial header: step A3 of ratchet.json", laterMessage],
  ["full_bucket", "a 4095-byte inner, so the marker is the last byte of the 4096 bucket; its 3978-byte body comes from SHA-256(\"LUME seal vector body\" || u64 counter)", fullBucket],
].map(([name, description, inner]) => {
  const envelope = sealPlaintext(pad(inner), randomStream(seedOf(name)));
  const opened = open(envelope);
  if (!opened.inner || !opened.inner.equals(inner)) throw new Error(`${name} does not open to its inner`);
  return { name, description, random_seed: seedOf(name), inner: hex(inner), padded_size: pad(inner).length, envelope: hex(envelope) };
});

const sealedNormally = (name) => sealPlaintext(pad(laterMessage), randomStream(seedOf(name)));
const withEphemeralKey = (envelope, key) => Buffer.concat([envelope.subarray(0, 5), key, envelope.subarray(37)]);
const withLastByteChanged = (value) => Buffer.concat([value.subarray(0, value.length - 1), u8(value[value.length - 1] ^ 0x01)]);
const notTheSender = Buffer.concat([u8(alice[0] ^ 0x01), alice.subarray(1)]);

const refusals = [
  ["wrong_key_id", "sealed correctly, but under seal key id + 1", "wrong_key",
    (name) => sealPlaintext(pad(laterMessage), randomStream(seedOf(name)), sealKey.id + 1)],
  ["non_canonical_ephemeral_key", "the ephemeral key is p itself, an unreduced encoding", "weak_key",
    (name) => withEphemeralKey(sealedNormally(name), bytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))],
  ["low_order_ephemeral_key", "the ephemeral key is 0, so the shared secret is all zero", "weak_key",
    (name) => withEphemeralKey(sealedNormally(name), Buffer.alloc(32))],
  ["forged_box", "the last byte of the box is changed", "authentication_failed",
    (name) => withLastByteChanged(sealedNormally(name))],
  ["padding_in_a_larger_bucket", "the inner fits the 2048 bucket but is padded to 4096", "authentication_failed",
    (name) => sealPlaintext(Buffer.concat([laterMessage, u8(0x80), Buffer.alloc(4096 - laterMessage.length - 1)]), randomStream(seedOf(name)))],
  ["padding_without_marker", "the inner is followed only by zero bytes", "authentication_failed",
    (name) => sealPlaintext(Buffer.concat([laterMessage, Buffer.alloc(2048 - laterMessage.length)]), randomStream(seedOf(name)))],
  ["byte_after_the_marker", "the last byte of the padding is 0x01", "authentication_failed",
    (name) => sealPlaintext(withLastByteChanged(pad(laterMessage)), randomStream(seedOf(name)))],
  ["inner_with_a_trailing_byte", "correctly padded, but the inner has one byte after its last field", "malformed",
    (name) => sealPlaintext(pad(Buffer.concat([laterMessage, u8(0)])), randomStream(seedOf(name)))],
  ["sender_is_not_the_initiator", "the sender hint differs from ik_sig of the initial header in one bit", "malformed",
    (name) => sealPlaintext(pad(encodeInner(notTheSender, initialHeader, messageOf("A0"))), randomStream(seedOf(name)))],
].map(([name, description, error, make]) => {
  const envelope = make(name);
  const opened = open(envelope);
  if (opened.error !== error) throw new Error(`${name} is refused with ${opened.error ?? "nothing"}, not ${error}`);
  return { name, description, envelope: hex(envelope), error };
});

const document = {
  description: "LUME sealed sender, CRYPTO.md sections 7.3 and 8, computed with Node.js crypto (OpenSSL) and a JavaScript HChaCha20; the seal key is the one of case 0 of handshake.json; each envelope draws the ephemeral secret (32 bytes) and then the nonce (24 bytes) from SHA-256(random_seed || u64 counter); a refusal must be refused with the error it names",
  generator: "core/tools/generate_seal_vectors.mjs",
  seal_key: { id: sealKey.id, secret: hex(sealKey.secret), public: hex(sealKey.public) },
  cases,
  refusals,
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log(`wrote ${cases.length} seal cases and ${refusals.length} refusals`);
