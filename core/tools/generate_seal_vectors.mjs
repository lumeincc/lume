// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, verify } from "node:crypto";
import { aeadDecrypt, aeadEncrypt, checkAgainstWycheproof, decryptIgnoringTheTag } from "./xchacha20poly1305.mjs";

const [identityFile, handshakeFile, ratchetFile, wycheproofDir, outputFile] = process.argv.slice(2);

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
const lengthPrefixed = (value) => Buffer.concat([u32(value.length), value]);
const label = (name) => lengthPrefixed(Buffer.from(`LUME/v1/${name}`, "ascii"));

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
const ed25519Public = (key) => createPublicKey({ key: Buffer.concat([bytes("302a300506032b6570032100"), key]), format: "der", type: "spki" });

const fieldPrime = (1n << 255n) - 19n;
const fromLittleEndian = (value) => BigInt(`0x${Buffer.from(value).reverse().toString("hex")}`);
const toLittleEndian = (value) => Buffer.from(value.toString(16).padStart(64, "0"), "hex").reverse();
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
const unpadLeniently = (padded) => {
  let end = padded.length;
  while (end > 0 && padded[end - 1] === 0) end -= 1;
  if (end > 0 && padded[end - 1] === 0x80) end -= 1;
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
const bob = JSON.parse(readFileSync(identityFile, "utf8")).cases[handshake.bob];
const sealKey = {
  id: handshake.seal_key.id,
  createdAt: handshake.created_at,
  generation: handshake.generation,
  signer: bytes(bob.signing_key),
  signature: bytes(handshake.seal_key.signature),
  ...keyPair(bytes(handshake.seal_key.secret)),
};
if (!sealKey.public.equals(bytes(handshake.seal_key.public))) throw new Error("the seal key of handshake.json does not match its secret");
const prekeyMessage = Buffer.concat([label("prekey"), u8(4), u32(sealKey.id), u64(sealKey.createdAt), u32(sealKey.generation), lengthPrefixed(sealKey.public)]);
if (!verify(null, prekeyMessage, ed25519Public(sealKey.signer), sealKey.signature)) throw new Error("the seal key's signature does not verify under Bob's identity");

const sealWith = (plaintext, { random, id = sealKey.id, ephemeral, shared }) => {
  const nonce = random(24);
  const key = envelopeKey(shared, ephemeral, sealKey.public);
  return encodeSeal(id, ephemeral, nonce, aeadEncrypt(key, nonce, associatedData(id, ephemeral, sealKey.public), plaintext));
};
const sealPlaintext = (plaintext, random, id = sealKey.id) => {
  const ephemeral = keyPair(random(32));
  return sealWith(plaintext, { random, id, ephemeral: ephemeral.public, shared: dh(ephemeral.secret, sealKey.public) });
};

const decodeInner = (data, { trailingAllowed = false } = {}) => {
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
  if (at !== data.length && !trailingAllowed) throw new Error("trailing_bytes");
  return { sender, initial, bytes: data.subarray(0, at) };
};

const open = (envelope, disabled = new Set()) => {
  const on = (check) => !disabled.has(check);
  const seal = decodeSeal(envelope);
  if (on("key_id") && seal.id !== sealKey.id) return { error: "wrong_key", check: "key_id" };
  if (on("canonical") && !isCanonical(seal.ephemeral)) return { error: "weak_key", check: "canonical" };
  let shared;
  try {
    shared = dh(sealKey.secret, seal.ephemeral);
  } catch {
    shared = Buffer.alloc(32);
  }
  if (on("low_order") && shared.every((byte) => byte === 0)) return { error: "weak_key", check: "low_order" };
  const key = envelopeKey(shared, seal.ephemeral, sealKey.public);
  const decrypt = on("aead") ? aeadDecrypt : decryptIgnoringTheTag;
  const padded = decrypt(key, seal.nonce, associatedData(sealKey.id, seal.ephemeral, sealKey.public), seal.box);
  if (!padded) return { error: "authentication_failed", check: "aead" };
  const inner = on("padding") ? unpad(padded) : unpadLeniently(padded);
  if (!inner) return { error: "authentication_failed", check: "padding" };
  let decoded;
  try {
    decoded = decodeInner(inner, { trailingAllowed: !on("decode") });
  } catch {
    return { error: "malformed", check: "decode" };
  }
  if (on("sender") && decoded.initial && !decoded.initial.subarray(0, 32).equals(decoded.sender)) return { error: "malformed", check: "sender" };
  return { inner: decoded.bytes };
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

const withLastByteChanged = (value) => Buffer.concat([value.subarray(0, value.length - 1), u8(value[value.length - 1] ^ 0x01)]);
const notTheSender = Buffer.concat([u8(alice[0] ^ 0x01), alice.subarray(1)]);
const unreducedBasePoint = toLittleEndian(fieldPrime + 9n);

const refusals = [
  ["wrong_key_id", "sealed correctly, but under seal key id + 1", "key_id", "wrong_key",
    (random) => sealPlaintext(pad(laterMessage), random, sealKey.id + 1)],
  ["ephemeral_key_with_top_bit", "a valid ephemeral key with bit 255 set, sealed consistently with those bytes; X25519 ignores the bit, so only the canonical check refuses it", "canonical", "weak_key",
    (random) => {
      const ephemeral = keyPair(random(32));
      const flagged = Buffer.from(ephemeral.public);
      flagged[31] |= 0x80;
      return sealWith(pad(laterMessage), { random, ephemeral: flagged, shared: dh(ephemeral.secret, sealKey.public) });
    }],
  ["unreduced_ephemeral_key", "the ephemeral key is p + 9, the base point left unreduced, sealed consistently; the shared secret is then the seal key's own public key, so only the canonical check refuses it", "canonical", "weak_key",
    (random) => sealWith(pad(laterMessage), { random, ephemeral: unreducedBasePoint, shared: sealKey.public })],
  ["low_order_ephemeral_key", "the ephemeral key is 0, sealed with the all-zero shared secret it gives, so only the low-order check refuses it", "low_order", "weak_key",
    (random) => sealWith(pad(laterMessage), { random, ephemeral: Buffer.alloc(32), shared: Buffer.alloc(32) })],
  ["forged_box", "the last byte of the box, part of the tag, is changed", "aead", "authentication_failed",
    (random) => withLastByteChanged(sealPlaintext(pad(laterMessage), random))],
  ["padding_in_a_larger_bucket", "the inner fits the 2048 bucket but is padded to 4096", "padding", "authentication_failed",
    (random) => sealPlaintext(Buffer.concat([laterMessage, u8(0x80), Buffer.alloc(4096 - laterMessage.length - 1)]), random)],
  ["padding_without_marker", "the inner is followed only by zero bytes", "padding", "authentication_failed",
    (random) => sealPlaintext(Buffer.concat([laterMessage, Buffer.alloc(2048 - laterMessage.length)]), random)],
  ["byte_after_the_marker", "the last byte of the padding is 0x01", "padding", "authentication_failed",
    (random) => sealPlaintext(withLastByteChanged(pad(laterMessage)), random)],
  ["empty_plaintext", "the box authenticates an empty plaintext", "padding", "authentication_failed",
    (random) => sealPlaintext(Buffer.alloc(0), random)],
  ["inner_with_a_trailing_byte", "correctly padded, but the inner has one byte after its last field", "decode", "malformed",
    (random) => sealPlaintext(pad(Buffer.concat([laterMessage, u8(0)])), random)],
  ["sender_is_not_the_initiator", "the sender hint differs from ik_sig of the initial header in one bit", "sender", "malformed",
    (random) => sealPlaintext(pad(encodeInner(notTheSender, initialHeader, messageOf("A0"))), random)],
].map(([name, description, check, error, make]) => {
  const envelope = make(randomStream(seedOf(name)));
  const opened = open(envelope);
  if (opened.error !== error || opened.check !== check) {
    throw new Error(`${name} is refused by ${opened.check ?? "nothing"} with ${opened.error ?? "nothing"}, not by ${check} with ${error}`);
  }
  const without = open(envelope, new Set([check]));
  if (without.error === error) throw new Error(`${name} is still refused with ${error} when ${check} is skipped, so it does not test ${check}`);
  return { name, description, check, envelope: hex(envelope), error };
});

const document = {
  description: "LUME sealed sender, CRYPTO.md sections 7.3 and 8, computed with Node.js crypto (OpenSSL) and a JavaScript HChaCha20 checked against every Wycheproof XChaCha20-Poly1305 case; the seal key is the one of case 0 of handshake.json, signed by its Bob; each envelope draws the ephemeral secret (32 bytes) and then the nonce (24 bytes) from SHA-256(random_seed || u64 counter); a refusal must be refused with the error it names, and the generator has checked that skipping the check it names would change the outcome",
  generator: "core/tools/generate_seal_vectors.mjs",
  now: handshake.now,
  seal_key: {
    id: sealKey.id,
    created_at: sealKey.createdAt,
    generation: sealKey.generation,
    signer: hex(sealKey.signer),
    signature: hex(sealKey.signature),
    secret: hex(sealKey.secret),
    public: hex(sealKey.public),
  },
  cases,
  refusals,
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log(`wrote ${cases.length} seal cases and ${refusals.length} refusals`);
