// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, sign, verify } from "node:crypto";
import { join } from "node:path";
import { aeadDecrypt, aeadEncrypt, checkAgainstWycheproof } from "./xchacha20poly1305.mjs";

const [identityFile, handshakeFile, directoryFile, wycheproofDir, outputFile] = process.argv.slice(2);

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
const sha256 = (...parts) => parts.reduce((hash, part) => hash.update(part), createHash("sha256")).digest();
const seedOf = (name) => sha256(Buffer.from(`LUME card vector ${name}`, "ascii"));

checkAgainstWycheproof(wycheproofDir);

const ed25519Private = (seed) => createPrivateKey({ key: Buffer.concat([bytes("302e020100300506032b657004220420"), seed]), format: "der", type: "pkcs8" });
const ed25519Public = (key) => createPublicKey({ key: Buffer.concat([bytes("302a300506032b6570032100"), key]), format: "der", type: "spki" });
const ed25519PublicOf = (seed) => createPublicKey(ed25519Private(seed)).export({ format: "der", type: "spki" }).subarray(-32);
const signed = (seed, message) => {
  const signature = sign(null, message, ed25519Private(seed));
  if (!verify(null, message, ed25519Public(ed25519PublicOf(seed)), signature)) throw new Error("OpenSSL refused its own signature");
  return signature;
};
const x25519Private = (secret) => createPrivateKey({ key: Buffer.concat([bytes("302e020100300506032b656e04220420"), secret]), format: "der", type: "pkcs8" });
const x25519PublicOf = (secret) => createPublicKey(x25519Private(secret)).export({ format: "der", type: "spki" }).subarray(-32);
const dh = (secret, peer) => diffieHellman({
  privateKey: x25519Private(secret),
  publicKey: createPublicKey({ key: Buffer.concat([bytes("302a300506032b656e032100"), peer]), format: "der", type: "spki" }),
});

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

const buckets = [2048, 4096, 8192, 16384, 32768, 65536, 69632];
const pad = (message) => {
  const out = Buffer.alloc(buckets.find((size) => message.length < size));
  message.copy(out);
  out[message.length] = 0x80;
  return out;
};
const unpad = (padded) => {
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end -= 1;
  if (end < 0 || padded[end] !== 0x80) return null;
  return padded.subarray(0, end);
};

const handshake = JSON.parse(readFileSync(handshakeFile, "utf8")).cases[0];
const identities = JSON.parse(readFileSync(identityFile, "utf8")).cases;
const bob = identities[handshake.bob];
const alice = identities[handshake.alice];
const directory = JSON.parse(readFileSync(directoryFile, "utf8"));
const kem = JSON.parse(readFileSync(join(wycheproofDir, "mlkem_768_test.json"), "utf8")).testGroups
  .flatMap((group) => group.tests).find((test) => test.tcId === handshake.kem_prekey.wycheproof_tcId);
if (!kem || !kem.ek) throw new Error("the ML-KEM key of handshake.json is missing from Wycheproof");

const now = handshake.now;
const day = 86400;
const generation = handshake.generation;
const createdAt = handshake.created_at;

const prekeyMessage = (kind, id, created, gen, publicKey) =>
  Buffer.concat([label("prekey"), u8(kind), u32(id), u64(created), u32(gen), lengthPrefixed(publicKey)]);
const checkPrekey = (signer, kind, id, publicKey, signature) => {
  if (!verify(null, prekeyMessage(kind, id, createdAt, generation, publicKey), ed25519Public(signer), signature)) {
    throw new Error(`a prekey of kind ${kind} in handshake.json does not verify`);
  }
};
const spk = { kind: 1, id: handshake.signed_prekey.id, key: bytes(handshake.signed_prekey.public), signature: bytes(handshake.signed_prekey.signature) };
const pqspk = { kind: 2, id: handshake.kem_prekey.id, key: bytes(kem.ek), signature: bytes(handshake.kem_prekey.signature) };
const ssk = { kind: 4, id: handshake.seal_key.id, key: bytes(handshake.seal_key.public), signature: bytes(handshake.seal_key.signature) };
if (handshake.kem_prekey.kind !== 2) throw new Error("case 0 of handshake.json must use the last-resort KEM key");
for (const key of [spk, pqspk, ssk]) checkPrekey(bytes(bob.signing_key), key.kind, key.id, key.key, key.signature);
const encodePrekeyX = (key) => Buffer.concat([u8(key.kind), u32(key.id), u64(createdAt), key.key, u8(1), key.signature]);
const encodePrekeyKem = (key) => Buffer.concat([u8(key.kind), u32(key.id), u64(createdAt), key.key, key.signature]);

const today = now - (now % day);
const certificate = {
  key_id: directory.directory_keys[0].key_id,
  username: Buffer.from("bob", "utf8"),
  account_id: seedOf("account").subarray(0, 16),
  generation: 1,
  issued_at: today,
  expires_at: today + 30 * day,
};
const unsignedCertificate = Buffer.concat([
  u32(certificate.key_id), lengthPrefixed(certificate.username), certificate.account_id, bytes(bob.signing_key),
  bytes(bob.exchange_key), u32(certificate.generation), u64(certificate.issued_at), u64(certificate.expires_at),
]);
const certificateSignature = signed(bytes(directory.directory_keys[0].seed), Buffer.concat([label("certificate"), unsignedCertificate]));
const encodedCertificate = Buffer.concat([unsignedCertificate, certificateSignature]);

const skew = 5 * 60;
const cardLifetime = 7 * day;
const keyUsableFor = 9 * day;
const token = seedOf("token");
const groupId = seedOf("group").subarray(0, 16);
const cardMessageFor = (recipient, expires) => Buffer.concat([label("card"), recipient, groupId, sha256(token), u64(expires)]);
const cardFor = (expires) => {
  const signature = signed(bytes(bob.signing_seed), cardMessageFor(bytes(alice.signing_key), expires));
  const encoded = Buffer.concat([
    encodedCertificate, bytes(bob.binding), u32(generation), encodePrekeyX(spk), encodePrekeyKem(pqspk), encodePrekeyX(ssk),
    token, groupId, u64(expires), signature,
  ]);
  return { expiresAt: expires, signature, encoded };
};
const expiresAt = Math.min(now + cardLifetime, createdAt + keyUsableFor);
const vectorCard = cardFor(expiresAt);
const cardMessage = cardMessageFor(bytes(alice.signing_key), expiresAt);
const cardSignature = vectorCard.signature;
const encodedCard = vectorCard.encoded;

const aliceSeal = { id: 0x00c0ffee, created_at: now - 20 * day, secret: seedOf("alice seal key") };
aliceSeal.public = x25519PublicOf(aliceSeal.secret);
aliceSeal.signature = signed(bytes(alice.signing_seed), prekeyMessage(4, aliceSeal.id, aliceSeal.created_at, generation, aliceSeal.public));

const associatedData = (id, ephemeral, recipient) => Buffer.concat([label("card/ad"), u8(1), u32(id), ephemeral, recipient]);
const envelopeKey = (shared, ephemeral, recipient) => Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeral, recipient]), label("card/key"), 32));
const randomSeed = "LUME card vector seal";
const random = randomStream(randomSeed);
const ephemeralSecret = random(32);
const ephemeral = x25519PublicOf(ephemeralSecret);
const nonce = random(24);
const box = aeadEncrypt(envelopeKey(dh(ephemeralSecret, aliceSeal.public), ephemeral, aliceSeal.public), nonce,
  associatedData(aliceSeal.id, ephemeral, aliceSeal.public), pad(encodedCard));
const envelope = Buffer.concat([u8(1), u32(aliceSeal.id), ephemeral, nonce, u32(box.length), box]);

const opened = aeadDecrypt(envelopeKey(dh(aliceSeal.secret, ephemeral), ephemeral, aliceSeal.public), nonce,
  associatedData(aliceSeal.id, ephemeral, aliceSeal.public), box);
if (!opened || !unpad(opened).equals(encodedCard)) throw new Error("the sealed card does not open to the card");
const asSeal = aeadDecrypt(Buffer.from(hkdfSync("sha256", dh(aliceSeal.secret, ephemeral), Buffer.concat([ephemeral, aliceSeal.public]), label("seal/key"), 32)),
  nonce, Buffer.concat([label("seal/ad"), u8(1), u32(aliceSeal.id), ephemeral, aliceSeal.public]), box);
if (asSeal) throw new Error("a sealed card must not open as a sealed message");

const expected = {
  card: vectorCard, recipient: bytes(alice.signing_key), group_id: groupId,
  member_ik_sig: bytes(bob.signing_key), member_ik_dh: bytes(bob.exchange_key), now,
};
const keyUsableAt = (at) => createdAt <= at + skew && at - createdAt <= keyUsableFor;
const refuse = (check) => {
  const { card } = check;
  if (check.now >= card.expiresAt) return "expired";
  if (card.expiresAt - check.now > cardLifetime + skew) return "bad_lifetime";
  if (!check.group_id.equals(groupId)) return "wrong_group";
  if (!check.member_ik_sig.equals(bytes(bob.signing_key)) || !check.member_ik_dh.equals(bytes(bob.exchange_key))
    || check.member_ik_sig.equals(check.recipient)) return "wrong_member";
  if (!verify(null, cardMessageFor(check.recipient, card.expiresAt), ed25519Public(bytes(bob.signing_key)), card.signature)) {
    return "invalid_signature";
  }
  if (!keyUsableAt(check.now)) return "invalid_keys";
  if (card.expiresAt - createdAt > keyUsableFor) return "outlives_its_keys";
  return null;
};
if (refuse(expected) !== null) throw new Error("the vector card must be accepted by its own recipient");
const outliving = cardFor(createdAt + keyUsableFor + 1);
const outlivingCheckedAt = outliving.expiresAt - cardLifetime;
if (refuse({ ...expected, card: outliving, now: outlivingCheckedAt }) !== "outlives_its_keys") {
  throw new Error("the outliving card must fail only the rule that a card may not outlive its keys");
}
const stranger = identities[0];
const checkRefusals = [
  ["another_group", "the card is offered as an introduction in another group", { ...expected, group_id: seedOf("other group").subarray(0, 16) }],
  ["another_member", "the card is offered as coming from another member",
    { ...expected, member_ik_sig: bytes(stranger.signing_key), member_ik_dh: bytes(stranger.exchange_key) }],
  ["another_exchange_key", "the membership update names the member's signing key with another exchange key",
    { ...expected, member_ik_dh: bytes(stranger.exchange_key) }],
  ["another_recipient", "the card is shown to someone it was not made for", { ...expected, recipient: bytes(stranger.signing_key) }],
  ["expired", "the card is checked at the moment it expires", { ...expected, now: expiresAt }],
  ["too_far_ahead", "the card is checked when it still has more than 7 days and the clock skew to live",
    { ...expected, now: expiresAt - cardLifetime - skew - 1 }],
  ["outlives_its_keys", "a card signed to expire one second after its keys stop being usable",
    { ...expected, card: outliving, now: outlivingCheckedAt }],
].map(([name, description, check]) => {
  const error = refuse(check);
  if (!error) throw new Error(`${name} must be refused`);
  return {
    name, description, ...(check.card === vectorCard ? {} : { card: hex(check.card.encoded) }),
    recipient: hex(check.recipient), group_id: hex(check.group_id), member_ik_sig: hex(check.member_ik_sig),
    member_ik_dh: hex(check.member_ik_dh), now: check.now, error,
  };
});

const sealedPlaintext = (plaintext, seed) => {
  const stream = randomStream(seed);
  const secret = stream(32);
  const publicKey = x25519PublicOf(secret);
  const iv = stream(24);
  const sealedBox = aeadEncrypt(envelopeKey(dh(secret, aliceSeal.public), publicKey, aliceSeal.public), iv,
    associatedData(aliceSeal.id, publicKey, aliceSeal.public), plaintext);
  return Buffer.concat([u8(1), u32(aliceSeal.id), publicKey, iv, u32(sealedBox.length), sealedBox]);
};
const withoutMarker = Buffer.concat([encodedCard, Buffer.alloc(2048 - encodedCard.length)]);
if (unpad(withoutMarker) !== null) throw new Error("a card followed only by zeros must not unpad");
const envelopeRefusals = [
  ["padding_without_marker", "the card is followed only by zero bytes", withoutMarker, "authentication_failed"],
  ["trailing_byte", "correctly padded, but one byte follows the card", pad(Buffer.concat([encodedCard, u8(0)])), "malformed"],
].map(([name, description, plaintext, error]) => ({ name, description, envelope: hex(sealedPlaintext(plaintext, `LUME card vector ${name}`)), error }));

const document = {
  description: "LUME introduction card, CRYPTO.md section 11.2, computed with Node.js crypto (OpenSSL) and the shared XChaCha20-Poly1305 checked against Wycheproof: Bob's card for Alice (cases 4 and 3 of identity.json) with Bob's keys from case 0 of handshake.json, the ML-KEM key being the Wycheproof mlkem_768_test.json case it names, and a certificate signed by directory key 1 of directory.json; the card is sealed under card/key and card/ad to a seal key of Alice that is 20 days old, inside the 30 days a card seal allows; seeds are SHA-256(\"LUME card vector \" || name); a check refusal must be refused with the error it names when the card, or the card it carries, is checked with that recipient, group, member pair and time, and an envelope refusal when it is opened",
  generator: "core/tools/generate_card_vectors.mjs",
  now,
  producer: handshake.bob,
  recipient: handshake.alice,
  card: {
    certificate: hex(encodedCertificate),
    token: hex(token),
    group_id: hex(groupId),
    expires_at: expiresAt,
    message: hex(cardMessage),
    signature: hex(cardSignature),
    encoded: hex(encodedCard),
  },
  recipient_seal_key: {
    id: aliceSeal.id,
    created_at: aliceSeal.created_at,
    generation,
    secret: hex(aliceSeal.secret),
    public: hex(aliceSeal.public),
    signature: hex(aliceSeal.signature),
  },
  random_seed: randomSeed,
  envelope: hex(envelope),
  check_refusals: checkRefusals,
  envelope_refusals: envelopeRefusals,
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log("wrote the card vectors");
