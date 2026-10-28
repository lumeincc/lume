// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, sign } from "node:crypto";
import { join } from "node:path";

const [identityFile, wycheproofDir, outputFile] = process.argv.slice(2);
const identities = JSON.parse(readFileSync(identityFile, "utf8")).cases;
const kemTests = JSON.parse(readFileSync(join(wycheproofDir, "mlkem_768_test.json"), "utf8"))
  .testGroups.flatMap((group) => group.tests);

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const bytes = (text) => Buffer.from(text, "hex");
const sha256 = (...parts) => parts.reduce((hash, part) => hash.update(part), createHash("sha256")).digest();
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

const pkcs8 = (prefix, key) => createPrivateKey({ key: Buffer.concat([bytes(prefix), key]), format: "der", type: "pkcs8" });
const ed25519Key = (seed) => pkcs8("302e020100300506032b657004220420", seed);
const x25519Key = (secret) => pkcs8("302e020100300506032b656e04220420", secret);
const rawPublicKey = (privateKey) => createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
const x25519Public = (secret) => rawPublicKey(x25519Key(secret));
const dh = (secret, peer) =>
  diffieHellman({
    privateKey: x25519Key(secret),
    publicKey: createPublicKey({ key: Buffer.concat([bytes("302a300506032b656e032100"), peer]), format: "der", type: "spki" }),
  });

const fieldPrime = (1n << 255n) - 19n;
const fromLittleEndian = (value) => BigInt(`0x${Buffer.from(value).reverse().toString("hex")}`);
const toLittleEndian = (value) => Buffer.from(value.toString(16).padStart(64, "0"), "hex").reverse();
const power = (base, exponent) => {
  let result = 1n;
  let square = base % fieldPrime;
  for (let rest = exponent; rest > 0n; rest >>= 1n) {
    if (rest & 1n) result = (result * square) % fieldPrime;
    square = (square * square) % fieldPrime;
  }
  return result;
};
const twinOf = (publicKey) => toLittleEndian(power(fromLittleEndian(publicKey), fieldPrime - 2n));

const signPrekey = (signingSeed, kind, id, createdAt, generation, publicKey) =>
  sign(null, Buffer.concat([label("prekey"), u8(kind), u32(id), u64(createdAt), u32(generation), lengthPrefixed(publicKey)]), ed25519Key(signingSeed));

const createdAt = 1_800_000_000;
const now = createdAt + 3600;

const scenarios = [
  { name: "last-resort KEM key, no one-time key", alice: 3, bob: 4, generation: 1, kemKind: 2, kemTcId: 2, oneTime: false },
  { name: "one-time KEM key and one-time key", alice: 5, bob: 6, generation: 2, kemKind: 3, kemTcId: 3, oneTime: true },
];

const cases = scenarios.map((scenario, index) => {
  const alice = identities[scenario.alice];
  const bob = identities[scenario.bob];
  const kem = kemTests.find((test) => test.tcId === scenario.kemTcId);
  if (!kem || kem.result !== "valid" || !kem.ek) throw new Error(`unexpected ML-KEM vector ${scenario.kemTcId}`);

  const secret = (role) => sha256(Buffer.from(`LUME handshake ${role} ${index + 1}`, "ascii"));
  const spkSecret = secret("signed prekey");
  const sskSecret = secret("seal key");
  const opkSecret = secret("one-time prekey");
  const ephemeralSecret = secret("ephemeral");
  const ids = { spk: 0x1000 + index, kem: 0x2000 + index, ssk: 0x3000 + index, opk: 0x4000 + index };

  const spkPublic = x25519Public(spkSecret);
  const sskPublic = x25519Public(sskSecret);
  const opkPublic = x25519Public(opkSecret);
  const ephemeralPublic = x25519Public(ephemeralSecret);
  const kemPublic = bytes(kem.ek);
  const ciphertext = bytes(kem.c);
  const sharedSecret = bytes(kem.K);
  const bobSeed = bytes(bob.signing_seed);

  const dhs = [
    dh(bytes(alice.exchange_secret), spkPublic),
    dh(ephemeralSecret, bytes(bob.exchange_key)),
    dh(ephemeralSecret, spkPublic),
    ...(scenario.oneTime ? [dh(ephemeralSecret, opkPublic)] : []),
  ];
  const transcriptHash = sha256(
    label("transcript"),
    bytes(alice.signing_key),
    bytes(alice.exchange_key),
    ephemeralPublic,
    bytes(bob.signing_key),
    bytes(bob.exchange_key),
    spkPublic,
    ...(scenario.oneTime ? [opkPublic] : []),
    kemPublic,
    ciphertext,
  );
  const inputKey = Buffer.concat([Buffer.alloc(32, 0xff), ...dhs, sharedSecret]);
  const output = Buffer.from(hkdfSync("sha256", inputKey, Buffer.alloc(32), Buffer.concat([label("pqxdh"), transcriptHash]), 96));
  const associatedData = Buffer.concat([
    label("ad"),
    bytes(alice.signing_key),
    bytes(alice.exchange_key),
    bytes(bob.signing_key),
    bytes(bob.exchange_key),
    transcriptHash,
  ]);

  const twin = twinOf(ephemeralPublic);
  const responderSecrets = [bytes(bob.exchange_secret), spkSecret, ...(scenario.oneTime ? [opkSecret] : [])];
  const twinAgrees = responderSecrets.every((responderSecret) => dh(responderSecret, twin).equals(dh(responderSecret, ephemeralPublic)));
  if (twin.equals(ephemeralPublic) || fromLittleEndian(twin) >= fieldPrime || !twinAgrees) {
    throw new Error("the ephemeral key's twin is not a second key with the same X25519 results");
  }
  const initialHeader = Buffer.concat([
    bytes(alice.signing_key),
    bytes(alice.exchange_key),
    bytes(alice.binding),
    ephemeralPublic,
    ciphertext,
    u32(ids.spk),
    u8(scenario.kemKind),
    u32(ids.kem),
    scenario.oneTime ? Buffer.concat([u8(1), u32(ids.opk)]) : u8(0),
  ]);

  return {
    name: scenario.name,
    alice: scenario.alice,
    bob: scenario.bob,
    generation: scenario.generation,
    created_at: createdAt,
    now,
    signed_prekey: {
      id: ids.spk,
      secret: hex(spkSecret),
      public: hex(spkPublic),
      signature: hex(signPrekey(bobSeed, 1, ids.spk, createdAt, scenario.generation, spkPublic)),
    },
    kem_prekey: {
      kind: scenario.kemKind,
      id: ids.kem,
      wycheproof_tcId: scenario.kemTcId,
      signature: hex(signPrekey(bobSeed, scenario.kemKind, ids.kem, createdAt, scenario.generation, kemPublic)),
    },
    seal_key: {
      id: ids.ssk,
      secret: hex(sskSecret),
      public: hex(sskPublic),
      signature: hex(signPrekey(bobSeed, 4, ids.ssk, createdAt, scenario.generation, sskPublic)),
    },
    one_time_prekey: scenario.oneTime ? { id: ids.opk, secret: hex(opkSecret), public: hex(opkPublic) } : null,
    ephemeral_secret: hex(ephemeralSecret),
    ephemeral_key_twin: hex(twin),
    transcript_hash: hex(transcriptHash),
    root_key: hex(output.subarray(0, 32)),
    header_key_alice: hex(output.subarray(32, 64)),
    next_header_key_bob: hex(output.subarray(64, 96)),
    associated_data: hex(associatedData),
    initial_header: hex(initialHeader),
    replay_tag: hex(sha256(ephemeralPublic, ciphertext)),
  };
});

const document = {
  description: "LUME PQXDH handshake, CRYPTO.md sections 4 and 5, computed with Node.js crypto (OpenSSL); the ML-KEM-768 key, ciphertext and shared secret are the Wycheproof mlkem_768_test.json case named by wycheproof_tcId; ephemeral_key_twin is EK_A^(p-2) mod p, checked with OpenSSL to give every X25519 result EK_A gives",
  generator: "core/tools/generate_handshake_vectors.mjs",
  cases,
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log(`wrote ${cases.length} handshake cases`);
