// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

const [identityFile, outputFile] = process.argv.slice(2);
const alice = JSON.parse(readFileSync(identityFile, "utf8")).cases[3];

const bytes = (text) => Buffer.from(text, "hex");
const hex = (value) => Buffer.from(value).toString("hex");
const u16 = (value) => {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
};
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

const privateKey = (seed) => createPrivateKey({ key: Buffer.concat([bytes("302e020100300506032b657004220420"), seed]), format: "der", type: "pkcs8" });
const publicOf = (seed) => createPublicKey(privateKey(seed)).export({ format: "der", type: "spki" }).subarray(-32);
const publicKey = (key) => createPublicKey({ key: Buffer.concat([bytes("302a300506032b6570032100"), key]), format: "der", type: "spki" });
const seedOf = (name) => createHash("sha256").update(`LUME directory vector ${name}`, "ascii").digest();
const signed = (seed, message) => {
  const signature = sign(null, message, privateKey(seed));
  if (!verify(null, message, publicKey(publicOf(seed)), signature)) throw new Error("OpenSSL refused its own Ed25519 signature");
  return signature;
};

const day = 86400;
const now = 1_800_003_600;
const today = now - (now % day);

const root = { seed: seedOf("root") };
root.public = publicOf(root.seed);

const directoryKeys = [
  { key_id: 0x0a0b0c01, seed: seedOf("directory key 1"), not_before: today - 7 * day, not_after: today + 60 * day },
  { key_id: 0x0a0b0c02, seed: seedOf("directory key 2"), not_before: today + 7 * day, not_after: today + 90 * day },
].map((key) => ({ ...key, public: publicOf(key.seed) }));
const revoked = [{ key_id: 0x0a0b0c00, since: today - 3 * day }];

const list = { sequence: 42, issued_at: today - day, expires_at: today + 13 * day };
const unsignedList = Buffer.concat([
  u64(list.sequence), u64(list.issued_at), u64(list.expires_at),
  u16(directoryKeys.length),
  ...directoryKeys.map((key) => Buffer.concat([u32(key.key_id), key.public, u64(key.not_before), u64(key.not_after)])),
  u16(revoked.length),
  ...revoked.map((entry) => Buffer.concat([u32(entry.key_id), u64(entry.since)])),
]);
const listMessage = Buffer.concat([label("directory-keys"), unsignedList]);
const listSignature = signed(root.seed, listMessage);

const username = Buffer.from("alice", "utf8");
const certificate = {
  key_id: directoryKeys[0].key_id,
  username: username.toString("utf8"),
  account_id: seedOf("account").subarray(0, 16),
  ik_sig: bytes(alice.signing_key),
  ik_dh: bytes(alice.exchange_key),
  generation: 1,
  issued_at: today,
  expires_at: today + 30 * day,
};
const unsignedCertificate = Buffer.concat([
  u32(certificate.key_id), lengthPrefixed(username), certificate.account_id, certificate.ik_sig, certificate.ik_dh,
  u32(certificate.generation), u64(certificate.issued_at), u64(certificate.expires_at),
]);
const certificateMessage = Buffer.concat([label("certificate"), unsignedCertificate]);
const certificateSignature = signed(directoryKeys[0].seed, certificateMessage);

const document = {
  description: "LUME directory key list and username certificate, PROTOCOL.md section 2.1 and CRYPTO.md section 5.3, signed with Node.js crypto (OpenSSL) Ed25519; every seed is SHA-256(\"LUME directory vector \" || name); the certificate names the identity of case 3 of identity.json; both must be accepted at now",
  generator: "core/tools/generate_directory_vectors.mjs",
  now,
  root: { seed: hex(root.seed), public: hex(root.public) },
  directory_keys: directoryKeys.map((key) => ({ key_id: key.key_id, seed: hex(key.seed), public: hex(key.public), not_before: key.not_before, not_after: key.not_after })),
  list: {
    ...list,
    revoked,
    message: hex(listMessage),
    signature: hex(listSignature),
    encoded: hex(Buffer.concat([unsignedList, listSignature])),
  },
  certificate: {
    ...certificate,
    account_id: hex(certificate.account_id),
    ik_sig: hex(certificate.ik_sig),
    ik_dh: hex(certificate.ik_dh),
    message: hex(certificateMessage),
    signature: hex(certificateSignature),
    encoded: hex(Buffer.concat([unsignedCertificate, certificateSignature])),
  },
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log("wrote the directory vectors");
