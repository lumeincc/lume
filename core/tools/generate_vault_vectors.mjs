// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { writeFileSync } from "node:fs";
import { createECDH, createHash, createHmac, hkdfSync } from "node:crypto";
import { argon2id, checkAgainstRfc9106 } from "./argon2id.mjs";
import { aeadDecrypt, aeadEncrypt, checkAgainstWycheproof } from "./xchacha20poly1305.mjs";

const [wycheproofDir, outputFile] = process.argv.slice(2);

const hex = (value) => Buffer.from(value).toString("hex");
const u8 = (value) => Buffer.from([value]);
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
const sha256 = (...parts) => parts.reduce((hash, part) => hash.update(part), createHash("sha256")).digest();
const hmac = (key, ...parts) => parts.reduce((mac, part) => mac.update(part), createHmac("sha256", key)).digest();
const hkdf = (salt, input, name) => Buffer.from(hkdfSync("sha256", input, salt, label(name), 32));
const seedOf = (name) => sha256(Buffer.from(`LUME vault vector ${name}`, "ascii"));
const zero = Buffer.alloc(32);

checkAgainstWycheproof(wycheproofDir);
checkAgainstRfc9106();

const argon2Cases = [
  ["floor", "the floor cost of section 10.3", "correct horse battery staple", 2, 65536],
  ["android", "the Android default cost with a passphrase outside ASCII", "пароль на этом устройстве", 3, 65536],
  ["smallest", "the smallest cost libsodium accepts, with an empty passphrase", "", 1, 8],
].map(([name, description, passphrase, ops, mem]) => {
  const password = Buffer.from(passphrase, "utf8");
  const salt = seedOf(`salt ${name}`).subarray(0, 16);
  const key = argon2id({ password, salt, passes: ops, memoryKiB: mem });
  return { name, description, passphrase: hex(password), salt: hex(salt), ops, mem, key: hex(key) };
});

const floor = argon2Cases[0];
const passphraseKey = Buffer.from(floor.key, "hex");
const salt = Buffer.from(floor.salt, "hex");
const dataKey = seedOf("data key");
const recordKey = hkdf(zero, dataKey, "vault/record-key");
const manifestKey = hkdf(zero, dataKey, "vault/manifest-key");
const rootKey = hkdf(zero, dataKey, "vault/root-key");

const tpmKey = createECDH("prime256v1");
tpmKey.setPrivateKey(seedOf("tpm key"));
const tpmPointOwner = createECDH("prime256v1");
tpmPointOwner.setPrivateKey(seedOf("tpm point"));
const tpmPoint = tpmPointOwner.getPublicKey();
const tpmSharedSecret = tpmKey.computeSecret(tpmPoint);
if (!tpmSharedSecret.equals(tpmPointOwner.computeSecret(tpmKey.getPublicKey()))) throw new Error("P-256 ECDH does not agree");
const tpmAuthorisation = hkdf(zero, passphraseKey, "vault/tpm-pin");
const tpmHardwareKey = sha256(label("vault/tpm"), tpmSharedSecret);

const keystoreHardwareKey = seedOf("keystore hardware key");
const masterKeyOf = (hardwareKey) => hkdf(hardwareKey, passphraseKey, "vault/master");

const encodeHeader = (header) => Buffer.concat([
  u8(1), header.salt, u32(header.ops), u32(header.mem), u8(header.hwMode),
  header.tpmPoint ? Buffer.concat([u8(1), header.tpmPoint]) : u8(0), header.wrapped, u64(header.epoch),
]);
const sealHeader = ({ masterKey, nonce, ops = floor.ops, mem = floor.mem, hwMode, tpmPoint = null, epoch, wrapped = null }) => {
  const header = {
    salt, ops, mem, hwMode, tpmPoint, epoch,
    wrapped: wrapped ?? Buffer.concat([nonce, aeadEncrypt(masterKey, nonce, label("vault/data-key"), dataKey)]),
  };
  if (header.wrapped.length !== 72) throw new Error("a wrapped data key is 72 bytes");
  const unsigned = encodeHeader(header);
  const check = hmac(hkdf(zero, masterKey, "vault/check-key"), label("vault/check"), unsigned);
  return { ...header, unsigned, check, encoded: Buffer.concat([unsigned, check]) };
};

const keystoreMaster = masterKeyOf(keystoreHardwareKey);
const tpmMaster = masterKeyOf(tpmHardwareKey);
const headers = [
  ["keystore", "an Android vault at epoch 7", { masterKey: keystoreMaster, nonce: seedOf("keystore nonce").subarray(0, 24), hwMode: 1, epoch: 7 }],
  ["tpm", "a Windows vault bound to a TPM key, with the point P in its header", { masterKey: tpmMaster, nonce: seedOf("tpm nonce").subarray(0, 24), hwMode: 2, tpmPoint, epoch: 1 }],
].map(([name, description, input]) => {
  const header = sealHeader(input);
  const unwrapped = aeadDecrypt(input.masterKey, header.wrapped.subarray(0, 24), label("vault/data-key"), header.wrapped.subarray(24));
  if (!unwrapped || !unwrapped.equals(dataKey)) throw new Error("the wrapped data key does not unwrap");
  return {
    name, description, master_key: hex(input.masterKey), hw_mode: input.hwMode, epoch: input.epoch,
    tpm_point: input.tpmPoint ? hex(input.tpmPoint) : null, nonce: hex(input.nonce),
    wrapped_data_key: hex(header.wrapped), check: hex(header.check), encoded: hex(header.encoded),
  };
});

const keystoreHeader = sealHeader({ masterKey: keystoreMaster, nonce: seedOf("keystore nonce").subarray(0, 24), hwMode: 1, epoch: 7 });
const tamperedEpoch = Buffer.concat([encodeHeader({ ...keystoreHeader, epoch: 8 }), keystoreHeader.check]);
const garbageWrapped = Buffer.concat([seedOf("garbage nonce").subarray(0, 24), seedOf("garbage a"), seedOf("garbage b").subarray(0, 16)]);
if (aeadDecrypt(keystoreMaster, garbageWrapped.subarray(0, 24), label("vault/data-key"), garbageWrapped.subarray(24))) {
  throw new Error("the garbage data key must not unwrap");
}
const headerRefusals = [
  ["another_hardware_key", "the right passphrase key with another hardware key", keystoreHeader.encoded, masterKeyOf(seedOf("another hardware key")), "wrong_passphrase"],
  ["another_passphrase", "another passphrase key with the right hardware key",
    keystoreHeader.encoded, hkdf(keystoreHardwareKey, seedOf("another passphrase key"), "vault/master"), "wrong_passphrase"],
  ["tampered_epoch", "the epoch was changed after the check was computed", tamperedEpoch, keystoreMaster, "wrong_passphrase"],
  ["ops_below_floor", "one pass, with a check that verifies",
    sealHeader({ masterKey: keystoreMaster, nonce: seedOf("ops nonce").subarray(0, 24), ops: 1, hwMode: 1, epoch: 7 }).encoded, keystoreMaster, "integrity"],
  ["mem_above_ceiling", "1 GiB and 1 KiB, with a check that verifies",
    sealHeader({ masterKey: keystoreMaster, nonce: seedOf("mem nonce").subarray(0, 24), mem: 1048577, hwMode: 1, epoch: 7 }).encoded, keystoreMaster, "integrity"],
  ["data_key_does_not_unwrap", "a check that verifies over a wrapped data key that does not authenticate",
    sealHeader({ masterKey: keystoreMaster, hwMode: 1, epoch: 7, wrapped: garbageWrapped }).encoded, keystoreMaster, "integrity"],
].map(([name, description, encoded, masterKey, error]) => ({ name, description, encoded: hex(encoded), master_key: hex(masterKey), error }));

const recordAd = (type, id, counter) => Buffer.concat([label("vault/record"), u8(type), lengthPrefixed(id), u64(counter)]);
const rootTermOf = (type, id, counter) => hmac(rootKey, label("vault/root"), u8(type), lengthPrefixed(id), u64(counter));
const recordInputs = [
  ["short", "a short record of type 1", 1, Buffer.from("contact 1", "ascii"), 1n, Buffer.from("hello, vault", "utf8")],
  ["day", "a day of history of type 2", 2, seedOf("contact 2").subarray(0, 20), 7n, Buffer.alloc(1000, 0x5a)],
  ["empty", "an empty id and an empty payload", 2, Buffer.alloc(0), 0n, Buffer.alloc(0)],
  ["largest_id", "an id at its 64-byte bound and the largest counter", 2, Buffer.concat([seedOf("id a"), seedOf("id b")]), (1n << 64n) - 1n, seedOf("payload")],
];
const records = recordInputs.map(([name, description, type, id, counter, payload]) => {
  const nonce = seedOf(`record nonce ${name}`).subarray(0, 24);
  const sealed = Buffer.concat([nonce, aeadEncrypt(recordKey, nonce, recordAd(type, id, counter), payload)]);
  return {
    name, description, type, id: hex(id), counter: counter.toString(), payload: hex(payload), nonce: hex(nonce),
    record: hex(sealed), root_term: hex(rootTermOf(type, id, counter)),
  };
});
const short = recordInputs[0];
const recordRefusals = [
  ["another_type", "the record read as another type", { type: 2 }],
  ["another_id", "the record read under another id", { id: Buffer.from("contact 2", "ascii") }],
  ["older_counter", "the record read with the counter of an older write", { counter: 0n }],
  ["flipped_byte", "one byte of the ciphertext flipped", { flip: true }],
].map(([name, description, change]) => {
  const sealed = Buffer.from(records[0].record, "hex");
  if (change.flip) sealed[30] ^= 0x01;
  const type = change.type ?? short[2];
  const id = change.id ?? short[3];
  const counter = change.counter ?? short[4];
  if (aeadDecrypt(recordKey, sealed.subarray(0, 24), recordAd(type, id, counter), sealed.subarray(24))) {
    throw new Error(`${name} must not open`);
  }
  return { name, description, type, id: hex(id), counter: counter.toString(), record: hex(sealed), error: "integrity" };
});

const modulus = 1n << 256n;
const asNumber = (bytes) => BigInt(`0x${hex(bytes) || "0"}`);
const asBytes = (number) => Buffer.from(number.toString(16).padStart(64, "0"), "hex");
const sumOf = (terms) => asBytes(terms.reduce((sum, term) => (sum + asNumber(term)) % modulus, 0n));
const typeTwo = records.filter((record) => record.type === 2).map((record) => Buffer.from(record.root_term, "hex"));
const typeOne = [Buffer.from(records[0].root_term, "hex")];
if (typeTwo.reduce((sum, term) => sum + asNumber(term), 0n) < modulus) throw new Error("the type 2 terms must wrap around 2^256");
const rewritten = rootTermOf(2, recordInputs[1][3], 8n);
const updated = asBytes((asNumber(sumOf(typeTwo)) - asNumber(typeTwo[0]) + asNumber(rewritten) + modulus) % modulus);
if (!updated.equals(sumOf([rewritten, typeTwo[1], typeTwo[2]]))) throw new Error("an incremental update must equal the recomputed root");
const roots = {
  type_1: hex(sumOf(typeOne)),
  type_2: hex(sumOf(typeTwo)),
  update: {
    description: "the type 2 record \"day\" is written again with counter 8: subtract its old term, add the new one",
    before: hex(sumOf(typeTwo)), removed_term: hex(typeTwo[0]), added_term: hex(rewritten), after: hex(updated),
  },
  from_zero: {
    description: "removing a term from the empty root wraps around 2^256",
    term: hex(typeOne[0]), after: hex(asBytes((modulus - asNumber(typeOne[0])) % modulus)),
  },
};

const manifestEpoch = 7;
const manifestTypes = [[1, typeOne.length, sumOf(typeOne)], [2, typeTwo.length, sumOf(typeTwo)]];
const encodedManifest = Buffer.concat([
  u64(manifestEpoch), u16(manifestTypes.length),
  ...manifestTypes.map(([type, count, root]) => Buffer.concat([u8(type), u32(count), root])),
]);
const manifestTag = hmac(manifestKey, label("vault/manifest"), encodedManifest);
const tamperedCount = Buffer.from(encodedManifest);
tamperedCount.writeUInt32BE(2, 8 + 2 + 1);
const manifest = {
  epoch: manifestEpoch,
  types: manifestTypes.map(([type, count, root]) => ({ type, count, root: hex(root) })),
  encoded: hex(encodedManifest),
  tag: hex(manifestTag),
  refusals: [
    { name: "another_epoch", description: "the manifest checked against the header of the next epoch", encoded: hex(encodedManifest), epoch: 8, error: "integrity" },
    { name: "tampered_count", description: "the count of type 1 changed after the tag was computed", encoded: hex(tamperedCount), epoch: 7, error: "integrity" },
  ],
};

const document = {
  description: "LUME vault, CRYPTO.md section 10, computed with Node.js crypto (OpenSSL), the shared XChaCha20-Poly1305 checked against Wycheproof and an Argon2id implementation of its own checked against RFC 9106 section 5.3: Argon2id with one lane and a 32-byte output, the key schedule of section 10.1 including the TPM binding with a real P-256 ECDH, headers that open under their master key, records, roots and a manifest; seeds are SHA-256(\"LUME vault vector \" || name); a header refusal must be refused with the error it names when opened under its master key, a record refusal when opened at its address, a manifest refusal when checked at its epoch",
  generator: "core/tools/generate_vault_vectors.mjs",
  argon2id: argon2Cases,
  keys: {
    passphrase_key: hex(passphraseKey),
    salt: hex(salt),
    ops: floor.ops,
    mem: floor.mem,
    data_key: hex(dataKey),
    record_key: hex(recordKey),
    manifest_key: hex(manifestKey),
    root_key: hex(rootKey),
    keystore: { hardware_key: hex(keystoreHardwareKey), master_key: hex(keystoreMaster), check_key: hex(hkdf(zero, keystoreMaster, "vault/check-key")) },
    tpm: {
      authorisation: hex(tpmAuthorisation),
      point: hex(tpmPoint),
      shared_secret: hex(tpmSharedSecret),
      hardware_key: hex(tpmHardwareKey),
      master_key: hex(tpmMaster),
    },
  },
  headers,
  header_refusals: headerRefusals,
  records,
  record_refusals: recordRefusals,
  roots,
  manifest,
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log("wrote the vault vectors");
