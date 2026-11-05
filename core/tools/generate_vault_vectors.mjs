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
const nonceOf = (name) => seedOf(name).subarray(0, 24);
const zero = Buffer.alloc(32);
const fail = (message) => {
  throw new Error(message);
};

checkAgainstWycheproof(wycheproofDir);
checkAgainstRfc9106();

const floorCost = { ops: 2, mem: 65536 };
const generalCeiling = { ops: 10, mem: 1048576 };
const withinBounds = (cost) => cost.ops >= floorCost.ops && cost.ops <= generalCeiling.ops
  && cost.mem >= floorCost.mem && cost.mem <= generalCeiling.mem;

const argon2Cases = [
  ["floor", "the floor cost of section 10.3", "correct horse battery staple", 2, 65536],
  ["android", "the Android default cost with a passphrase outside ASCII", "пароль на этом устройстве", 3, 65536],
  ["smallest", "the smallest cost libsodium accepts, with an empty passphrase", "", 1, 8],
  ["changed", "the passphrase a vault changes to, at the floor cost", "a different passphrase for the vault", 2, 65536],
  ["another", "another passphrase under the salt and cost of the floor case", "not the passphrase of this vault", 2, 65536, "floor"],
].map(([name, description, passphrase, ops, mem, saltOf = name]) => {
  const password = Buffer.from(passphrase, "utf8");
  const salt = seedOf(`salt ${saltOf}`).subarray(0, 16);
  const key = argon2id({ password, salt, passes: ops, memoryKiB: mem });
  return { name, description, passphrase: hex(password), salt: hex(salt), ops, mem, key: hex(key) };
});
const argonCase = (name) => argon2Cases.find((entry) => entry.name === name) ?? fail(`no Argon2id case ${name}`);
const passphraseOf = (name) => {
  const entry = argonCase(name);
  return { name, kpw: Buffer.from(entry.key, "hex"), salt: Buffer.from(entry.salt, "hex"), cost: { ops: entry.ops, mem: entry.mem } };
};

const dataKey = seedOf("data key");
const keys = {
  record: hkdf(zero, dataKey, "vault/record-key"),
  address: hkdf(zero, dataKey, "vault/address-key"),
  manifest: hkdf(zero, dataKey, "vault/manifest-key"),
  root: hkdf(zero, dataKey, "vault/root-key"),
};

const keystoreInput = (kpw) => hkdf(zero, kpw, "vault/keystore");
const tpmAuthorisation = (kpw) => hkdf(zero, kpw, "vault/tpm-pin");
const keystoreOutput = (epoch, kpw) => hmac(seedOf(`keystore key ${epoch}`), keystoreInput(kpw));

const tpmKey = createECDH("prime256v1");
tpmKey.setPrivateKey(seedOf("tpm key"));
const tpmPoint = tpmKey.getPublicKey();
const tpmSharedSecret = tpmKey.computeSecret(tpmPoint);
const squared = createECDH("prime256v1");
const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const scalar = BigInt(`0x${hex(seedOf("tpm key"))}`);
squared.setPrivateKey(Buffer.from(((scalar * scalar) % order).toString(16).padStart(64, "0"), "hex"));
if (!tpmSharedSecret.equals(squared.getPublicKey().subarray(1, 33))) fail("ECDH of K_tpm with its own public key must be the x-coordinate of k^2 G");

const hardwareOf = (mode, epoch, output) => ({ mode, epoch, point: mode === 2 ? tpmPoint : null, output });
const keystoreHardware = (epoch, passphrase) => hardwareOf(1, epoch, keystoreOutput(epoch, passphrase.kpw));
const hardwareKeyOf = (hardware) => (hardware.mode === 2 ? sha256(label("vault/tpm"), hardware.output) : hardware.output);
const masterOf = (passphrase, hardware) => ({
  key: hkdf(hardwareKeyOf(hardware), passphrase.kpw, "vault/master"),
  salt: passphrase.salt, cost: passphrase.cost, mode: hardware.mode, epoch: hardware.epoch, point: hardware.point,
});
const hardwareJson = (hardware) => ({
  mode: hardware.mode, epoch: hardware.epoch, point: hardware.point ? hex(hardware.point) : null, output: hex(hardware.output),
});

const encodeHeader = (header) => Buffer.concat([
  u8(1), header.salt, u32(header.cost.ops), u32(header.cost.mem), u8(header.mode),
  header.point ? Buffer.concat([u8(1), header.point]) : u8(0), header.wrapped, u64(header.epoch),
]);
const checkOf = (masterKey, header) => hmac(hkdf(zero, masterKey, "vault/check-key"), label("vault/check"), encodeHeader(header));
const sealHeader = ({ master, nonce, cost = master.cost, epoch, wrapped = null }) => {
  const header = {
    salt: master.salt, cost, mode: master.mode, point: master.point, epoch,
    wrapped: wrapped ?? Buffer.concat([nonce, aeadEncrypt(master.key, nonce, label("vault/data-key"), dataKey)]),
  };
  if (header.wrapped.length !== 72) fail("a wrapped data key is 72 bytes");
  return { ...header, check: checkOf(master.key, header) };
};
const encodedHeader = (header) => Buffer.concat([encodeHeader(header), header.check]);
const headerOutcome = (header, master) => {
  if (![1, 2, 3].includes(header.mode) || (header.mode === 2) !== Boolean(header.point)
    || (header.point && header.point[0] !== 4) || header.epoch < 1) return "integrity";
  if (!withinBounds(header.cost)) return "integrity";
  const named = header.mode === 2 ? Boolean(master.point) && master.point.equals(header.point) : master.epoch === header.epoch;
  if (!master.salt.equals(header.salt) || master.cost.ops !== header.cost.ops || master.cost.mem !== header.cost.mem
    || master.mode !== header.mode || !named) return "invalid_parameters";
  const unwrapped = aeadDecrypt(master.key, header.wrapped.subarray(0, 24), label("vault/data-key"), header.wrapped.subarray(24));
  const unwraps = Boolean(unwrapped) && unwrapped.length === 32;
  if (!checkOf(master.key, header).equals(header.check)) return unwraps ? "integrity" : "wrong_passphrase";
  return unwraps ? null : "integrity";
};

const floor = passphraseOf("floor");
const changed = passphraseOf("changed");
const another = passphraseOf("another");
const softwareOutput = seedOf("software key 1");
const headerInputs = [
  ["keystore_first", "a new Android vault: epoch 1 under Keystore key 1", null, floor, keystoreHardware(1, floor), 1],
  ["keystore_next", "the same vault after one unlock: epoch 2 under Keystore key 2, the same data key", "keystore_first", floor,
    keystoreHardware(2, floor), 2],
  ["keystore_rekeyed", "the same vault after a passphrase change: a new salt, epoch 3 under Keystore key 3, the same data key",
    "keystore_next", changed, keystoreHardware(3, changed), 3],
  ["tpm_first", "a new Windows vault bound to a TPM key whose own public key is P: epoch 1", null, floor,
    hardwareOf(2, 1, tpmSharedSecret), 1],
  ["tpm_next", "the same TPM vault after one unlock: epoch 2 under the same TPM key", "tpm_first", floor,
    hardwareOf(2, 1, tpmSharedSecret), 2],
  ["software_first", "a new software-only vault: epoch 1 under the core's random key 1", null, floor,
    hardwareOf(3, 1, softwareOutput), 1],
];
const headerByName = new Map();
const headers = headerInputs.map(([name, description, from, passphrase, hardware, epoch]) => {
  const nonce = nonceOf(`header ${name}`);
  const master = masterOf(passphrase, hardware);
  const header = sealHeader({ master, nonce, epoch });
  if (headerOutcome(header, master) !== null) fail(`the ${name} header must open`);
  if (from && headerByName.get(from).epoch + 1 !== epoch) fail(`${name} must follow ${from}`);
  headerByName.set(name, header);
  return {
    name, description, from, passphrase: passphrase.name, hardware: hardwareJson(hardware), nonce: hex(nonce), epoch,
    wrapped_data_key: hex(header.wrapped), check: hex(header.check), encoded: hex(encodedHeader(header)),
  };
});

const keystoreFirst = headerByName.get("keystore_first");
const firstMaster = masterOf(floor, keystoreHardware(1, floor));
const garbageWrapped = Buffer.concat([nonceOf("garbage nonce"), seedOf("garbage a"), seedOf("garbage b").subarray(0, 16)]);
if (aeadDecrypt(firstMaster.key, garbageWrapped.subarray(0, 24), label("vault/data-key"), garbageWrapped.subarray(24))) {
  fail("the garbage data key must not unwrap");
}
const tamperedCheck = { ...keystoreFirst, check: Buffer.from(keystoreFirst.check) };
tamperedCheck.check[0] ^= 0x01;
const headerRefusals = [
  ["another_hardware_key", "the right passphrase with another Keystore output", keystoreFirst, floor,
    hardwareOf(1, 1, seedOf("another hardware key")), "wrong_passphrase"],
  ["another_passphrase", "another passphrase under the same salt and cost, with the Keystore key of that passphrase", keystoreFirst,
    another, keystoreHardware(1, another), "wrong_passphrase"],
  ["tampered_check", "the check changed after it was written: the master key is right and the data key unwraps", tamperedCheck,
    floor, keystoreHardware(1, floor), "integrity"],
  ["ops_below_floor", "one pass, with a check that verifies under the master key",
    sealHeader({ master: firstMaster, nonce: nonceOf("ops nonce"), cost: { ops: 1, mem: 65536 }, epoch: 1 }), floor,
    keystoreHardware(1, floor), "integrity"],
  ["mem_above_ceiling", "1 GiB and 1 KiB, with a check that verifies under the master key",
    sealHeader({ master: firstMaster, nonce: nonceOf("mem nonce"), cost: { ops: 2, mem: 1048577 }, epoch: 1 }), floor,
    keystoreHardware(1, floor), "integrity"],
  ["data_key_does_not_unwrap", "a check that verifies over a wrapped data key that does not authenticate",
    sealHeader({ master: firstMaster, wrapped: garbageWrapped, epoch: 1 }), floor, keystoreHardware(1, floor), "integrity"],
  ["another_salt", "a master key derived under another salt", keystoreFirst, changed, keystoreHardware(1, changed),
    "invalid_parameters"],
  ["another_epoch", "the Keystore key of epoch 2 offered for a header of epoch 1", keystoreFirst, floor, keystoreHardware(2, floor),
    "invalid_parameters"],
  ["another_mode", "a software key offered for a Keystore header", keystoreFirst, floor, hardwareOf(3, 1, softwareOutput),
    "invalid_parameters"],
  ["tpm_epoch_zero", "a TPM header at epoch 0 whose check verifies and whose data key unwraps: a TPM key is named by its point, so only the epoch rule refuses it",
    sealHeader({ master: masterOf(floor, hardwareOf(2, 1, tpmSharedSecret)), nonce: nonceOf("tpm epoch zero nonce"), epoch: 0 }), floor,
    hardwareOf(2, 1, tpmSharedSecret), "integrity"],
].map(([name, description, header, passphrase, hardware, error]) => {
  if (headerOutcome(header, masterOf(passphrase, hardware)) !== error) fail(`${name} must be refused as ${error}`);
  if (name === "tpm_epoch_zero") {
    const master = masterOf(passphrase, hardware);
    const unwrapped = aeadDecrypt(master.key, header.wrapped.subarray(0, 24), label("vault/data-key"), header.wrapped.subarray(24));
    if (!checkOf(master.key, header).equals(header.check) || !unwrapped) fail("only the epoch rule may refuse tpm_epoch_zero");
  }
  return {
    name, description, encoded: hex(encodedHeader(header)), passphrase: passphrase.name, hardware: hardwareJson(hardware), error,
  };
});

const recordBuckets = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072];
const manifestBuckets = [8 + 2 + 32 * 37 + 1];
const pad = (message, buckets) => {
  const size = buckets.find((bucket) => message.length < bucket) ?? fail("too long to pad");
  const out = Buffer.alloc(size);
  message.copy(out);
  out[message.length] = 0x80;
  return out;
};
const unpad = (padded, buckets) => {
  if (!buckets.includes(padded.length)) return null;
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end -= 1;
  if (end < 0 || padded[end] !== 0x80) return null;
  return buckets.find((bucket) => end < bucket) === padded.length ? padded.subarray(0, end) : null;
};

const recordAd = (type, id, counter) => Buffer.concat([label("vault/record"), u8(type), lengthPrefixed(id), u64(counter)]);
const sealRecord = (type, id, counter, payload, nonce) =>
  Buffer.concat([nonce, aeadEncrypt(keys.record, nonce, recordAd(type, id, counter), pad(payload, recordBuckets))]);
const openRecord = (type, id, counter, expected, record) => {
  if (record.length < 40 + 256 || record.length > 40 + 131072 || type === 0 || id.length > 64) return "integrity";
  if (!record.subarray(0, 24).equals(expected)) return "integrity";
  const padded = aeadDecrypt(keys.record, record.subarray(0, 24), recordAd(type, id, counter), record.subarray(24));
  if (!padded) return "integrity";
  return unpad(padded, recordBuckets) ?? "integrity";
};
const encodeAddress = ({ type, idLength, id, counter, nonce }) => {
  const idField = Buffer.alloc(64);
  id.copy(idField);
  return Buffer.concat([u8(type), u8(idLength ?? id.length), idField, u64(counter), nonce]);
};
const addressAd = (slot) => Buffer.concat([label("vault/address"), u64(slot)]);
const sealAddress = (slot, address, nonce) =>
  Buffer.concat([nonce, aeadEncrypt(keys.address, nonce, addressAd(slot), encodeAddress(address))]);
const openAddress = (slot, sealed) => {
  if (slot === 0n || slot >= 1n << 63n || sealed.length !== 138) return "integrity";
  const plain = aeadDecrypt(keys.address, sealed.subarray(0, 24), addressAd(slot), sealed.subarray(24));
  if (!plain) return "integrity";
  const type = plain[0];
  const idLength = plain[1];
  if (type === 0 || idLength > 64 || plain.subarray(2 + idLength, 66).some((byte) => byte !== 0)) return "integrity";
  return { type, id: plain.subarray(2, 2 + idLength), counter: plain.readBigUInt64BE(66), nonce: plain.subarray(74, 98) };
};
const rootTermOf = (type, id, counter, nonce) => hmac(keys.root, label("vault/root"), u8(type), lengthPrefixed(id), u64(counter), nonce);

const recordInputs = [
  ["short", "a short record of type 1", 1, Buffer.from("contact 1", "ascii"), 1n, Buffer.from("hello, vault", "utf8")],
  ["day", "a day of history of type 2, padded to 1024 bytes", 2, seedOf("contact 2").subarray(0, 20), 7n, Buffer.alloc(1000, 0x5a)],
  ["empty", "an empty id and an empty payload, padded to 256 bytes", 2, Buffer.alloc(0), 0n, Buffer.alloc(0)],
  ["fills_a_bucket", "255 bytes, the most a 256-byte bucket holds", 3, Buffer.from("bucket edge", "ascii"), 2n, Buffer.alloc(255, 0x11)],
  ["next_bucket", "256 bytes, the fewest that need the 512-byte bucket", 3, Buffer.from("bucket edge 2", "ascii"), 3n, Buffer.alloc(256, 0x22)],
  ["largest_id", "an id at its 64-byte bound and the largest counter", 2, Buffer.concat([seedOf("id a"), seedOf("id b")]), (1n << 64n) - 1n, seedOf("payload")],
];
const records = recordInputs.map(([name, description, type, id, counter, payload]) => {
  const nonce = nonceOf(`record nonce ${name}`);
  const record = sealRecord(type, id, counter, payload, nonce);
  const opened = openRecord(type, id, counter, nonce, record);
  if (typeof opened === "string" || !opened.equals(payload)) fail(`${name} must open to its payload`);
  const slot = BigInt(`0x${hex(seedOf(`slot ${name}`).subarray(0, 8))}`) & ((1n << 63n) - 1n);
  if (slot === 0n) fail("a slot is never 0");
  const addressNonce = nonceOf(`address nonce ${name}`);
  const address = sealAddress(slot, { type, id, counter, nonce }, addressNonce);
  const located = openAddress(slot, address);
  if (typeof located === "string" || located.type !== type || !located.id.equals(id) || located.counter !== counter || !located.nonce.equals(nonce)) {
    fail(`the address of ${name} must open to its record`);
  }
  return {
    name, description, type, id: hex(id), counter: counter.toString(), payload: hex(payload), nonce: hex(nonce),
    record: hex(record), padded_size: pad(payload, recordBuckets).length, slot: slot.toString(),
    address_nonce: hex(addressNonce), address: hex(address), root_term: hex(rootTermOf(type, id, counter, nonce)),
  };
});

const [, , shortType, shortId, shortCounter] = recordInputs[0];
const shortRecord = Buffer.from(records[0].record, "hex");
const shortNonce = Buffer.from(records[0].nonce, "hex");
const shortSlot = BigInt(records[0].slot);
const flipped = Buffer.from(shortRecord);
flipped[30] ^= 0x01;
const sealedPlain = (name, plain) => {
  const nonce = nonceOf(`record nonce ${name}`);
  return Buffer.concat([nonce, aeadEncrypt(keys.record, nonce, recordAd(shortType, shortId, shortCounter), plain)]);
};
const noMarker = (() => {
  const plain = Buffer.alloc(256, 0);
  plain.write("no marker after this", "ascii");
  return sealedPlain("no marker", plain);
})();
const notABucket = sealedPlain("not a bucket", pad(Buffer.from("short", "ascii"), [300]));
const tooLargeABucket = sealedPlain("too large a bucket", pad(Buffer.from("fits in 256", "ascii"), [512]));
const longId = Buffer.alloc(65, 0x41);
const sealedOutside = (name, type, id) => {
  const nonce = nonceOf(`record nonce ${name}`);
  const record = sealRecord(type, id, shortCounter, Buffer.from("outside the address rules", "ascii"), nonce);
  if (!aeadDecrypt(keys.record, nonce, recordAd(type, id, shortCounter), record.subarray(24))) fail(`${name} must authenticate`);
  return record;
};
const typeZeroRecord = sealedOutside("type zero", 0, shortId);
const longIdRecord = sealedOutside("id too long", shortType, longId);
const recordRefusals = [
  ["another_type", "the record read as another type", { type: 2 }],
  ["type_zero", "a record sealed under type 0, which no record may have: only the address rule refuses it", {
    type: 0, record: typeZeroRecord, expected: typeZeroRecord.subarray(0, 24) }],
  ["id_too_long", "a record sealed under a 65-byte id: only the address rule refuses it", {
    id: longId, record: longIdRecord, expected: longIdRecord.subarray(0, 24) }],
  ["another_id", "the record read under another id", { id: Buffer.from("contact 2", "ascii") }],
  ["older_counter", "the record read with the counter of an older write", { counter: 0n }],
  ["flipped_byte", "one byte of the ciphertext flipped", { record: flipped }],
  ["truncated", "the record without its last byte, shorter than the smallest bucket", {
    record: Buffer.from(records[0].record, "hex").subarray(0, 295) }],
  ["another_nonce", "the record read where the vault expects the nonce of another write", { expected: nonceOf("another write") }],
  ["no_marker", "a payload whose padding has no 0x80 marker", { record: noMarker, expected: noMarker.subarray(0, 24) }],
  ["not_a_bucket", "a padded payload of 300 bytes, which is not a bucket size", { record: notABucket, expected: notABucket.subarray(0, 24) }],
  ["larger_bucket", "11 bytes padded to 512 bytes when 256 would hold them", {
    record: tooLargeABucket, expected: tooLargeABucket.subarray(0, 24) }],
].map(([name, description, change]) => {
  const type = change.type ?? shortType;
  const id = change.id ?? shortId;
  const counter = change.counter ?? shortCounter;
  const record = change.record ?? shortRecord;
  const expected = change.expected ?? shortNonce;
  if (openRecord(type, id, counter, expected, record) !== "integrity") fail(`${name} must not open`);
  return {
    name, description, type, id: hex(id), counter: counter.toString(), expected: hex(expected), record: hex(record), error: "integrity",
  };
});

const shortAddress = Buffer.from(records[0].address, "hex");
const flippedAddress = Buffer.from(shortAddress);
flippedAddress[40] ^= 0x01;
const badAddress = (name, address) => sealAddress(shortSlot, address, nonceOf(`address nonce ${name}`));
const outsideSlot = (name, slot) => {
  const box = sealAddress(slot, { type: shortType, id: shortId, counter: shortCounter, nonce: shortNonce }, nonceOf(`address nonce ${name}`));
  if (!aeadDecrypt(keys.address, box.subarray(0, 24), addressAd(slot), box.subarray(24))) fail(`${name} must authenticate`);
  return box;
};
const addressRefusals = [
  ["slot_zero", "a valid address sealed under slot 0, which no record has: only the slot rule refuses it", 0n,
    outsideSlot("slot zero", 0n)],
  ["slot_above_bound", "a valid address sealed under slot 2^63, above the bound: only the slot rule refuses it", 1n << 63n,
    outsideSlot("slot above bound", 1n << 63n)],
  ["another_slot", "the address opened under another slot", shortSlot + 1n, shortAddress],
  ["flipped_byte", "one byte of the box flipped", shortSlot, flippedAddress],
  ["type_zero", "an address of type 0", shortSlot,
    badAddress("type zero", { type: 0, id: shortId, counter: shortCounter, nonce: nonceOf("x") })],
  ["id_too_long", "an id length of 65", shortSlot,
    badAddress("id too long", { type: 1, idLength: 65, id: Buffer.alloc(64, 1), counter: 1n, nonce: nonceOf("x") })],
  ["bytes_after_id", "a byte that is not zero after the id", shortSlot,
    badAddress("bytes after id", { type: 1, idLength: 3, id: Buffer.from("abcd", "ascii"), counter: 1n, nonce: nonceOf("x") })],
].map(([name, description, slot, address]) => {
  if (openAddress(slot, address) !== "integrity") fail(`address ${name} must be refused`);
  return { name, description, slot: slot.toString(), address: hex(address), error: "integrity" };
});

const earlierNonce = nonceOf("record nonce short earlier");
const earlierPayload = Buffer.from("an earlier write at the same counter", "utf8");
const earlierRecord = sealRecord(shortType, shortId, shortCounter, earlierPayload, earlierNonce);
const earlierTerm = rootTermOf(shortType, shortId, shortCounter, earlierNonce);
if (earlierTerm.equals(Buffer.from(records[0].root_term, "hex"))) fail("an earlier write must have another term");
if (openRecord(shortType, shortId, shortCounter, shortNonce, earlierRecord) !== "integrity") {
  fail("an earlier write must not open where the vault expects the current nonce");
}
const earlierWrite = {
  description: "the record \"short\" as written before a deletion, at the same type, id and counter: it opens only when its own nonce is expected, and its term differs from the current one",
  record: hex(earlierRecord), nonce: hex(earlierNonce), payload: hex(earlierPayload), root_term: hex(earlierTerm),
};

const modulus = 1n << 256n;
const asNumber = (bytes) => BigInt(`0x${hex(bytes) || "0"}`);
const asBytes = (number) => Buffer.from(number.toString(16).padStart(64, "0"), "hex");
const sumOf = (terms) => asBytes(terms.reduce((sum, term) => (sum + asNumber(term)) % modulus, 0n));
const termsOfType = (type) => records.filter((record) => record.type === type).map((record) => Buffer.from(record.root_term, "hex"));
const typeTwo = termsOfType(2);
if (typeTwo.reduce((sum, term) => sum + asNumber(term), 0n) < modulus) fail("the type 2 terms must wrap around 2^256");
const rewritten = rootTermOf(2, recordInputs[1][3], 8n, nonceOf("record nonce day rewritten"));
const updated = asBytes((asNumber(sumOf(typeTwo)) - asNumber(typeTwo[0]) + asNumber(rewritten) + modulus) % modulus);
if (!updated.equals(sumOf([rewritten, ...typeTwo.slice(1)]))) fail("an incremental update must equal the recomputed root");
const roots = {
  type_1: hex(sumOf(termsOfType(1))),
  type_2: hex(sumOf(typeTwo)),
  type_3: hex(sumOf(termsOfType(3))),
  update: {
    description: "the type 2 record \"day\" is written again with counter 8: subtract its old term, add the new one",
    before: hex(sumOf(typeTwo)), removed_term: hex(typeTwo[0]), added_term: hex(rewritten), after: hex(updated),
  },
  from_zero: {
    description: "removing a term from the empty root wraps around 2^256",
    term: hex(termsOfType(1)[0]), after: hex(asBytes((modulus - asNumber(termsOfType(1)[0])) % modulus)),
  },
};

const manifestTypes = [1, 2, 3].map((type) => ({ type, count: termsOfType(type).length, root: sumOf(termsOfType(type)) }));
const encodeManifest = (epoch, types) => Buffer.concat([
  u64(epoch), u16(types.length), ...types.map(({ type, count, root }) => Buffer.concat([u8(type), u32(count), root])),
]);
const sealManifest = (nonce, plain) => Buffer.concat([nonce, aeadEncrypt(keys.manifest, nonce, label("vault/manifest"), plain)]);
const decodeManifest = (encoded) => {
  if (encoded.length < 10) return null;
  const count = encoded.readUInt16BE(8);
  if (count > 32 || encoded.length !== 10 + 37 * count) return null;
  const types = Array.from({ length: count }, (_, index) => {
    const at = 10 + 37 * index;
    return { type: encoded[at], count: encoded.readUInt32BE(at + 1) };
  });
  if (types.some((entry, index) => entry.type === 0 || entry.count === 0 || (index > 0 && types[index - 1].type >= entry.type))) return null;
  return { epoch: encoded.readBigUInt64BE(0), types };
};
const openManifest = (sealed, epoch) => {
  if (sealed.length !== 40 + manifestBuckets[0]) return "integrity";
  const padded = aeadDecrypt(keys.manifest, sealed.subarray(0, 24), label("vault/manifest"), sealed.subarray(24));
  if (!padded) return "integrity";
  const encoded = unpad(padded, manifestBuckets);
  const manifest = encoded && decodeManifest(encoded);
  if (!manifest || manifest.epoch !== BigInt(epoch)) return "integrity";
  return manifest;
};
const sealedManifest = sealManifest(nonceOf("manifest nonce"), pad(encodeManifest(1, manifestTypes), manifestBuckets));
if (sealedManifest.length !== 1235) fail("a sealed manifest is always 1235 bytes");
if (typeof openManifest(sealedManifest, 1) === "string") fail("the manifest must open at its epoch");
const emptyManifest = sealManifest(nonceOf("empty manifest nonce"), pad(encodeManifest(1, []), manifestBuckets));
if (emptyManifest.length !== 1235 || typeof openManifest(emptyManifest, 1) === "string") fail("the empty manifest must open");
const flippedManifest = Buffer.from(sealedManifest);
flippedManifest[100] ^= 0x01;
const manifestRefusals = [
  ["another_epoch", "the manifest opened under the header of the next epoch", "keystore_next", sealedManifest],
  ["flipped_byte", "one byte of the box flipped", "keystore_first", flippedManifest],
  ["no_marker", "a box whose plaintext has no padding marker", "keystore_first",
    sealManifest(nonceOf("unpadded manifest nonce"), Buffer.alloc(manifestBuckets[0], 0))],
  ["out_of_order", "types 2 and then 1, which a canonical manifest never holds", "keystore_first",
    sealManifest(nonceOf("unordered manifest nonce"), pad(encodeManifest(1, [manifestTypes[1], manifestTypes[0]]), manifestBuckets))],
  ["type_zero", "an entry of type 0 before type 1, in order and counted, which no record may have", "keystore_first",
    sealManifest(nonceOf("type zero manifest nonce"), pad(encodeManifest(1, [{ type: 0, count: 1, root: zero }, manifestTypes[0]]), manifestBuckets))],
].map(([name, description, header, sealed]) => {
  if (openManifest(sealed, headerByName.get(header).epoch) !== "integrity") fail(`manifest ${name} must be refused`);
  return { name, description, header, sealed: hex(sealed), error: "integrity" };
});

const document = {
  description: "LUME vault, CRYPTO.md section 10, computed with Node.js crypto (OpenSSL), the shared XChaCha20-Poly1305 checked against Wycheproof and an Argon2id implementation of its own checked against RFC 9106 section 5.3. It holds Argon2id with one lane and a 32-byte output; the Keystore input and the TPM authorisation; headers of a first epoch, a next epoch and a passphrase change, each built from an Argon2id case, a hardware output and a nonce, with the same data key; records padded to power-of-two buckets, their sealed addresses under a slot, root terms that cover each record's nonce, roots and an incremental update; and a manifest sealed at a fixed size. Seeds are SHA-256(\"LUME vault vector \" || name). A Keystore output of epoch e is HMAC-SHA256 under SHA-256(\"LUME vault vector keystore key e\") of the Keystore input; a TPM output is the x-coordinate of a real P-256 ECDH of K_tpm with its own public key. Every refusal is confirmed against the generator's own model of the checks, and must be refused with the error it names",
  generator: "core/tools/generate_vault_vectors.mjs",
  argon2id: argon2Cases,
  keys: {
    passphrase: "floor",
    keystore_input: hex(keystoreInput(floor.kpw)),
    tpm_authorisation: hex(tpmAuthorisation(floor.kpw)),
    data_key: hex(dataKey),
  },
  headers,
  header_refusals: headerRefusals,
  records,
  record_refusals: recordRefusals,
  address_refusals: addressRefusals,
  earlier_write: earlierWrite,
  roots,
  manifest: {
    header: "keystore_first",
    types: manifestTypes.map(({ type, count, root }) => ({ type, count, root: hex(root) })),
    nonce: hex(nonceOf("manifest nonce")),
    sealed: hex(sealedManifest),
    empty: { nonce: hex(nonceOf("empty manifest nonce")), sealed: hex(emptyManifest) },
    refusals: manifestRefusals,
  },
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log("wrote the vault vectors");
