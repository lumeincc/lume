// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const [vectorsDir, outputFile] = process.argv.slice(2);
const load = (name) => JSON.parse(readFileSync(join(vectorsDir, name), "utf8"));
const tests = (suite) => suite.testGroups.flatMap((g) => g.tests.map((t) => ({ ...t, group: g })));
const sha256Hex = (hex) => createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex");

const hmac = tests(load("hmac_sha256_test.json")).find((t) => t.tcId === 1);
if (hmac.group.tagSize !== 256 || hmac.result !== "valid") throw new Error("unexpected HMAC vector");

const hkdf = tests(load("hkdf_sha256_test.json")).find((t) => t.tcId === 1);
if (hkdf.size !== 42 || hkdf.result !== "valid") throw new Error("unexpected HKDF vector");

const x25519 = tests(load("x25519_test.json")).find((t) => t.tcId === 100);
if (!x25519.comment.includes("RFC 7748")) throw new Error("unexpected X25519 vector");

const ed25519 = tests(load("ed25519_test.json")).find((t) => t.tcId === 80);
if (!ed25519.comment.includes("Test 1") || ed25519.msg !== "") throw new Error("unexpected Ed25519 vector");

const xchacha = tests(load("xchacha20_poly1305_test.json")).find((t) => t.tcId === 1);
if (xchacha.result !== "valid" || xchacha.group.ivSize !== 192) throw new Error("unexpected XChaCha vector");

const mlkem = tests(load("mlkem_768_test.json")).find((t) => t.tcId === 1);
if (mlkem.result !== "valid") throw new Error("unexpected ML-KEM vector");

const constants = [
  ["sha2_input", "616263"],
  ["sha256_digest", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
  ["sha512_digest", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"],
  ["hmac_key", hmac.key],
  ["hmac_message", hmac.msg],
  ["hmac_tag", hmac.tag],
  ["hkdf_input_key", hkdf.ikm],
  ["hkdf_salt", hkdf.salt],
  ["hkdf_info", hkdf.info],
  ["hkdf_output", hkdf.okm],
  ["x25519_secret_key", x25519.private],
  ["x25519_peer_public_key", x25519.public],
  ["x25519_shared_secret", x25519.shared],
  ["ed25519_seed", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"],
  ["ed25519_public_key", ed25519.group.publicKey.pk],
  ["ed25519_message", ed25519.msg],
  ["ed25519_signature", ed25519.sig],
  ["aead_key", xchacha.key],
  ["aead_nonce", xchacha.iv],
  ["aead_associated_data", xchacha.aad],
  ["aead_plaintext", xchacha.msg],
  ["aead_ciphertext", xchacha.ct + xchacha.tag],
  ["mlkem_key_seed", mlkem.seed],
  ["mlkem_public_key_sha256", sha256Hex(mlkem.ek)],
  ["mlkem_ciphertext", mlkem.c],
  ["mlkem_shared_secret", mlkem.K],
];

const declare = ([name, hex]) =>
  hex === ""
    ? `inline constexpr std::string_view ${name}{};`
    : `inline constexpr std::string_view ${name} =\n    "${hex.match(/.{1,96}/g).join('"\n    "')}";`;

const body = constants.map(declare).join("\n\n");

writeFileSync(
  outputFile,
  `// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include <string_view>

namespace lume::crypto::known_answers {

${body}

}
`,
);
console.log(`wrote ${constants.length} constants`);
