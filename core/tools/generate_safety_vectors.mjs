// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const [identityFile, outputFile] = process.argv.slice(2);
const identities = JSON.parse(readFileSync(identityFile, "utf8")).cases.map((identity) => ({
  signing: Buffer.from(identity.signing_key, "hex"),
  exchange: Buffer.from(identity.exchange_key, "hex"),
}));

const label = (name) => {
  const text = Buffer.from(`LUME/v1/${name}`, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(text.length);
  return Buffer.concat([length, text]);
};
const hash = (algorithm, ...parts) => {
  const state = createHash(algorithm);
  for (const part of parts) state.update(part);
  return state.digest();
};

const fingerprint = ({ signing, exchange }) => {
  let digest = hash("sha512", Buffer.from([0, 0]), label("fingerprint"), signing, exchange);
  for (let round = 1; round < 5200; round += 1) digest = hash("sha512", digest, signing, exchange);
  let digits = "";
  for (let offset = 0; offset < 30; offset += 5) {
    const value = digest.readUIntBE(offset, 5) % 100000;
    digits += String(value).padStart(5, "0");
  }
  return digits;
};

const safetyNumber = (first, second) => {
  const ordered = Buffer.compare(first.signing, second.signing) <= 0 ? [first, second] : [second, first];
  return ordered.map(fingerprint).join("");
};

const inviteFingerprint = ({ signing, exchange }) =>
  hash("sha256", label("invite/fingerprint"), signing, exchange).subarray(0, 16).toString("hex");

const pairs = identities.flatMap((_, first) => {
  const next = (first + 1) % identities.length;
  return [[first, next], [next, first], [first, first]];
});

const document = {
  description: "LUME safety numbers and invite fingerprints, CRYPTO.md section 12, computed with Node.js crypto (OpenSSL) over the identities in identity.json",
  generator: "core/tools/generate_safety_vectors.mjs",
  identities: identities.map((identity, index) => ({
    identity: index,
    fingerprint: fingerprint(identity),
    invite_fingerprint: inviteFingerprint(identity),
  })),
  pairs: pairs.map(([first, second]) => ({
    first,
    second,
    safety_number: safetyNumber(identities[first], identities[second]),
  })),
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log(`wrote ${document.identities.length} fingerprints and ${document.pairs.length} safety numbers`);
