// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, hkdfSync, sign } from "node:crypto";

const [wordlistFile, trezorFile, outputFile] = process.argv.slice(2);

const words = readFileSync(wordlistFile, "ascii").split("\n").filter((line) => line !== "");
if (words.length !== 2048) throw new Error("the wordlist must have 2048 words");

const sha256 = (data) => createHash("sha256").update(data).digest();
const u32 = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
};
const lengthPrefixed = (bytes) => Buffer.concat([u32(bytes.length), bytes]);
const label = (name) => lengthPrefixed(Buffer.from(`LUME/v1/${name}`, "ascii"));
const hkdf = (salt, inputKey, info) => Buffer.from(hkdfSync("sha256", inputKey, salt, info, 32));
const zeroSalt = Buffer.alloc(32);

const pkcs8 = (prefix, key) => createPrivateKey({ key: Buffer.concat([Buffer.from(prefix, "hex"), key]), format: "der", type: "pkcs8" });
const ed25519Key = (seed) => pkcs8("302e020100300506032b657004220420", seed);
const x25519Key = (secret) => pkcs8("302e020100300506032b656e04220420", secret);
const rawPublicKey = (privateKey) => createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);

const phraseOf = (entropy) => {
  const bits = [...entropy, sha256(entropy)[0]].map((byte) => byte.toString(2).padStart(8, "0")).join("");
  return bits.match(/.{11}/g).map((chunk) => words[parseInt(chunk, 2)]).join(" ");
};

const trezor = JSON.parse(readFileSync(trezorFile, "utf8")).english.filter(([entropy]) => entropy.length === 64);
if (trezor.length !== 8) throw new Error("expected eight 24-word Trezor vectors");
for (const [entropy, mnemonic] of trezor) {
  if (phraseOf(Buffer.from(entropy, "hex")) !== mnemonic) throw new Error(`phrase mismatch for ${entropy}`);
}

const entropies = [
  Buffer.alloc(32, 0x00),
  Buffer.alloc(32, 0xff),
  Buffer.alloc(32, 0x7f),
  ...[1, 2, 3, 4, 5].map((index) => sha256(`LUME identity vector ${index}`)),
];
const generations = [1, 2, 0xffffffff];

const cases = entropies.map((entropy, index) => {
  const root = hkdf(label("identity/salt"), entropy, label("identity/root"));
  const signingSeed = hkdf(zeroSalt, root, label("identity/ed25519"));
  const signingKey = ed25519Key(signingSeed);
  const signingPublic = rawPublicKey(signingKey);
  const exchangeSecret = hkdf(zeroSalt, root, label("identity/x25519"));
  const exchangePublic = rawPublicKey(x25519Key(exchangeSecret));
  const binding = sign(null, Buffer.concat([label("identity/bind"), signingPublic, exchangePublic]), signingKey);
  const deviceSeed = sha256(`LUME device vector ${index + 1}`);
  const deviceKey = rawPublicKey(ed25519Key(deviceSeed));
  return {
    entropy: entropy.toString("hex"),
    phrase: phraseOf(entropy),
    root: root.toString("hex"),
    signing_seed: signingSeed.toString("hex"),
    signing_key: signingPublic.toString("hex"),
    exchange_secret: exchangeSecret.toString("hex"),
    exchange_key: exchangePublic.toString("hex"),
    binding: binding.toString("hex"),
    device_seed: deviceSeed.toString("hex"),
    device_key: deviceKey.toString("hex"),
    certificates: generations.map((generation) => ({
      generation,
      certificate: sign(null, Buffer.concat([label("device"), deviceKey, u32(generation)]), signingKey).toString("hex"),
    })),
  };
});

const document = {
  description: "LUME identity derivation, CRYPTO.md sections 3.1 to 3.3, computed with Node.js crypto (OpenSSL)",
  generator: "core/tools/generate_identity_vectors.mjs",
  cases,
};
writeFileSync(outputFile, JSON.stringify(document, null, 2) + "\n");
console.log(`wrote ${cases.length} identity cases`);
