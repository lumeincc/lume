// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

const MASK64 = (1n << 64n) - 1n;
const IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const rotr64 = (x, n) => ((x >> n) | (x << (64n - n))) & MASK64;

export const blake2b = (input, outputLength) => {
  if (outputLength < 1 || outputLength > 64) throw new Error("BLAKE2b output length must be 1 to 64 bytes");
  const h = IV.slice();
  h[0] ^= 0x01010000n ^ BigInt(outputLength);
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  for (let index = 0; index < blocks; index += 1) {
    const block = Buffer.alloc(128);
    input.copy(block, 0, index * 128, Math.min(input.length, (index + 1) * 128));
    const m = Array.from({ length: 16 }, (_, word) => block.readBigUInt64LE(word * 8));
    const last = index === blocks - 1;
    const counter = BigInt(last ? input.length : (index + 1) * 128);
    const v = [...h, ...IV];
    v[12] ^= counter & MASK64;
    v[13] ^= counter >> 64n;
    if (last) v[14] ^= MASK64;
    const g = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + x) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 24n);
      v[a] = (v[a] + v[b] + y) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 63n);
    };
    for (let round = 0; round < 12; round += 1) {
      const s = SIGMA[round % 10];
      g(0, 4, 8, 12, m[s[0]], m[s[1]]);
      g(1, 5, 9, 13, m[s[2]], m[s[3]]);
      g(2, 6, 10, 14, m[s[4]], m[s[5]]);
      g(3, 7, 11, 15, m[s[6]], m[s[7]]);
      g(0, 5, 10, 15, m[s[8]], m[s[9]]);
      g(1, 6, 11, 12, m[s[10]], m[s[11]]);
      g(2, 7, 8, 13, m[s[12]], m[s[13]]);
      g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let word = 0; word < 8; word += 1) h[word] ^= v[word] ^ v[word + 8];
  }
  const out = Buffer.alloc(64);
  h.forEach((word, position) => out.writeBigUInt64LE(word, position * 8));
  return out.subarray(0, outputLength);
};

const le32 = (value) => {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
};

const variableHash = (input, length) => {
  const prefixed = Buffer.concat([le32(length), input]);
  if (length <= 64) return blake2b(prefixed, length);
  const rounds = Math.ceil(length / 32) - 2;
  const parts = [];
  let value = blake2b(prefixed, 64);
  parts.push(value.subarray(0, 32));
  for (let step = 1; step < rounds; step += 1) {
    value = blake2b(value, 64);
    parts.push(value.subarray(0, 32));
  }
  parts.push(blake2b(value, length - 32 * rounds));
  return Buffer.concat(parts);
};

const WORDS = 256;
const TWO32 = 4294967296;

const mixMultiply = (v, a, b) => {
  const al = v[2 * a];
  const ah = v[2 * a + 1];
  const bl = v[2 * b];
  const bh = v[2 * b + 1];
  const a0 = al & 0xffff;
  const a1 = al >>> 16;
  const b0 = bl & 0xffff;
  const b1 = bl >>> 16;
  const middle = a0 * b1 + a1 * b0;
  const lowFull = a0 * b0 + (middle % 65536) * 65536;
  let productLow = lowFull >>> 0;
  let productHigh = (a1 * b1 + Math.floor(middle / 65536) + Math.floor(lowFull / TWO32)) >>> 0;
  productHigh = ((productHigh << 1) | (productLow >>> 31)) >>> 0;
  productLow = (productLow << 1) >>> 0;
  const low = al + bl + productLow;
  v[2 * a] = low >>> 0;
  v[2 * a + 1] = (ah + bh + productHigh + Math.floor(low / TWO32)) >>> 0;
};

const xorRotate = (v, d, a, n) => {
  const low = (v[2 * d] ^ v[2 * a]) >>> 0;
  const high = (v[2 * d + 1] ^ v[2 * a + 1]) >>> 0;
  if (n === 32) {
    v[2 * d] = high;
    v[2 * d + 1] = low;
  } else if (n < 32) {
    v[2 * d] = ((low >>> n) | (high << (32 - n))) >>> 0;
    v[2 * d + 1] = ((high >>> n) | (low << (32 - n))) >>> 0;
  } else {
    const m = n - 32;
    v[2 * d] = ((high >>> m) | (low << (32 - m))) >>> 0;
    v[2 * d + 1] = ((low >>> m) | (high << (32 - m))) >>> 0;
  }
};

const mix = (v, a, b, c, d) => {
  mixMultiply(v, a, b);
  xorRotate(v, d, a, 32);
  mixMultiply(v, c, d);
  xorRotate(v, b, c, 24);
  mixMultiply(v, a, b);
  xorRotate(v, d, a, 16);
  mixMultiply(v, c, d);
  xorRotate(v, b, c, 63);
};

const permute = (v, w) => {
  mix(v, w[0], w[4], w[8], w[12]);
  mix(v, w[1], w[5], w[9], w[13]);
  mix(v, w[2], w[6], w[10], w[14]);
  mix(v, w[3], w[7], w[11], w[15]);
  mix(v, w[0], w[5], w[10], w[15]);
  mix(v, w[1], w[6], w[11], w[12]);
  mix(v, w[2], w[7], w[8], w[13]);
  mix(v, w[3], w[4], w[9], w[14]);
};

const ROWS = Array.from({ length: 8 }, (_, row) => Array.from({ length: 16 }, (_, word) => 16 * row + word));
const COLUMNS = Array.from({ length: 8 }, (_, column) =>
  Array.from({ length: 16 }, (_, word) => 2 * column + 16 * Math.floor(word / 2) + (word % 2)));

const scratchR = new Uint32Array(WORDS);
const scratchQ = new Uint32Array(WORDS);

const compress = (previous, previousOffset, reference, referenceOffset, output, outputOffset, withXor) => {
  for (let k = 0; k < WORDS; k += 1) scratchR[k] = previous[previousOffset + k] ^ reference[referenceOffset + k];
  scratchQ.set(scratchR);
  for (const row of ROWS) permute(scratchQ, row);
  for (const column of COLUMNS) permute(scratchQ, column);
  for (let k = 0; k < WORDS; k += 1) {
    const value = scratchQ[k] ^ scratchR[k];
    output[outputOffset + k] = withXor ? output[outputOffset + k] ^ value : value;
  }
};

const loadBlock = (bytes, memory, offset) => {
  for (let k = 0; k < WORDS; k += 1) memory[offset + k] = bytes.readUInt32LE(4 * k);
};

export const argon2id = ({ password, salt, secret = Buffer.alloc(0), associatedData = Buffer.alloc(0), passes, memoryKiB, lanes = 1, tagLength = 32 }) => {
  const version = 0x13;
  const type = 2;
  const h0 = blake2b(Buffer.concat([
    le32(lanes), le32(tagLength), le32(memoryKiB), le32(passes), le32(version), le32(type),
    le32(password.length), password, le32(salt.length), salt, le32(secret.length), secret,
    le32(associatedData.length), associatedData,
  ]), 64);
  const blockCount = 4 * lanes * Math.floor(memoryKiB / (4 * lanes));
  const laneLength = blockCount / lanes;
  const segmentLength = laneLength / 4;
  const memory = new Uint32Array(blockCount * WORDS);
  const offsetOf = (lane, column) => (lane * laneLength + column) * WORDS;
  for (let lane = 0; lane < lanes; lane += 1) {
    loadBlock(variableHash(Buffer.concat([h0, le32(0), le32(lane)]), 1024), memory, offsetOf(lane, 0));
    loadBlock(variableHash(Buffer.concat([h0, le32(1), le32(lane)]), 1024), memory, offsetOf(lane, 1));
  }
  const zero = new Uint32Array(WORDS);
  const input = new Uint32Array(WORDS);
  const addresses = new Uint32Array(WORDS);
  const nextAddresses = () => {
    input[12] = (input[12] + 1) >>> 0;
    compress(zero, 0, input, 0, addresses, 0, false);
    compress(zero, 0, addresses, 0, addresses, 0, false);
  };
  for (let pass = 0; pass < passes; pass += 1) {
    for (let slice = 0; slice < 4; slice += 1) {
      for (let lane = 0; lane < lanes; lane += 1) {
        const independent = pass === 0 && slice < 2;
        if (independent) {
          input.fill(0);
          input[0] = pass;
          input[2] = lane;
          input[4] = slice;
          input[6] = blockCount;
          input[8] = passes;
          input[10] = type;
        }
        let start = 0;
        if (pass === 0 && slice === 0) {
          start = 2;
          if (independent) nextAddresses();
        }
        for (let index = start; index < segmentLength; index += 1) {
          const column = slice * segmentLength + index;
          const previousColumn = column === 0 ? laneLength - 1 : column - 1;
          const previousOffset = offsetOf(lane, previousColumn);
          let j1;
          let j2;
          if (independent) {
            if (index % 128 === 0) nextAddresses();
            j1 = addresses[2 * (index % 128)];
            j2 = addresses[2 * (index % 128) + 1];
          } else {
            j1 = memory[previousOffset];
            j2 = memory[previousOffset + 1];
          }
          const referenceLane = pass === 0 && slice === 0 ? lane : j2 % lanes;
          const sameLane = referenceLane === lane;
          let areaSize;
          if (pass === 0) {
            if (slice === 0) areaSize = index - 1;
            else if (sameLane) areaSize = slice * segmentLength + index - 1;
            else areaSize = slice * segmentLength + (index === 0 ? -1 : 0);
          } else if (sameLane) {
            areaSize = laneLength - segmentLength + index - 1;
          } else {
            areaSize = laneLength - segmentLength + (index === 0 ? -1 : 0);
          }
          const x = (BigInt(j1) * BigInt(j1)) >> 32n;
          const relative = BigInt(areaSize) - 1n - ((BigInt(areaSize) * x) >> 32n);
          const startPosition = pass === 0 || slice === 3 ? 0 : (slice + 1) * segmentLength;
          const referenceColumn = Number((BigInt(startPosition) + relative) % BigInt(laneLength));
          compress(memory, previousOffset, memory, offsetOf(referenceLane, referenceColumn), memory, offsetOf(lane, column), pass > 0);
        }
      }
    }
  }
  const final = new Uint32Array(WORDS);
  for (let lane = 0; lane < lanes; lane += 1) {
    const offset = offsetOf(lane, laneLength - 1);
    for (let k = 0; k < WORDS; k += 1) final[k] ^= memory[offset + k];
  }
  const finalBytes = Buffer.alloc(1024);
  for (let k = 0; k < WORDS; k += 1) finalBytes.writeUInt32LE(final[k], 4 * k);
  return variableHash(finalBytes, tagLength);
};

export const checkAgainstRfc9106 = () => {
  const tag = argon2id({
    password: Buffer.alloc(32, 0x01), salt: Buffer.alloc(16, 0x02), secret: Buffer.alloc(8, 0x03),
    associatedData: Buffer.alloc(12, 0x04), passes: 3, memoryKiB: 32, lanes: 4, tagLength: 32,
  });
  if (tag.toString("hex") !== "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659") {
    throw new Error("the Argon2id implementation does not reproduce RFC 9106 section 5.3");
  }
};
