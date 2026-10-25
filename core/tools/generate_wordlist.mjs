// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const pinnedSha256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
const wordsPerLine = 8;

const [wordlistFile, outputFile] = process.argv.slice(2);
const text = readFileSync(wordlistFile);
const digest = createHash("sha256").update(text).digest("hex");
if (digest !== pinnedSha256) throw new Error(`wordlist sha256 is ${digest}, expected ${pinnedSha256}`);

const words = text.toString("ascii").split("\n").filter((line) => line !== "");
if (words.length !== 2048) throw new Error(`expected 2048 words, found ${words.length}`);
if (!words.every((word) => /^[a-z]{3,8}$/.test(word))) throw new Error("a word is not 3 to 8 letters a-z");
if (!words.every((word, index) => index === 0 || words[index - 1] < word)) throw new Error("words are not sorted");
if (new Set(words.map((word) => word.slice(0, 4))).size !== words.length) throw new Error("prefixes are not unique");

const longest = Math.max(...words.map((word) => word.length));
const lines = [];
for (let start = 0; start < words.length; start += wordsPerLine) {
  lines.push("    " + words.slice(start, start + wordsPerLine).map((word) => `"${word}"`).join(", ") + ",");
}

const spdx = (tag, value) => `// SPDX-${tag}: ${value}`;

writeFileSync(
  outputFile,
  `${spdx("FileCopyrightText", "2013 Marek Palatinus, Pavol Rusnak, Aaron Voisine, Sean Bowe")}
${spdx("FileCopyrightText", "2026 LUME Inc.")}
${spdx("License-Identifier", "MIT AND AGPL-3.0-only")}

#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace lume::identity::detail {

inline constexpr std::size_t longest_word = ${longest};

inline constexpr std::array<std::string_view, ${words.length}> words{
${lines.join("\n")}
};

}
`,
);
console.log(`wrote ${words.length} words`);
