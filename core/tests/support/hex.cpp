// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "support/hex.hpp"

#include <sodium.h>

namespace lume::test {

std::optional<crypto::Bytes> decode_hex(std::string_view hex)
{
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    crypto::Bytes bytes(hex.size() / 2);
    if (hex.empty()) {
        return bytes;
    }
    std::size_t written = 0;
    if (sodium_hex2bin(bytes.data(), bytes.size(), hex.data(), hex.size(), nullptr, &written, nullptr) != 0
        || written != bytes.size()) {
        return std::nullopt;
    }
    return bytes;
}

std::string encode_hex(crypto::ByteView bytes)
{
    std::string hex((bytes.size() * 2) + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), bytes.data(), bytes.size());
    hex.pop_back();
    return hex;
}

}
