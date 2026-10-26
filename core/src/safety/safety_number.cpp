// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/safety/safety_number.hpp"

#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <string>
#include <string_view>

namespace lume::safety {
namespace {

constexpr std::string_view fingerprint_label = "fingerprint";
constexpr std::string_view invite_label = "invite/fingerprint";
constexpr std::uint16_t fingerprint_version = 0;
constexpr std::size_t chunk_bytes = 5;
constexpr std::size_t chunk_digits = 5;
constexpr std::uint64_t chunk_modulus = 100000;
constexpr std::size_t bits_per_byte = 8;

static_assert(fingerprint_digits / chunk_digits * chunk_bytes <= crypto::sha512_size);

void append_chunk(std::string& digits, std::span<const std::uint8_t> chunk)
{
    std::uint64_t value = 0;
    for (const std::uint8_t byte : chunk) {
        value = (value << bits_per_byte) | byte;
    }
    value %= chunk_modulus;
    std::string group(chunk_digits, '0');
    for (char& digit : std::views::reverse(group)) {
        digit = static_cast<char>('0' + (value % 10));
        value /= 10;
    }
    digits += group;
}

}

bool same_identity(const identity::PublicIdentity& first, const identity::PublicIdentity& second)
{
    return first.signing_key == second.signing_key && first.exchange_key == second.exchange_key;
}

std::string fingerprint(const identity::PublicIdentity& identity)
{
    const auto start = crypto::Encoder{}
                           .u16(fingerprint_version)
                           .label(fingerprint_label)
                           .raw(identity.signing_key)
                           .raw(identity.exchange_key)
                           .take();
    auto digest = crypto::sha512(start);
    for (std::uint32_t round = 1; round < fingerprint_iterations; ++round) {
        digest = crypto::sha512({digest, identity.signing_key, identity.exchange_key});
    }

    std::string digits;
    digits.reserve(fingerprint_digits);
    const std::span<const std::uint8_t> hash(digest);
    for (std::size_t offset = 0; digits.size() < fingerprint_digits; offset += chunk_bytes) {
        append_chunk(digits, hash.subspan(offset, chunk_bytes));
    }
    return digits;
}

std::string safety_number(const identity::PublicIdentity& first, const identity::PublicIdentity& second)
{
    const bool first_is_lower = std::ranges::lexicographical_compare(first.signing_key, second.signing_key)
        || first.signing_key == second.signing_key;
    const auto& lower = first_is_lower ? first : second;
    const auto& higher = first_is_lower ? second : first;
    return fingerprint(lower) + fingerprint(higher);
}

InviteFingerprint invite_fingerprint(const identity::PublicIdentity& identity)
{
    const auto digest = crypto::sha256({crypto::label(invite_label), identity.signing_key, identity.exchange_key});
    InviteFingerprint prefix{};
    std::ranges::copy(std::span(digest).first<invite_fingerprint_size>(), prefix.begin());
    return prefix;
}

bool matches_invite(const identity::PublicIdentity& identity, crypto::ByteView fingerprint)
{
    return std::ranges::equal(invite_fingerprint(identity), fingerprint);
}

}
