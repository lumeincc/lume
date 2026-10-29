// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/identity/identity.hpp"
#include "lume/wire/structures.hpp"

#include <cstdint>

namespace lume::handshake {

inline constexpr std::uint64_t allowed_clock_skew = std::uint64_t{5} * 60;
inline constexpr std::uint64_t rotating_key_usable_for = std::uint64_t{9} * 24 * 60 * 60;

struct PrekeyFacts {
    wire::PrekeyKind kind = wire::PrekeyKind::signed_prekey;
    std::uint32_t id = 0;
    std::uint64_t created_at = 0;
    std::uint32_t generation = 0;
};

[[nodiscard]] crypto::Bytes prekey_message(const PrekeyFacts& facts, crypto::ByteView public_key);

[[nodiscard]] crypto::Result<wire::PrekeyX> make_prekey_x(
    const identity::Identity& owner, const PrekeyFacts& facts, crypto::ByteView public_key);

[[nodiscard]] crypto::Result<wire::PrekeyKem> make_prekey_kem(
    const identity::Identity& owner, const PrekeyFacts& facts, crypto::ByteView public_key);

[[nodiscard]] bool verify_prekey(crypto::ByteView signing_key, const wire::PrekeyX& prekey, std::uint32_t generation);

[[nodiscard]] bool verify_prekey(crypto::ByteView signing_key, const wire::PrekeyKem& prekey, std::uint32_t generation);

[[nodiscard]] bool is_rotating(wire::PrekeyKind kind) noexcept;

[[nodiscard]] bool is_usable_at(wire::PrekeyKind kind, std::uint64_t created_at, std::uint64_t now) noexcept;

[[nodiscard]] bool is_usable_at(
    wire::PrekeyKind kind, std::uint64_t created_at, std::uint64_t now, std::uint64_t usable_for) noexcept;

}
