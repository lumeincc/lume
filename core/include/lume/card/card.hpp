// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/error.hpp"
#include "lume/handshake/handshake.hpp"
#include "lume/identity/identity.hpp"
#include "lume/wire/structures.hpp"

#include <cstdint>
#include <expected>
#include <optional>

namespace lume::card {

inline constexpr std::uint64_t day = std::uint64_t{24} * 60 * 60;
inline constexpr std::uint64_t card_lifetime = 7 * day;

enum class Error : std::uint8_t {
    expired,
    bad_lifetime,
    invalid_signature,
    outlives_its_keys,
    identity_changed,
    generation_went_down,
    invalid_keys,
};

template <typename T>
using Result = std::expected<T, Error>;

[[nodiscard]] crypto::Bytes card_message(crypto::ByteView recipient_ik_sig, const wire::Card& card);

[[nodiscard]] crypto::Result<wire::Card> sign_card(
    const identity::Identity& owner, wire::Card card, crypto::ByteView recipient_ik_sig);

[[nodiscard]] Result<handshake::Bundle> check_card(
    const wire::Card& card, crypto::ByteView recipient_ik_sig, std::uint64_t now,
    const std::optional<handshake::Pin>& pinned);

}
