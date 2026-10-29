// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/directory/directory.hpp"
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
    wrong_group,
    wrong_member,
    invalid_signature,
    invalid_keys,
    identity_changed,
    generation_went_down,
    outlives_its_keys,
    not_the_owner,
    library_failure,
};

template <typename T>
using Result = std::expected<T, Error>;

using SigningKey = crypto::ByteArray<wire::ed25519_key_size>;
using GroupId = crypto::ByteArray<wire::group_id_size>;

struct Expected {
    SigningKey recipient{};
    GroupId group_id{};
    SigningKey member{};
};

struct CheckedCard {
    handshake::Bundle bundle;
    bool name_verified = false;
};

[[nodiscard]] crypto::Bytes card_message(const SigningKey& recipient, const wire::Card& card);

[[nodiscard]] Result<wire::Card> sign_card(
    const identity::Identity& owner, wire::Card card, const SigningKey& recipient, std::uint64_t now);

[[nodiscard]] Result<CheckedCard> check_card(
    const wire::Card& card, const Expected& expected, std::uint64_t now, const std::optional<handshake::Pin>& pinned,
    const directory::Directory& names);

}
