// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/x25519.hpp"
#include "lume/handshake/handshake.hpp"
#include "lume/wire/structures.hpp"

#include <cstdint>
#include <expected>

namespace lume::seal {

enum class Error : std::uint8_t {
    too_long,
    not_a_seal_key,
    generation_went_down,
    invalid_signature,
    generation_went_up,
    key_not_usable,
    wrong_key,
    weak_key,
    authentication_failed,
    malformed,
    library_failure,
};

template <typename T>
using Result = std::expected<T, Error>;

struct Recipient {
    handshake::Pin pin;
    std::uint32_t generation = 0;
    wire::PrekeyX seal_key;
};

[[nodiscard]] Result<wire::Seal> seal(const Recipient& recipient, const wire::Inner& inner, std::uint64_t now);

[[nodiscard]] Result<wire::Inner> open(
    std::uint32_t seal_key_id, const crypto::X25519KeyPair& seal_key, const wire::Seal& envelope);

}
