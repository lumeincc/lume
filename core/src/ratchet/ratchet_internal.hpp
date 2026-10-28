// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/ratchet/ratchet.hpp"

#include <cstdint>
#include <functional>
#include <span>

namespace lume::ratchet::detail {

using RandomSource = std::function<void(std::span<std::uint8_t>)>;

[[nodiscard]] Result<State> start_as_alice(
    const handshake::SessionKeys& keys, crypto::ByteView peer_ratchet_key, const RandomSource& random);

[[nodiscard]] Result<wire::RatchetMessage> encrypt(
    State& state, crypto::ByteView plaintext, const RandomSource& random);

[[nodiscard]] Result<crypto::SecretBytes> decrypt(
    State& state, const wire::RatchetMessage& message, std::uint64_t now, const RandomSource& random);

}
