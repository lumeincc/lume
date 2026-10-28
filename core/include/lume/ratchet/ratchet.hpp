// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/aead.hpp"
#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/crypto/x25519.hpp"
#include "lume/handshake/handshake.hpp"
#include "lume/ratchet/skipped_keys.hpp"
#include "lume/wire/structures.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>

namespace lume::ratchet {

inline constexpr std::uint32_t max_skip = 256;
inline constexpr std::size_t max_skipped_keys_in_a_request = 32;
inline constexpr std::size_t max_plaintext_size =
    wire::ratchet_body_bound - crypto::aead_overhead;

enum class Error : std::uint8_t {
    cannot_send,
    message_too_large,
    unknown_header,
    old_or_duplicate,
    too_many_skipped,
    authentication_failed,
    weak_key,
    exhausted,
    library_failure,
};

template <typename T>
using Result = std::expected<T, Error>;

struct State {
    crypto::X25519KeyPair sending_ratchet;
    std::optional<RatchetKey> receiving_ratchet;
    crypto::SecretBytes root_key;
    std::optional<crypto::SecretBytes> sending_chain;
    std::optional<crypto::SecretBytes> receiving_chain;
    std::optional<crypto::SecretBytes> sending_header_key;
    std::optional<crypto::SecretBytes> receiving_header_key;
    crypto::SecretBytes next_sending_header_key;
    crypto::SecretBytes next_receiving_header_key;
    std::uint32_t sent = 0;
    std::uint32_t received = 0;
    std::uint32_t previous_sent = 0;
    SkippedKeys skipped;
    crypto::Bytes associated_data;
    bool has_received = false;
};

[[nodiscard]] State clone(const State& state);

[[nodiscard]] Result<State> start_as_alice(
    const handshake::SessionKeys& keys, crypto::ByteView peer_ratchet_key);

[[nodiscard]] State start_as_bob(const handshake::SessionKeys& keys, const crypto::X25519KeyPair& signed_prekey);

[[nodiscard]] Result<wire::RatchetMessage> encrypt(State& state, crypto::ByteView plaintext);

[[nodiscard]] Result<crypto::SecretBytes> decrypt(
    State& state, const wire::RatchetMessage& message, std::uint64_t now, std::size_t skipped_key_limit);

void expire(State& state, std::uint64_t now);

}
