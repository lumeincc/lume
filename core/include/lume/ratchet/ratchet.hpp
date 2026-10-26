// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/aead.hpp"
#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/crypto/x25519.hpp"
#include "lume/handshake/handshake.hpp"
#include "lume/wire/structures.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace lume::ratchet {

inline constexpr std::uint32_t max_skip = 256;
inline constexpr std::size_t max_skipped_keys = 1024;
inline constexpr std::size_t max_skipped_header_keys = 8;
inline constexpr std::uint64_t skipped_key_lifetime = std::uint64_t{14} * 24 * 60 * 60;
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

struct SkippedKey {
    crypto::SecretBytes header_key;
    crypto::ByteArray<crypto::x25519_key_size> ratchet_key{};
    std::uint32_t number = 0;
    crypto::SecretBytes message_key;
    std::uint64_t stored_at = 0;
};

struct State {
    crypto::X25519KeyPair sending_ratchet;
    std::optional<crypto::ByteArray<crypto::x25519_key_size>> receiving_ratchet;
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
    std::vector<SkippedKey> skipped;
    crypto::Bytes associated_data;
    bool has_received = false;
};

[[nodiscard]] State clone(const State& state);

[[nodiscard]] Result<State> start_as_alice(
    const handshake::SessionKeys& keys, crypto::ByteView peer_ratchet_key);

[[nodiscard]] State start_as_bob(const handshake::SessionKeys& keys, const crypto::X25519KeyPair& signed_prekey);

[[nodiscard]] Result<wire::RatchetMessage> encrypt(State& state, crypto::ByteView plaintext);

[[nodiscard]] Result<crypto::SecretBytes> decrypt(
    State& state, const wire::RatchetMessage& message, std::uint64_t now);

namespace detail {

using RandomSource = std::function<void(std::span<std::uint8_t>)>;

[[nodiscard]] Result<State> start_as_alice(
    const handshake::SessionKeys& keys, crypto::ByteView peer_ratchet_key, const RandomSource& random);

[[nodiscard]] Result<wire::RatchetMessage> encrypt(
    State& state, crypto::ByteView plaintext, const RandomSource& random);

[[nodiscard]] Result<crypto::SecretBytes> decrypt(
    State& state, const wire::RatchetMessage& message, std::uint64_t now, const RandomSource& random);

}

}
