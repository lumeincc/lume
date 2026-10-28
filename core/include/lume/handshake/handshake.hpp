// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/mlkem.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/crypto/x25519.hpp"
#include "lume/identity/identity.hpp"
#include "lume/wire/structures.hpp"

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>

namespace lume::handshake {

enum class Error : std::uint8_t {
    invalid_binding,
    identity_changed,
    invalid_prekey,
    prekey_not_usable,
    weak_key,
    invalid_kem_key,
    unknown_prekey,
    non_canonical_key,
    library_failure,
    generation_went_down,
};

template <typename T>
using Result = std::expected<T, Error>;

struct Pin {
    identity::PublicIdentity identity{};
    std::uint32_t generation = 0;
};

struct Bundle {
    identity::PublicIdentity identity{};
    std::uint32_t generation = 0;
    wire::PrekeyX signed_prekey;
    wire::PrekeyKem kem_prekey;
    wire::PrekeyX seal_key;
    std::optional<wire::PrekeyX> one_time_prekey;
};

struct SessionKeys {
    crypto::SecretBytes root_key;
    crypto::SecretBytes header_key_alice;
    crypto::SecretBytes next_header_key_bob;
    crypto::Bytes associated_data;
};

struct Initiation {
    SessionKeys keys;
    wire::InitialHeader header;
    crypto::ByteArray<crypto::x25519_key_size> peer_ratchet_key{};
};

struct ResponderKeys {
    std::uint32_t signed_prekey_id = 0;
    std::reference_wrapper<const crypto::X25519KeyPair> signed_prekey;
    wire::PrekeyKind kem_kind = wire::PrekeyKind::kem_last_resort;
    std::uint32_t kem_id = 0;
    std::reference_wrapper<const crypto::MlKemKeyPair> kem_prekey;
    std::optional<std::uint32_t> one_time_prekey_id;
    std::optional<std::reference_wrapper<const crypto::X25519KeyPair>> one_time_prekey;
};

[[nodiscard]] Result<void> check_bundle(const Bundle& bundle, const std::optional<Pin>& pinned, std::uint64_t now);

[[nodiscard]] Result<Initiation> initiate(
    const identity::Identity& alice, const Bundle& bob, const std::optional<Pin>& pinned, std::uint64_t now);

[[nodiscard]] Result<identity::PublicIdentity> initiator_of(
    const wire::InitialHeader& header, const std::optional<identity::PublicIdentity>& pinned);

[[nodiscard]] Result<SessionKeys> respond(
    const identity::Identity& bob, const wire::InitialHeader& header, const ResponderKeys& keys,
    const std::optional<identity::PublicIdentity>& pinned);

[[nodiscard]] crypto::ByteArray<crypto::sha256_size> replay_tag(const wire::InitialHeader& header);

}
