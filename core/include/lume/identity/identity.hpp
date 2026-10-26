// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/error.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/crypto/x25519.hpp"

#include <cstddef>
#include <cstdint>

namespace lume::identity {

inline constexpr std::uint32_t first_generation = 1;
inline constexpr std::size_t binding_size = crypto::ed25519_signature_size;
inline constexpr std::size_t device_certificate_size = crypto::ed25519_signature_size;

using Binding = crypto::ByteArray<binding_size>;
using DeviceCertificate = crypto::ByteArray<device_certificate_size>;

struct PublicIdentity {
    crypto::ByteArray<crypto::ed25519_public_key_size> signing_key;
    crypto::ByteArray<crypto::x25519_key_size> exchange_key;
    Binding binding;
};

struct Identity {
    crypto::Ed25519KeyPair signing;
    crypto::X25519KeyPair exchange;
    Binding binding;
};

[[nodiscard]] PublicIdentity public_identity(const Identity& identity);

[[nodiscard]] crypto::Result<Identity> derive_identity(const crypto::SecretBytes& entropy);

[[nodiscard]] bool verify_binding(const PublicIdentity& identity);

[[nodiscard]] crypto::Result<DeviceCertificate> certify_device(
    const Identity& identity, crypto::ByteView device_key, std::uint32_t generation);

[[nodiscard]] bool verify_device_certificate(
    crypto::ByteView signing_key, crypto::ByteView device_key, std::uint32_t generation,
    crypto::ByteView certificate);

}
