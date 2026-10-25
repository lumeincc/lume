// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/identity/identity.hpp"

#include "lume/crypto/encoding.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/identity/phrase.hpp"

#include <expected>
#include <string_view>
#include <utility>

namespace lume::identity {
namespace {

using crypto::ByteView;
using crypto::SecretBytes;

constexpr std::size_t derived_key_size = 32;
constexpr crypto::ByteArray<derived_key_size> zero_salt{};

constexpr std::string_view salt_label = "identity/salt";
constexpr std::string_view root_label = "identity/root";
constexpr std::string_view signing_label = "identity/ed25519";
constexpr std::string_view exchange_label = "identity/x25519";
constexpr std::string_view binding_label = "identity/bind";
constexpr std::string_view device_label = "device";

static_assert(crypto::ed25519_seed_size == derived_key_size);
static_assert(crypto::x25519_key_size == derived_key_size);

crypto::Result<SecretBytes> expand(const SecretBytes& root, std::string_view name)
{
    return crypto::hkdf_sha256(zero_salt, root.view(), crypto::label(name), derived_key_size);
}

crypto::Bytes binding_message(ByteView signing_key, ByteView exchange_key)
{
    return crypto::Encoder{}.label(binding_label).raw(signing_key).raw(exchange_key).take();
}

crypto::Bytes device_message(ByteView device_key, std::uint32_t generation)
{
    return crypto::Encoder{}.label(device_label).raw(device_key).u32(generation).take();
}

}

PublicIdentity public_identity(const Identity& identity)
{
    return PublicIdentity{
        .signing_key = identity.signing.public_key,
        .exchange_key = identity.exchange.public_key,
        .binding = identity.binding};
}

crypto::Result<Identity> derive_identity(const SecretBytes& entropy)
{
    if (entropy.size() != entropy_size) {
        return std::unexpected(crypto::Error::invalid_size);
    }
    const auto root =
        crypto::hkdf_sha256(crypto::label(salt_label), entropy.view(), crypto::label(root_label), derived_key_size);
    if (!root) {
        return std::unexpected(root.error());
    }
    auto signing_seed = expand(*root, signing_label);
    if (!signing_seed) {
        return std::unexpected(signing_seed.error());
    }
    auto exchange_secret = expand(*root, exchange_label);
    if (!exchange_secret) {
        return std::unexpected(exchange_secret.error());
    }
    auto signing = crypto::ed25519_from_seed(std::move(*signing_seed));
    if (!signing) {
        return std::unexpected(signing.error());
    }
    auto exchange = crypto::x25519_from_secret(std::move(*exchange_secret));
    if (!exchange) {
        return std::unexpected(exchange.error());
    }
    const auto binding =
        crypto::ed25519_sign(signing->seed, binding_message(signing->public_key, exchange->public_key));
    if (!binding) {
        return std::unexpected(binding.error());
    }
    return Identity{.signing = std::move(*signing), .exchange = std::move(*exchange), .binding = *binding};
}

bool verify_binding(const PublicIdentity& identity)
{
    return crypto::ed25519_verify(
        identity.signing_key, binding_message(identity.signing_key, identity.exchange_key), identity.binding);
}

crypto::Result<DeviceCertificate> certify_device(
    const Identity& identity, ByteView device_key, std::uint32_t generation)
{
    if (device_key.size() != crypto::ed25519_public_key_size) {
        return std::unexpected(crypto::Error::invalid_size);
    }
    if (generation < first_generation) {
        return std::unexpected(crypto::Error::out_of_range);
    }
    return crypto::ed25519_sign(identity.signing.seed, device_message(device_key, generation));
}

bool verify_device_certificate(
    ByteView signing_key, ByteView device_key, std::uint32_t generation, ByteView certificate)
{
    if (device_key.size() != crypto::ed25519_public_key_size || generation < first_generation) {
        return false;
    }
    return crypto::ed25519_verify(signing_key, device_message(device_key, generation), certificate);
}

}
