// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/seal/seal.hpp"

#include "crypto/aead_internal.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/random.hpp"
#include "lume/handshake/prekey.hpp"
#include "lume/seal/padding.hpp"
#include "seal/seal_internal.hpp"

#include <string_view>
#include <utility>

namespace lume::seal {
namespace {

using crypto::ByteView;
using crypto::Bytes;
using crypto::SecretBytes;

using Random = const detail::RandomSource*;

constexpr std::string_view key_label = "seal/key";
constexpr std::string_view associated_data_label = "seal/ad";

Result<crypto::X25519KeyPair> fresh_key_pair(Random random)
{
    if (random == nullptr) {
        return crypto::x25519_generate();
    }
    SecretBytes secret(crypto::x25519_key_size);
    (*random)(secret.writable());
    auto pair = crypto::x25519_from_secret(std::move(secret));
    if (!pair) {
        return std::unexpected(Error::library_failure);
    }
    return std::move(*pair);
}

Result<SecretBytes> envelope_key(
    const SecretBytes& secret_key, ByteView peer_key, ByteView ephemeral_key, ByteView seal_key)
{
    if (!crypto::x25519_is_canonical(peer_key)) {
        return std::unexpected(Error::weak_key);
    }
    const auto shared = crypto::x25519_shared_secret(secret_key, peer_key);
    if (!shared) {
        return std::unexpected(
            shared.error() == crypto::Error::weak_public_key ? Error::weak_key : Error::library_failure);
    }
    const auto salt = crypto::Encoder{}.raw(ephemeral_key).raw(seal_key).take();
    auto key = crypto::hkdf_sha256(salt, shared->view(), crypto::label(key_label), crypto::aead_key_size);
    if (!key) {
        return std::unexpected(Error::library_failure);
    }
    return std::move(*key);
}

Bytes associated_data(std::uint32_t seal_key_id, ByteView ephemeral_key, ByteView seal_key)
{
    return crypto::Encoder{}
        .label(associated_data_label)
        .u8(wire::seal_version)
        .u32(seal_key_id)
        .raw(ephemeral_key)
        .raw(seal_key)
        .take();
}

bool sender_is_initiator(const wire::Inner& inner)
{
    return !inner.initial || inner.initial->ik_sig == inner.sender;
}

Result<void> check_recipient(const Recipient& recipient, std::uint64_t now)
{
    const auto& key = recipient.seal_key;
    if (key.kind != wire::PrekeyKind::seal_key) {
        return std::unexpected(Error::not_a_seal_key);
    }
    if (recipient.generation < recipient.pin.generation) {
        return std::unexpected(Error::generation_went_down);
    }
    if (!handshake::verify_prekey(recipient.pin.identity.signing_key, key, recipient.generation)) {
        return std::unexpected(Error::invalid_signature);
    }
    if (recipient.generation > recipient.pin.generation) {
        return std::unexpected(Error::generation_went_up);
    }
    if (!handshake::is_usable_at(key.kind, key.created_at, now)) {
        return std::unexpected(Error::key_not_usable);
    }
    return {};
}

Result<wire::Seal> seal_with(const Recipient& recipient, const wire::Inner& inner, std::uint64_t now, Random random)
{
    if (auto checked = check_recipient(recipient, now); !checked) {
        return std::unexpected(checked.error());
    }
    if (!sender_is_initiator(inner)) {
        return std::unexpected(Error::malformed);
    }
    if (inner.message.body.size() > wire::ratchet_body_bound) {
        return std::unexpected(Error::too_long);
    }
    if (inner.initial && inner.initial->pq_kind != wire::PrekeyKind::kem_last_resort
        && inner.initial->pq_kind != wire::PrekeyKind::kem_one_time) {
        return std::unexpected(Error::malformed);
    }
    const auto& seal_key = recipient.seal_key;
    const auto padded = pad(wire::encode(inner));
    if (!padded) {
        return std::unexpected(Error::too_long);
    }
    auto ephemeral = fresh_key_pair(random);
    if (!ephemeral) {
        return std::unexpected(ephemeral.error());
    }
    const auto key = envelope_key(ephemeral->secret_key, seal_key.key, ephemeral->public_key, seal_key.key);
    if (!key) {
        return std::unexpected(key.error());
    }
    wire::Seal envelope;
    envelope.ssk_id = seal_key.id;
    envelope.ephemeral_key = ephemeral->public_key;
    if (random == nullptr) {
        crypto::random_fill(envelope.nonce);
    } else {
        (*random)(envelope.nonce);
    }
    auto box = crypto::detail::aead_encrypt(
        *key, envelope.nonce, associated_data(envelope.ssk_id, envelope.ephemeral_key, seal_key.key), *padded);
    if (!box) {
        return std::unexpected(Error::library_failure);
    }
    envelope.box = std::move(*box);
    return envelope;
}

}

Result<wire::Seal> seal(const Recipient& recipient, const wire::Inner& inner, std::uint64_t now)
{
    return seal_with(recipient, inner, now, nullptr);
}

Result<wire::Inner> open(std::uint32_t seal_key_id, const crypto::X25519KeyPair& seal_key, const wire::Seal& envelope)
{
    if (envelope.ssk_id != seal_key_id) {
        return std::unexpected(Error::wrong_key);
    }
    const auto key =
        envelope_key(seal_key.secret_key, envelope.ephemeral_key, envelope.ephemeral_key, seal_key.public_key);
    if (!key) {
        return std::unexpected(key.error());
    }
    const auto padded = crypto::detail::aead_decrypt(
        *key, envelope.nonce, associated_data(seal_key_id, envelope.ephemeral_key, seal_key.public_key),
        envelope.box);
    if (!padded) {
        return std::unexpected(Error::authentication_failed);
    }
    return detail::inner_of(padded->view());
}

namespace detail {

Result<wire::Seal> seal(
    const Recipient& recipient, const wire::Inner& inner, std::uint64_t now, const RandomSource& random)
{
    return seal_with(recipient, inner, now, &random);
}

Result<wire::Inner> inner_of(ByteView padded)
{
    const auto message = unpad(padded);
    if (!message) {
        return std::unexpected(Error::authentication_failed);
    }
    auto inner = wire::decode(*message, wire::read_inner);
    if (!inner || !sender_is_initiator(*inner)) {
        return std::unexpected(Error::malformed);
    }
    return std::move(*inner);
}

}

}
