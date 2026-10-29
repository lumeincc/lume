// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/handshake/prekey.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/encoding.hpp"

#include <algorithm>
#include <expected>
#include <string_view>

namespace lume::handshake {
namespace {

constexpr std::string_view prekey_label = "prekey";

crypto::Result<crypto::ByteArray<crypto::ed25519_signature_size>> sign(
    const identity::Identity& owner, const PrekeyFacts& facts, crypto::ByteView public_key)
{
    if (facts.generation < identity::first_generation) {
        return std::unexpected(crypto::Error::out_of_range);
    }
    return crypto::ed25519_sign(owner.signing.seed, prekey_message(facts, public_key));
}

}

crypto::Bytes prekey_message(const PrekeyFacts& facts, crypto::ByteView public_key)
{
    return crypto::Encoder{}
        .label(prekey_label)
        .u8(static_cast<std::uint8_t>(facts.kind))
        .u32(facts.id)
        .u64(facts.created_at)
        .u32(facts.generation)
        .prefixed(public_key)
        .take();
}

crypto::Result<wire::PrekeyX> make_prekey_x(
    const identity::Identity& owner, const PrekeyFacts& facts, crypto::ByteView public_key)
{
    if (public_key.size() != wire::x25519_key_size) {
        return std::unexpected(crypto::Error::invalid_size);
    }
    wire::PrekeyX prekey;
    prekey.kind = facts.kind;
    prekey.id = facts.id;
    prekey.created_at = facts.created_at;
    std::ranges::copy(public_key, prekey.key.begin());
    if (facts.kind == wire::PrekeyKind::one_time_prekey) {
        prekey.signature.reset();
        return prekey;
    }
    if (facts.kind != wire::PrekeyKind::signed_prekey && facts.kind != wire::PrekeyKind::seal_key) {
        return std::unexpected(crypto::Error::invalid_key);
    }
    const auto signature = sign(owner, facts, public_key);
    if (!signature) {
        return std::unexpected(signature.error());
    }
    prekey.signature = *signature;
    return prekey;
}

crypto::Result<wire::PrekeyKem> make_prekey_kem(
    const identity::Identity& owner, const PrekeyFacts& facts, crypto::ByteView public_key)
{
    if (public_key.size() != wire::kem_public_key_size) {
        return std::unexpected(crypto::Error::invalid_size);
    }
    if (facts.kind != wire::PrekeyKind::kem_last_resort && facts.kind != wire::PrekeyKind::kem_one_time) {
        return std::unexpected(crypto::Error::invalid_key);
    }
    const auto signature = sign(owner, facts, public_key);
    if (!signature) {
        return std::unexpected(signature.error());
    }
    wire::PrekeyKem prekey;
    prekey.kind = facts.kind;
    prekey.id = facts.id;
    prekey.created_at = facts.created_at;
    std::ranges::copy(public_key, prekey.key.begin());
    prekey.signature = *signature;
    return prekey;
}

bool verify_prekey(crypto::ByteView signing_key, const wire::PrekeyX& prekey, std::uint32_t generation)
{
    if (prekey.kind == wire::PrekeyKind::one_time_prekey) {
        return !prekey.signature.has_value();
    }
    if (!prekey.signature || generation < identity::first_generation) {
        return false;
    }
    const PrekeyFacts facts{
        .kind = prekey.kind, .id = prekey.id, .created_at = prekey.created_at, .generation = generation};
    return crypto::ed25519_verify(signing_key, prekey_message(facts, prekey.key), *prekey.signature);
}

bool verify_prekey(crypto::ByteView signing_key, const wire::PrekeyKem& prekey, std::uint32_t generation)
{
    if (generation < identity::first_generation) {
        return false;
    }
    const PrekeyFacts facts{
        .kind = prekey.kind, .id = prekey.id, .created_at = prekey.created_at, .generation = generation};
    return crypto::ed25519_verify(signing_key, prekey_message(facts, prekey.key), prekey.signature);
}

bool is_rotating(wire::PrekeyKind kind) noexcept
{
    return kind == wire::PrekeyKind::signed_prekey || kind == wire::PrekeyKind::kem_last_resort
        || kind == wire::PrekeyKind::seal_key;
}

bool is_usable_at(wire::PrekeyKind kind, std::uint64_t created_at, std::uint64_t now) noexcept
{
    if (created_at > now && created_at - now > allowed_clock_skew) {
        return false;
    }
    if (!is_rotating(kind) || created_at >= now) {
        return true;
    }
    return now - created_at <= rotating_key_usable_for;
}

}
