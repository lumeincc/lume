// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/card/card.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/handshake/prekey.hpp"

#include <algorithm>
#include <limits>
#include <string_view>

namespace lume::card {
namespace {

constexpr std::string_view card_label = "card";

bool right_kinds(const wire::Card& card) noexcept
{
    return card.spk.kind == wire::PrekeyKind::signed_prekey && card.pqspk.kind == wire::PrekeyKind::kem_last_resort
        && card.ssk.kind == wire::PrekeyKind::seal_key;
}

std::uint64_t oldest_key(const wire::Card& card) noexcept
{
    return std::min({card.spk.created_at, card.pqspk.created_at, card.ssk.created_at});
}

bool outlives(std::uint64_t expires_at, std::uint64_t created_at) noexcept
{
    return expires_at > created_at && expires_at - created_at > handshake::rotating_key_usable_for;
}

Error from(handshake::Error error) noexcept
{
    switch (error) {
    case handshake::Error::identity_changed:
        return Error::identity_changed;
    case handshake::Error::generation_went_down:
        return Error::generation_went_down;
    default:
        return Error::invalid_keys;
    }
}

handshake::Bundle bundle_of(const wire::Card& card)
{
    return handshake::Bundle{
        .identity = identity::PublicIdentity{
            .signing_key = card.certificate.ik_sig, .exchange_key = card.certificate.ik_dh, .binding = card.bind},
        .generation = card.generation,
        .signed_prekey = card.spk,
        .kem_prekey = card.pqspk,
        .seal_key = card.ssk,
        .one_time_prekey = std::nullopt};
}

}

crypto::Bytes card_message(const SigningKey& recipient, const wire::Card& card)
{
    return crypto::Encoder{}
        .label(card_label)
        .raw(recipient)
        .raw(card.group_id)
        .raw(crypto::sha256(card.token))
        .u64(card.expires_at)
        .take();
}

Result<wire::Card> sign_card(
    const identity::Identity& owner, wire::Card card, const SigningKey& recipient, std::uint64_t now)
{
    const auto identity = identity::public_identity(owner);
    if (card.certificate.ik_sig != identity.signing_key || card.certificate.ik_dh != identity.exchange_key
        || card.bind != identity.binding) {
        return std::unexpected(Error::not_the_owner);
    }
    if (recipient == identity.signing_key) {
        return std::unexpected(Error::wrong_member);
    }
    if (!right_kinds(card)) {
        return std::unexpected(Error::invalid_keys);
    }
    const auto oldest = oldest_key(card);
    const auto usable_until = oldest > std::numeric_limits<std::uint64_t>::max() - handshake::rotating_key_usable_for
        ? std::numeric_limits<std::uint64_t>::max()
        : oldest + handshake::rotating_key_usable_for;
    card.expires_at = std::min(now + card_lifetime, usable_until);
    if (card.expires_at <= now) {
        return std::unexpected(Error::outlives_its_keys);
    }
    auto signature = crypto::ed25519_sign(owner.signing.seed, card_message(recipient, card));
    if (!signature) {
        return std::unexpected(Error::library_failure);
    }
    card.signature = *signature;
    return card;
}

Result<CheckedCard> check_card(
    const wire::Card& card, const Expected& expected, std::uint64_t now, const std::optional<handshake::Pin>& pinned,
    const directory::Directory& names)
{
    if (now >= card.expires_at) {
        return std::unexpected(Error::expired);
    }
    if (card.expires_at - now > card_lifetime + handshake::allowed_clock_skew) {
        return std::unexpected(Error::bad_lifetime);
    }
    if (card.group_id != expected.group_id) {
        return std::unexpected(Error::wrong_group);
    }
    if (card.certificate.ik_sig != expected.member || card.certificate.ik_sig == expected.recipient) {
        return std::unexpected(Error::wrong_member);
    }
    if (!crypto::ed25519_verify(card.certificate.ik_sig, card_message(expected.recipient, card), card.signature)) {
        return std::unexpected(Error::invalid_signature);
    }
    if (!right_kinds(card)) {
        return std::unexpected(Error::invalid_keys);
    }
    auto bundle = bundle_of(card);
    if (auto checked = handshake::check_bundle(bundle, pinned, now); !checked) {
        return std::unexpected(from(checked.error()));
    }
    if (outlives(card.expires_at, card.spk.created_at) || outlives(card.expires_at, card.pqspk.created_at)
        || outlives(card.expires_at, card.ssk.created_at)) {
        return std::unexpected(Error::outlives_its_keys);
    }
    const bool name_verified =
        names.check_certificate(card.certificate, now, bundle.identity, card.certificate.account_id).has_value();
    return CheckedCard{.bundle = bundle, .name_verified = name_verified};
}

}
