// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/card/card.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/handshake/prekey.hpp"

#include <string_view>
#include <utility>

namespace lume::card {
namespace {

constexpr std::string_view card_label = "card";

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

}

crypto::Bytes card_message(crypto::ByteView recipient_ik_sig, const wire::Card& card)
{
    return crypto::Encoder{}
        .label(card_label)
        .raw(recipient_ik_sig)
        .raw(card.group_id)
        .raw(crypto::sha256(card.token))
        .u64(card.expires_at)
        .take();
}

crypto::Result<wire::Card> sign_card(const identity::Identity& owner, wire::Card card, crypto::ByteView recipient_ik_sig)
{
    auto signature = crypto::ed25519_sign(owner.signing.seed, card_message(recipient_ik_sig, card));
    if (!signature) {
        return std::unexpected(signature.error());
    }
    card.signature = *signature;
    return card;
}

Result<handshake::Bundle> check_card(
    const wire::Card& card, crypto::ByteView recipient_ik_sig, std::uint64_t now,
    const std::optional<handshake::Pin>& pinned)
{
    if (now >= card.expires_at) {
        return std::unexpected(Error::expired);
    }
    if (card.expires_at - now > card_lifetime + handshake::allowed_clock_skew) {
        return std::unexpected(Error::bad_lifetime);
    }
    if (!crypto::ed25519_verify(card.certificate.ik_sig, card_message(recipient_ik_sig, card), card.signature)) {
        return std::unexpected(Error::invalid_signature);
    }
    if (outlives(card.expires_at, card.spk.created_at) || outlives(card.expires_at, card.pqspk.created_at)
        || outlives(card.expires_at, card.ssk.created_at)) {
        return std::unexpected(Error::outlives_its_keys);
    }
    handshake::Bundle bundle{
        .identity = identity::PublicIdentity{
            .signing_key = card.certificate.ik_sig, .exchange_key = card.certificate.ik_dh, .binding = card.bind},
        .generation = card.generation,
        .signed_prekey = card.spk,
        .kem_prekey = card.pqspk,
        .seal_key = card.ssk,
        .one_time_prekey = std::nullopt};
    if (auto checked = handshake::check_bundle(bundle, pinned, now); !checked) {
        return std::unexpected(from(checked.error()));
    }
    return bundle;
}

}
