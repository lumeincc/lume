// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/handshake/handshake.hpp"

#include "lume/crypto/encoding.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/handshake/prekey.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <expected>
#include <string_view>
#include <utility>
#include <vector>

namespace lume::handshake {
namespace {

using crypto::ByteView;
using crypto::SecretBytes;

constexpr std::string_view pqxdh_label = "pqxdh";
constexpr std::string_view ad_label = "ad";
constexpr std::size_t key_size = 32;
constexpr std::size_t derived_size = 3 * key_size;
constexpr crypto::ByteArray<key_size> zero_salt{};
constexpr std::uint8_t filler_byte = 0xff;

constexpr crypto::ByteArray<key_size> filler = [] {
    crypto::ByteArray<key_size> bytes{};
    bytes.fill(filler_byte);
    return bytes;
}();

struct Transcript {
    ByteView initiator_signing_key;
    ByteView initiator_exchange_key;
    ByteView responder_signing_key;
    ByteView responder_exchange_key;
    ByteView kem_public_key;
    ByteView kem_ciphertext;
};

Result<SecretBytes> agree(const SecretBytes& secret_key, ByteView public_key)
{
    auto shared = crypto::x25519_shared_secret(secret_key, public_key);
    if (!shared) {
        return std::unexpected(shared.error() == crypto::Error::weak_public_key ? Error::weak_key
                                                                                : Error::library_failure);
    }
    return std::move(*shared);
}

Result<SessionKeys> derive(const std::vector<ByteView>& secrets, const Transcript& transcript)
{
    std::vector<ByteView> parts{filler};
    parts.insert(parts.end(), secrets.begin(), secrets.end());
    const auto input_key = SecretBytes::joined(parts);
    const auto output = crypto::hkdf_sha256(zero_salt, input_key.view(), crypto::label(pqxdh_label), derived_size);
    if (!output) {
        return std::unexpected(Error::library_failure);
    }
    const auto kem_digest = crypto::sha256({transcript.kem_public_key, transcript.kem_ciphertext});
    return SessionKeys{
        .root_key = SecretBytes::copy_of(output->view().first(key_size)),
        .header_key_alice = SecretBytes::copy_of(output->view().subspan(key_size, key_size)),
        .next_header_key_bob = SecretBytes::copy_of(output->view().subspan(2 * key_size, key_size)),
        .associated_data = crypto::Encoder{}
                               .label(ad_label)
                               .raw(transcript.initiator_signing_key)
                               .raw(transcript.initiator_exchange_key)
                               .raw(transcript.responder_signing_key)
                               .raw(transcript.responder_exchange_key)
                               .raw(kem_digest)
                               .take()};
}

bool same_pair(const identity::PublicIdentity& first, const identity::PublicIdentity& second)
{
    return first.signing_key == second.signing_key && first.exchange_key == second.exchange_key;
}

bool usable(wire::PrekeyKind kind, std::uint64_t created_at, std::uint64_t now)
{
    return is_usable_at(kind, created_at, now);
}

}

Result<void> check_bundle(const Bundle& bundle, const std::optional<identity::PublicIdentity>& pinned, std::uint64_t now)
{
    if (!identity::verify_binding(bundle.identity)) {
        return std::unexpected(Error::invalid_binding);
    }
    if (pinned && !same_pair(*pinned, bundle.identity)) {
        return std::unexpected(Error::identity_changed);
    }
    const auto& one_time = bundle.one_time_prekey;
    const bool right_kinds = bundle.signed_prekey.kind == wire::PrekeyKind::signed_prekey
        && bundle.seal_key.kind == wire::PrekeyKind::seal_key
        && (bundle.kem_prekey.kind == wire::PrekeyKind::kem_last_resort
            || bundle.kem_prekey.kind == wire::PrekeyKind::kem_one_time)
        && (!one_time || one_time->kind == wire::PrekeyKind::one_time_prekey);
    const ByteView signer = bundle.identity.signing_key;
    if (!right_kinds || !verify_prekey(signer, bundle.signed_prekey, bundle.generation)
        || !verify_prekey(signer, bundle.kem_prekey, bundle.generation)
        || !verify_prekey(signer, bundle.seal_key, bundle.generation)
        || (one_time && !verify_prekey(signer, *one_time, bundle.generation))) {
        return std::unexpected(Error::invalid_prekey);
    }
    if (!crypto::x25519_is_canonical(bundle.signed_prekey.key) || !crypto::x25519_is_canonical(bundle.seal_key.key)
        || (one_time && !crypto::x25519_is_canonical(one_time->key))) {
        return std::unexpected(Error::non_canonical_key);
    }
    if (!usable(bundle.signed_prekey.kind, bundle.signed_prekey.created_at, now)
        || !usable(bundle.kem_prekey.kind, bundle.kem_prekey.created_at, now)
        || !usable(bundle.seal_key.kind, bundle.seal_key.created_at, now)
        || (one_time && !usable(one_time->kind, one_time->created_at, now))) {
        return std::unexpected(Error::prekey_not_usable);
    }
    return {};
}

Result<Initiation> initiate(
    const identity::Identity& alice, const Bundle& bob, const std::optional<identity::PublicIdentity>& pinned,
    std::uint64_t now)
{
    if (auto checked = check_bundle(bob, pinned, now); !checked) {
        return std::unexpected(checked.error());
    }
    auto encapsulation = crypto::mlkem768_encapsulate(bob.kem_prekey.key);
    if (!encapsulation) {
        return std::unexpected(Error::invalid_kem_key);
    }
    auto ephemeral = crypto::x25519_generate();
    return detail::initiate_with(alice, bob, pinned, now, std::move(ephemeral.secret_key), *encapsulation);
}

Result<identity::PublicIdentity> initiator_of(
    const wire::InitialHeader& header, const std::optional<identity::PublicIdentity>& pinned)
{
    const identity::PublicIdentity alice{
        .signing_key = header.ik_sig, .exchange_key = header.ik_dh, .binding = header.bind};
    if (!identity::verify_binding(alice)) {
        return std::unexpected(Error::invalid_binding);
    }
    if (pinned && !same_pair(*pinned, alice)) {
        return std::unexpected(Error::identity_changed);
    }
    if (!crypto::x25519_is_canonical(header.ephemeral_key)) {
        return std::unexpected(Error::non_canonical_key);
    }
    return alice;
}

Result<SessionKeys> respond(const identity::Identity& bob, const wire::InitialHeader& header, const ResponderKeys& keys)
{
    if (auto alice = initiator_of(header, std::nullopt); !alice) {
        return std::unexpected(alice.error());
    }
    if (header.spk_id != keys.signed_prekey_id || header.pq_kind != keys.kem_kind || header.pq_id != keys.kem_id
        || header.opk_id != keys.one_time_prekey_id || header.opk_id.has_value() != keys.one_time_prekey.has_value()) {
        return std::unexpected(Error::unknown_prekey);
    }
    const auto& signed_prekey = keys.signed_prekey.get();
    auto dh1 = agree(signed_prekey.secret_key, header.ik_dh);
    auto dh2 = agree(bob.exchange.secret_key, header.ephemeral_key);
    auto dh3 = agree(signed_prekey.secret_key, header.ephemeral_key);
    if (!dh1 || !dh2 || !dh3) {
        return std::unexpected(Error::weak_key);
    }
    std::vector<ByteView> secrets{dh1->view(), dh2->view(), dh3->view()};
    std::optional<SecretBytes> dh4;
    if (keys.one_time_prekey) {
        auto shared = agree(keys.one_time_prekey->get().secret_key, header.ephemeral_key);
        if (!shared) {
            return std::unexpected(shared.error());
        }
        dh4 = std::move(*shared);
        secrets.push_back(dh4->view());
    }
    const auto& kem_prekey = keys.kem_prekey.get();
    const auto shared_secret = crypto::mlkem768_decapsulate(kem_prekey.seed, header.kem_ciphertext);
    if (!shared_secret) {
        return std::unexpected(Error::library_failure);
    }
    secrets.push_back(shared_secret->view());
    return derive(
        secrets,
        Transcript{
            .initiator_signing_key = header.ik_sig,
            .initiator_exchange_key = header.ik_dh,
            .responder_signing_key = bob.signing.public_key,
            .responder_exchange_key = bob.exchange.public_key,
            .kem_public_key = kem_prekey.public_key,
            .kem_ciphertext = header.kem_ciphertext});
}

crypto::ByteArray<crypto::sha256_size> replay_tag(const wire::InitialHeader& header)
{
    return crypto::sha256({header.ephemeral_key, header.kem_ciphertext});
}

namespace detail {

Result<Initiation> initiate_with(
    const identity::Identity& alice, const Bundle& bob, const std::optional<identity::PublicIdentity>& pinned,
    std::uint64_t now, SecretBytes ephemeral_secret, const crypto::MlKemEncapsulation& encapsulation)
{
    if (auto checked = check_bundle(bob, pinned, now); !checked) {
        return std::unexpected(checked.error());
    }
    if (encapsulation.ciphertext.size() != wire::kem_ciphertext_size) {
        return std::unexpected(Error::invalid_kem_key);
    }
    auto ephemeral = crypto::x25519_from_secret(std::move(ephemeral_secret));
    if (!ephemeral) {
        return std::unexpected(Error::library_failure);
    }
    auto dh1 = agree(alice.exchange.secret_key, bob.signed_prekey.key);
    auto dh2 = agree(ephemeral->secret_key, bob.identity.exchange_key);
    auto dh3 = agree(ephemeral->secret_key, bob.signed_prekey.key);
    if (!dh1 || !dh2 || !dh3) {
        return std::unexpected(Error::weak_key);
    }
    std::vector<ByteView> secrets{dh1->view(), dh2->view(), dh3->view()};
    std::optional<SecretBytes> dh4;
    if (bob.one_time_prekey) {
        auto shared = agree(ephemeral->secret_key, bob.one_time_prekey->key);
        if (!shared) {
            return std::unexpected(shared.error());
        }
        dh4 = std::move(*shared);
        secrets.push_back(dh4->view());
    }
    secrets.push_back(encapsulation.shared_secret.view());

    Initiation initiation{
        .keys = {},
        .header = {},
        .peer_ratchet_key = bob.signed_prekey.key};
    initiation.header.ik_sig = alice.signing.public_key;
    initiation.header.ik_dh = alice.exchange.public_key;
    initiation.header.bind = alice.binding;
    initiation.header.ephemeral_key = ephemeral->public_key;
    std::ranges::copy(encapsulation.ciphertext, initiation.header.kem_ciphertext.begin());
    initiation.header.spk_id = bob.signed_prekey.id;
    initiation.header.pq_kind = bob.kem_prekey.kind;
    initiation.header.pq_id = bob.kem_prekey.id;
    if (bob.one_time_prekey) {
        initiation.header.opk_id = bob.one_time_prekey->id;
    }

    auto keys = derive(
        secrets,
        Transcript{
            .initiator_signing_key = alice.signing.public_key,
            .initiator_exchange_key = alice.exchange.public_key,
            .responder_signing_key = bob.identity.signing_key,
            .responder_exchange_key = bob.identity.exchange_key,
            .kem_public_key = bob.kem_prekey.key,
            .kem_ciphertext = encapsulation.ciphertext});
    if (!keys) {
        return std::unexpected(keys.error());
    }
    initiation.keys = std::move(*keys);
    return initiation;
}

}

}
