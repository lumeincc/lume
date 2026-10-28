// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/ratchet/ratchet.hpp"

#include "crypto/aead_internal.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/kdf.hpp"
#include "ratchet/ratchet_internal.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>
#include <utility>

namespace lume::ratchet {
namespace {

using crypto::ByteView;
using crypto::Bytes;
using crypto::SecretBytes;

using Random = const detail::RandomSource*;

constexpr std::string_view root_label = "ratchet/root";
constexpr std::size_t key_size = 32;
constexpr std::size_t header_size = wire::encrypted_header_size - crypto::aead_overhead;
constexpr std::uint32_t last_number = std::numeric_limits<std::uint32_t>::max();
constexpr std::array<std::uint8_t, 1> chain_step{0x02};
constexpr std::array<std::uint8_t, 1> message_step{0x01};

struct RootStep {
    SecretBytes root_key;
    SecretBytes chain_key;
    SecretBytes next_header_key;
};

struct ChainStep {
    SecretBytes chain_key;
    SecretBytes message_key;
};

struct Skip {
    SecretBytes chain_key;
    SecretBytes message_keys;
};

struct Turn {
    RootStep receiving;
    crypto::X25519KeyPair sending_ratchet;
    RootStep sending;
};

struct Hit {
    std::size_t chain = 0;
    std::size_t index = 0;
};

struct Delivery {
    ByteView associated_data;
    ByteView body;
    std::uint64_t now = 0;
    std::size_t limit = 0;
};

Result<RootStep> kdf_rk(const SecretBytes& root_key, const SecretBytes& shared)
{
    const auto output =
        crypto::hkdf_sha256(root_key.view(), shared.view(), crypto::label(root_label), 3 * key_size);
    if (!output) {
        return std::unexpected(Error::library_failure);
    }
    return RootStep{
        .root_key = SecretBytes::copy_of(output->view().first(key_size)),
        .chain_key = SecretBytes::copy_of(output->view().subspan(key_size, key_size)),
        .next_header_key = SecretBytes::copy_of(output->view().subspan(2 * key_size, key_size))};
}

ChainStep kdf_ck(const SecretBytes& chain_key)
{
    return ChainStep{
        .chain_key = crypto::hmac_sha256(chain_key.view(), chain_step),
        .message_key = crypto::hmac_sha256(chain_key.view(), message_step)};
}

Result<crypto::X25519KeyPair> fresh_key_pair(Random random)
{
    if (random == nullptr) {
        return crypto::x25519_generate();
    }
    SecretBytes secret(key_size);
    (*random)(secret.writable());
    auto pair = crypto::x25519_from_secret(std::move(secret));
    if (!pair) {
        return std::unexpected(Error::library_failure);
    }
    return std::move(*pair);
}

Result<SecretBytes> agree(const SecretBytes& secret_key, ByteView public_key)
{
    if (!crypto::x25519_is_canonical(public_key)) {
        return std::unexpected(Error::weak_key);
    }
    auto shared = crypto::x25519_shared_secret(secret_key, public_key);
    if (!shared) {
        return std::unexpected(Error::weak_key);
    }
    return std::move(*shared);
}

Bytes joined(ByteView first, ByteView second)
{
    Bytes bytes(first.begin(), first.end());
    bytes.insert(bytes.end(), second.begin(), second.end());
    return bytes;
}

Result<Bytes> seal(const SecretBytes& key, ByteView associated_data, ByteView plaintext, Random random)
{
    if (random == nullptr) {
        auto sealed = crypto::aead_seal(key, associated_data, plaintext);
        if (!sealed) {
            return std::unexpected(Error::library_failure);
        }
        return std::move(*sealed);
    }
    crypto::ByteArray<crypto::aead_nonce_size> nonce{};
    (*random)(nonce);
    const auto ciphertext = crypto::detail::aead_encrypt(key, nonce, associated_data, plaintext);
    if (!ciphertext) {
        return std::unexpected(Error::library_failure);
    }
    return joined(nonce, *ciphertext);
}

std::optional<wire::RatchetHeader> open_header(ByteView header_key, ByteView associated_data, ByteView encrypted_header)
{
    crypto::ByteArray<header_size> plaintext{};
    if (!crypto::detail::aead_open_into(header_key, associated_data, encrypted_header, plaintext)) {
        return std::nullopt;
    }
    auto header = wire::decode(plaintext, wire::read_ratchet_header);
    if (!header) {
        return std::nullopt;
    }
    return *header;
}

std::optional<Hit> find_skipped(const State& state, ByteView encrypted_header)
{
    const auto& skipped = state.skipped;
    for (std::size_t chain = 0; chain < skipped.chain_count(); ++chain) {
        const auto header = open_header(skipped.header_key(chain), state.associated_data, encrypted_header);
        if (!header) {
            continue;
        }
        if (header->ratchet_key != skipped.ratchet_key(chain)) {
            return std::nullopt;
        }
        const auto index = skipped.find(chain, header->message_number);
        if (!index) {
            return std::nullopt;
        }
        return Hit{.chain = chain, .index = *index};
    }
    return std::nullopt;
}

Result<Skip> skip(const SecretBytes& chain_key, std::uint32_t from, std::uint32_t until)
{
    if (until - from > max_skip) {
        return std::unexpected(Error::too_many_skipped);
    }
    Skip result{.chain_key = chain_key.clone(), .message_keys = SecretBytes(std::size_t{until - from} * key_size)};
    auto next = result.message_keys.writable().begin();
    for (std::uint32_t number = from; number < until; ++number) {
        auto step = kdf_ck(result.chain_key);
        next = std::ranges::copy(step.message_key.view(), next).out;
        result.chain_key = std::move(step.chain_key);
    }
    return result;
}

Result<std::optional<Skip>> skip_rest_of_chain(const State& state, std::uint32_t until)
{
    if (!state.receiving_chain || !state.receiving_header_key || !state.receiving_ratchet || until <= state.received) {
        return std::nullopt;
    }
    auto skipped = skip(*state.receiving_chain, state.received, until);
    if (!skipped) {
        return std::unexpected(skipped.error());
    }
    return std::optional<Skip>(std::move(*skipped));
}

Result<Turn> turn(const State& state, const RatchetKey& their_key, Random random)
{
    auto received_shared = agree(state.sending_ratchet.secret_key, their_key);
    if (!received_shared) {
        return std::unexpected(received_shared.error());
    }
    auto receiving = kdf_rk(state.root_key, *received_shared);
    if (!receiving) {
        return std::unexpected(receiving.error());
    }
    auto fresh = fresh_key_pair(random);
    if (!fresh) {
        return std::unexpected(fresh.error());
    }
    auto sent_shared = agree(fresh->secret_key, their_key);
    if (!sent_shared) {
        return std::unexpected(sent_shared.error());
    }
    auto sending = kdf_rk(receiving->root_key, *sent_shared);
    if (!sending) {
        return std::unexpected(sending.error());
    }
    return Turn{.receiving = std::move(*receiving), .sending_ratchet = std::move(*fresh), .sending = std::move(*sending)};
}

void commit_turn(State& state, const RatchetKey& their_key, Turn turned)
{
    state.previous_sent = state.sent;
    state.sent = 0;
    state.sending_header_key = std::move(state.next_sending_header_key);
    state.receiving_header_key = std::move(state.next_receiving_header_key);
    state.receiving_ratchet = their_key;
    state.next_receiving_header_key = std::move(turned.receiving.next_header_key);
    state.sending_ratchet = std::move(turned.sending_ratchet);
    state.root_key = std::move(turned.sending.root_key);
    state.sending_chain = std::move(turned.sending.chain_key);
    state.next_sending_header_key = std::move(turned.sending.next_header_key);
}

void store_skipped(State& state, ByteView message_keys, std::uint32_t first_number, const Delivery& delivery)
{
    if (state.receiving_header_key && state.receiving_ratchet) {
        state.skipped.add(
            *state.receiving_header_key, *state.receiving_ratchet, first_number, message_keys, delivery.now,
            delivery.limit);
    }
}

void commit_message(State& state, SecretBytes chain_key, std::uint32_t number)
{
    state.receiving_chain = std::move(chain_key);
    state.received = number + 1;
    state.has_received = true;
}

Result<SecretBytes> open_skipped(State& state, const Hit& hit, const Delivery& delivery)
{
    auto plaintext = crypto::detail::aead_open(
        state.skipped.message_key(hit.chain, hit.index), delivery.associated_data, delivery.body);
    if (!plaintext) {
        return std::unexpected(Error::authentication_failed);
    }
    state.skipped.erase(hit.chain, hit.index);
    state.has_received = true;
    return std::move(*plaintext);
}

Result<SecretBytes> continue_chain(State& state, const wire::RatchetHeader& header, const Delivery& delivery)
{
    if (!state.receiving_ratchet || header.ratchet_key != *state.receiving_ratchet || !state.receiving_chain
        || !state.receiving_header_key) {
        return std::unexpected(Error::unknown_header);
    }
    if (header.message_number < state.received) {
        return std::unexpected(Error::old_or_duplicate);
    }
    if (header.message_number == last_number) {
        return std::unexpected(Error::exhausted);
    }
    auto skipped = skip(*state.receiving_chain, state.received, header.message_number);
    if (!skipped) {
        return std::unexpected(skipped.error());
    }
    auto step = kdf_ck(skipped->chain_key);
    auto plaintext = crypto::aead_open(step.message_key, delivery.associated_data, delivery.body);
    if (!plaintext) {
        return std::unexpected(Error::authentication_failed);
    }
    store_skipped(state, skipped->message_keys.view(), state.received, delivery);
    commit_message(state, std::move(step.chain_key), header.message_number);
    return std::move(*plaintext);
}

Result<SecretBytes> next_chain(
    State& state, const wire::RatchetHeader& header, const Delivery& delivery, Random random)
{
    auto previous = skip_rest_of_chain(state, header.previous_chain_length);
    if (!previous) {
        return std::unexpected(previous.error());
    }
    if (header.message_number == last_number) {
        return std::unexpected(Error::exhausted);
    }
    if (header.message_number > max_skip) {
        return std::unexpected(Error::too_many_skipped);
    }
    auto turned = turn(state, header.ratchet_key, random);
    if (!turned) {
        return std::unexpected(turned.error());
    }
    auto current = skip(turned->receiving.chain_key, 0, header.message_number);
    if (!current) {
        return std::unexpected(current.error());
    }
    auto step = kdf_ck(current->chain_key);
    auto plaintext = crypto::aead_open(step.message_key, delivery.associated_data, delivery.body);
    if (!plaintext) {
        return std::unexpected(Error::authentication_failed);
    }
    if (*previous) {
        store_skipped(state, (*previous)->message_keys.view(), state.received, delivery);
    }
    commit_turn(state, header.ratchet_key, std::move(*turned));
    store_skipped(state, current->message_keys.view(), 0, delivery);
    commit_message(state, std::move(step.chain_key), header.message_number);
    return std::move(*plaintext);
}

Result<State> start_alice(const handshake::SessionKeys& keys, ByteView peer_ratchet_key, Random random)
{
    if (peer_ratchet_key.size() != crypto::x25519_key_size) {
        return std::unexpected(Error::weak_key);
    }
    auto sending_ratchet = fresh_key_pair(random);
    if (!sending_ratchet) {
        return std::unexpected(sending_ratchet.error());
    }
    auto shared = agree(sending_ratchet->secret_key, peer_ratchet_key);
    if (!shared) {
        return std::unexpected(shared.error());
    }
    auto step = kdf_rk(keys.root_key, *shared);
    if (!step) {
        return std::unexpected(step.error());
    }
    RatchetKey peer{};
    std::ranges::copy(peer_ratchet_key, peer.begin());
    return State{
        .sending_ratchet = std::move(*sending_ratchet),
        .receiving_ratchet = peer,
        .root_key = std::move(step->root_key),
        .sending_chain = std::move(step->chain_key),
        .receiving_chain = std::nullopt,
        .sending_header_key = keys.header_key_alice.clone(),
        .receiving_header_key = std::nullopt,
        .next_sending_header_key = std::move(step->next_header_key),
        .next_receiving_header_key = keys.next_header_key_bob.clone(),
        .sent = 0,
        .received = 0,
        .previous_sent = 0,
        .skipped = {},
        .associated_data = keys.associated_data,
        .has_received = false};
}

Result<wire::RatchetMessage> encrypt_with(State& state, ByteView plaintext, Random random)
{
    if (!state.sending_chain || !state.sending_header_key) {
        return std::unexpected(Error::cannot_send);
    }
    if (plaintext.size() > max_plaintext_size) {
        return std::unexpected(Error::message_too_large);
    }
    if (state.sent == last_number) {
        return std::unexpected(Error::exhausted);
    }
    auto step = kdf_ck(*state.sending_chain);
    const auto header = wire::encode(wire::RatchetHeader{
        .ratchet_key = state.sending_ratchet.public_key,
        .previous_chain_length = state.previous_sent,
        .message_number = state.sent});
    const auto encrypted_header = seal(*state.sending_header_key, state.associated_data, header, random);
    if (!encrypted_header || encrypted_header->size() != wire::encrypted_header_size) {
        return std::unexpected(Error::library_failure);
    }
    auto body = seal(step.message_key, joined(state.associated_data, *encrypted_header), plaintext, random);
    if (!body) {
        return std::unexpected(body.error());
    }
    wire::RatchetMessage message;
    std::ranges::copy(*encrypted_header, message.encrypted_header.begin());
    message.body = std::move(*body);
    state.sending_chain = std::move(step.chain_key);
    ++state.sent;
    return message;
}

Result<SecretBytes> decrypt_with(
    State& state, const wire::RatchetMessage& message, std::uint64_t now, std::size_t limit, Random random)
{
    expire(state, now);
    const auto associated_data = joined(state.associated_data, message.encrypted_header);
    const Delivery delivery{.associated_data = associated_data, .body = message.body, .now = now, .limit = limit};
    if (const auto hit = find_skipped(state, message.encrypted_header)) {
        return open_skipped(state, *hit, delivery);
    }
    if (state.receiving_header_key) {
        const auto header =
            open_header(state.receiving_header_key->view(), state.associated_data, message.encrypted_header);
        if (header) {
            return continue_chain(state, *header, delivery);
        }
    }
    const auto header = open_header(state.next_receiving_header_key.view(), state.associated_data, message.encrypted_header);
    if (!header) {
        return std::unexpected(Error::unknown_header);
    }
    return next_chain(state, *header, delivery, random);
}

std::optional<SecretBytes> clone_optional(const std::optional<SecretBytes>& key)
{
    if (!key) {
        return std::nullopt;
    }
    return key->clone();
}

}

State clone(const State& state)
{
    return State{
        .sending_ratchet =
            crypto::X25519KeyPair{
                .public_key = state.sending_ratchet.public_key,
                .secret_key = state.sending_ratchet.secret_key.clone()},
        .receiving_ratchet = state.receiving_ratchet,
        .root_key = state.root_key.clone(),
        .sending_chain = clone_optional(state.sending_chain),
        .receiving_chain = clone_optional(state.receiving_chain),
        .sending_header_key = clone_optional(state.sending_header_key),
        .receiving_header_key = clone_optional(state.receiving_header_key),
        .next_sending_header_key = state.next_sending_header_key.clone(),
        .next_receiving_header_key = state.next_receiving_header_key.clone(),
        .sent = state.sent,
        .received = state.received,
        .previous_sent = state.previous_sent,
        .skipped = state.skipped.clone(),
        .associated_data = state.associated_data,
        .has_received = state.has_received};
}

Result<State> start_as_alice(const handshake::SessionKeys& keys, ByteView peer_ratchet_key)
{
    return start_alice(keys, peer_ratchet_key, nullptr);
}

State start_as_bob(const handshake::SessionKeys& keys, const crypto::X25519KeyPair& signed_prekey)
{
    return State{
        .sending_ratchet =
            crypto::X25519KeyPair{.public_key = signed_prekey.public_key, .secret_key = signed_prekey.secret_key.clone()},
        .receiving_ratchet = std::nullopt,
        .root_key = keys.root_key.clone(),
        .sending_chain = std::nullopt,
        .receiving_chain = std::nullopt,
        .sending_header_key = std::nullopt,
        .receiving_header_key = std::nullopt,
        .next_sending_header_key = keys.next_header_key_bob.clone(),
        .next_receiving_header_key = keys.header_key_alice.clone(),
        .sent = 0,
        .received = 0,
        .previous_sent = 0,
        .skipped = {},
        .associated_data = keys.associated_data,
        .has_received = false};
}

Result<wire::RatchetMessage> encrypt(State& state, ByteView plaintext)
{
    return encrypt_with(state, plaintext, nullptr);
}

Result<SecretBytes> decrypt(
    State& state, const wire::RatchetMessage& message, std::uint64_t now, std::size_t skipped_key_limit)
{
    return decrypt_with(state, message, now, skipped_key_limit, nullptr);
}

void expire(State& state, std::uint64_t now)
{
    state.skipped.expire(now);
}

namespace detail {

Result<State> start_as_alice(const handshake::SessionKeys& keys, ByteView peer_ratchet_key, const RandomSource& random)
{
    return start_alice(keys, peer_ratchet_key, &random);
}

Result<wire::RatchetMessage> encrypt(State& state, ByteView plaintext, const RandomSource& random)
{
    return encrypt_with(state, plaintext, &random);
}

Result<SecretBytes> decrypt(State& state, const wire::RatchetMessage& message, std::uint64_t now, const RandomSource& random)
{
    return decrypt_with(state, message, now, max_skipped_keys, &random);
}

}

}
