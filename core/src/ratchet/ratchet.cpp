// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/ratchet/ratchet.hpp"

#include "crypto/aead_internal.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/random.hpp"

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

constexpr std::string_view root_label = "ratchet/root";
constexpr std::size_t key_size = 32;
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

void system_random(std::span<std::uint8_t> output)
{
    crypto::random_fill(output);
}

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

Result<crypto::X25519KeyPair> fresh_key_pair(const detail::RandomSource& random)
{
    SecretBytes secret(key_size);
    random(secret.writable());
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

Result<Bytes> seal(
    const SecretBytes& key, ByteView associated_data, ByteView plaintext, const detail::RandomSource& random)
{
    crypto::ByteArray<crypto::aead_nonce_size> nonce{};
    random(nonce);
    const auto ciphertext = crypto::detail::aead_encrypt(key, nonce, associated_data, plaintext);
    if (!ciphertext) {
        return std::unexpected(Error::library_failure);
    }
    return joined(nonce, *ciphertext);
}

std::optional<wire::RatchetHeader> open_header(
    const SecretBytes& header_key, ByteView associated_data, ByteView encrypted_header)
{
    const auto plaintext = crypto::aead_open(header_key, associated_data, encrypted_header);
    if (!plaintext) {
        return std::nullopt;
    }
    auto header = wire::decode(plaintext->view(), wire::read_ratchet_header);
    if (!header) {
        return std::nullopt;
    }
    return *header;
}

void forget_expired(State& state, std::uint64_t now)
{
    std::erase_if(state.skipped, [now](const SkippedKey& key) {
        return now > key.stored_at && now - key.stored_at > skipped_key_lifetime;
    });
}

std::size_t distinct_header_keys(const State& state)
{
    std::size_t runs = 0;
    const SecretBytes* previous = nullptr;
    for (const auto& entry : state.skipped) {
        if (previous == nullptr || !previous->equals(entry.header_key.view())) {
            ++runs;
        }
        previous = &entry.header_key;
    }
    return runs;
}

void store_skipped(State& state, SkippedKey key)
{
    const bool new_chain = state.skipped.empty() || !state.skipped.back().header_key.equals(key.header_key.view());
    state.skipped.push_back(std::move(key));
    while (new_chain && distinct_header_keys(state) > max_skipped_header_keys) {
        const auto oldest = state.skipped.front().header_key.clone();
        std::erase_if(state.skipped, [&oldest](const SkippedKey& entry) {
            return entry.header_key.equals(oldest.view());
        });
    }
    while (state.skipped.size() > max_skipped_keys) {
        state.skipped.erase(state.skipped.begin());
    }
}

Result<void> skip_message_keys(State& state, std::uint32_t until, std::uint64_t now)
{
    if (!state.receiving_chain || !state.receiving_header_key || !state.receiving_ratchet
        || until <= state.received) {
        return {};
    }
    if (until - state.received > max_skip) {
        return std::unexpected(Error::too_many_skipped);
    }
    while (state.received < until) {
        auto step = kdf_ck(*state.receiving_chain);
        store_skipped(
            state,
            SkippedKey{
                .header_key = state.receiving_header_key->clone(),
                .ratchet_key = *state.receiving_ratchet,
                .number = state.received,
                .message_key = std::move(step.message_key),
                .stored_at = now});
        state.receiving_chain = std::move(step.chain_key);
        ++state.received;
    }
    return {};
}

std::optional<SecretBytes> take_skipped(State& state, ByteView encrypted_header)
{
    std::vector<const SecretBytes*> tried;
    for (const auto& candidate : state.skipped) {
        const bool seen = std::ranges::any_of(tried, [&candidate](const SecretBytes* key) {
            return key->equals(candidate.header_key.view());
        });
        if (seen) {
            continue;
        }
        tried.push_back(&candidate.header_key);
        const auto header = open_header(candidate.header_key, state.associated_data, encrypted_header);
        if (!header) {
            continue;
        }
        const auto match = std::ranges::find_if(state.skipped, [&](const SkippedKey& entry) {
            return entry.header_key.equals(candidate.header_key.view()) && entry.ratchet_key == header->ratchet_key
                && entry.number == header->message_number;
        });
        if (match == state.skipped.end()) {
            return std::nullopt;
        }
        auto message_key = std::move(match->message_key);
        state.skipped.erase(match);
        return message_key;
    }
    return std::nullopt;
}

Result<void> dh_ratchet(
    State& state, const crypto::ByteArray<crypto::x25519_key_size>& their_key, const detail::RandomSource& random)
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

    state.previous_sent = state.sent;
    state.sent = 0;
    state.received = 0;
    state.sending_header_key = std::move(state.next_sending_header_key);
    state.receiving_header_key = std::move(state.next_receiving_header_key);
    state.receiving_ratchet = their_key;
    state.receiving_chain = std::move(receiving->chain_key);
    state.next_receiving_header_key = std::move(receiving->next_header_key);
    state.sending_ratchet = std::move(*fresh);
    state.root_key = std::move(sending->root_key);
    state.sending_chain = std::move(sending->chain_key);
    state.next_sending_header_key = std::move(sending->next_header_key);
    return {};
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
    State copy{
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
        .skipped = {},
        .associated_data = state.associated_data,
        .has_received = state.has_received};
    copy.skipped.reserve(state.skipped.size());
    for (const auto& key : state.skipped) {
        copy.skipped.push_back(SkippedKey{
            .header_key = key.header_key.clone(),
            .ratchet_key = key.ratchet_key,
            .number = key.number,
            .message_key = key.message_key.clone(),
            .stored_at = key.stored_at});
    }
    return copy;
}

Result<State> start_as_alice(const handshake::SessionKeys& keys, ByteView peer_ratchet_key)
{
    return detail::start_as_alice(keys, peer_ratchet_key, system_random);
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
    return detail::encrypt(state, plaintext, system_random);
}

Result<SecretBytes> decrypt(State& state, const wire::RatchetMessage& message, std::uint64_t now)
{
    return detail::decrypt(state, message, now, system_random);
}

namespace detail {

Result<State> start_as_alice(const handshake::SessionKeys& keys, ByteView peer_ratchet_key, const RandomSource& random)
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
    crypto::ByteArray<crypto::x25519_key_size> peer{};
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

Result<wire::RatchetMessage> encrypt(State& state, ByteView plaintext, const RandomSource& random)
{
    if (!state.sending_chain || !state.sending_header_key) {
        return std::unexpected(Error::cannot_send);
    }
    if (plaintext.size() > max_plaintext_size) {
        return std::unexpected(Error::message_too_large);
    }
    if (state.sent == std::numeric_limits<std::uint32_t>::max()) {
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

Result<SecretBytes> decrypt(State& state, const wire::RatchetMessage& message, std::uint64_t now, const RandomSource& random)
{
    State work = clone(state);
    forget_expired(work, now);
    const auto body_associated_data = joined(work.associated_data, message.encrypted_header);

    if (auto message_key = take_skipped(work, message.encrypted_header)) {
        auto plaintext = crypto::aead_open(*message_key, body_associated_data, message.body);
        if (!plaintext) {
            return std::unexpected(Error::authentication_failed);
        }
        work.has_received = true;
        state = std::move(work);
        return std::move(*plaintext);
    }

    std::optional<wire::RatchetHeader> header;
    if (work.receiving_header_key) {
        header = open_header(*work.receiving_header_key, work.associated_data, message.encrypted_header);
    }
    if (header) {
        if (!work.receiving_ratchet || header->ratchet_key != *work.receiving_ratchet) {
            return std::unexpected(Error::unknown_header);
        }
        if (header->message_number < work.received) {
            return std::unexpected(Error::old_or_duplicate);
        }
    } else {
        header = open_header(work.next_receiving_header_key, work.associated_data, message.encrypted_header);
        if (!header) {
            return std::unexpected(Error::unknown_header);
        }
        if (auto skipped = skip_message_keys(work, header->previous_chain_length, now); !skipped) {
            return std::unexpected(skipped.error());
        }
        if (auto stepped = dh_ratchet(work, header->ratchet_key, random); !stepped) {
            return std::unexpected(stepped.error());
        }
    }
    if (header->message_number == std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error::exhausted);
    }
    if (auto skipped = skip_message_keys(work, header->message_number, now); !skipped) {
        return std::unexpected(skipped.error());
    }
    auto step = kdf_ck(*work.receiving_chain);
    auto plaintext = crypto::aead_open(step.message_key, body_associated_data, message.body);
    if (!plaintext) {
        return std::unexpected(Error::authentication_failed);
    }
    work.receiving_chain = std::move(step.chain_key);
    ++work.received;
    work.has_received = true;
    state = std::move(work);
    return std::move(*plaintext);
}

}

}
