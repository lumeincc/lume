// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/ratchet/ratchet.hpp"

#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/random.hpp"
#include "lume/handshake/prekey.hpp"
#include "lume/identity/phrase.hpp"
#include "ratchet/ratchet_internal.hpp"
#include "support/mutate.hpp"
#include "support/random_stream.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <span>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace lume::ratchet {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

constexpr std::uint64_t now = 1'800'000'000;

template <typename T, typename E>
T must(std::expected<T, E> result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
    return std::move(*result);
}

struct Pair {
    State alice;
    State bob;
};

Pair new_pair()
{
    const auto alice = must(identity::derive_identity(crypto::random_secret(identity::entropy_size)));
    const auto bob = must(identity::derive_identity(crypto::random_secret(identity::entropy_size)));
    const auto signed_prekey = crypto::x25519_generate();
    const auto kem_prekey = crypto::mlkem768_generate();
    const auto seal_key = crypto::x25519_generate();
    const auto facts = [](wire::PrekeyKind kind, std::uint32_t id) {
        return handshake::PrekeyFacts{.kind = kind, .id = id, .created_at = now, .generation = 1};
    };
    const handshake::Bundle bundle{
        .identity = identity::public_identity(bob),
        .generation = 1,
        .signed_prekey = must(handshake::make_prekey_x(bob, facts(wire::PrekeyKind::signed_prekey, 1), signed_prekey.public_key)),
        .kem_prekey = must(handshake::make_prekey_kem(bob, facts(wire::PrekeyKind::kem_last_resort, 2), kem_prekey.public_key)),
        .seal_key = must(handshake::make_prekey_x(bob, facts(wire::PrekeyKind::seal_key, 3), seal_key.public_key)),
        .one_time_prekey = std::nullopt};
    auto initiation = must(handshake::initiate(alice, bundle, std::nullopt, now));
    const auto response = must(handshake::respond(
        bob, initiation.header,
        handshake::ResponderKeys{
            .signed_prekey_id = 1,
            .signed_prekey = std::cref(signed_prekey),
            .kem_kind = wire::PrekeyKind::kem_last_resort,
            .kem_id = 2,
            .kem_prekey = std::cref(kem_prekey),
            .one_time_prekey_id = std::nullopt,
            .one_time_prekey = std::nullopt},
        std::nullopt));
    return Pair{
        .alice = must(start_as_alice(initiation.keys, initiation.peer_ratchet_key)),
        .bob = start_as_bob(response, signed_prekey)};
}

Bytes text(const std::string& value)
{
    return {value.begin(), value.end()};
}

std::string text_of(const SecretBytes& value)
{
    return {value.view().begin(), value.view().end()};
}

wire::RatchetMessage send(State& state, const std::string& value)
{
    return must(encrypt(state, text(value)));
}

Bytes fingerprint(const State& state)
{
    crypto::Encoder encoder;
    const auto optional_key = [&encoder](const std::optional<SecretBytes>& key) {
        encoder.u8(key ? 1 : 0);
        if (key) {
            encoder.prefixed(key->view());
        }
    };
    encoder.raw(state.sending_ratchet.public_key).prefixed(state.sending_ratchet.secret_key.view());
    encoder.u8(state.receiving_ratchet ? 1 : 0);
    if (state.receiving_ratchet) {
        encoder.raw(*state.receiving_ratchet);
    }
    encoder.prefixed(state.root_key.view());
    optional_key(state.sending_chain);
    optional_key(state.receiving_chain);
    optional_key(state.sending_header_key);
    optional_key(state.receiving_header_key);
    encoder.prefixed(state.next_sending_header_key.view()).prefixed(state.next_receiving_header_key.view());
    encoder.u32(state.sent).u32(state.received).u32(state.previous_sent).u8(state.has_received ? 1 : 0);
    const auto& skipped = state.skipped;
    for (std::size_t chain = 0; chain < skipped.chain_count(); ++chain) {
        encoder.prefixed(skipped.header_key(chain)).raw(skipped.ratchet_key(chain));
        std::size_t index = 0;
        for (const auto& entry : skipped.entries(chain)) {
            encoder.u32(entry.number).u64(entry.stored_at).prefixed(skipped.message_key(chain, index));
            ++index;
        }
    }
    encoder.prefixed(state.associated_data);
    const auto digest = crypto::sha256(encoder.view());
    return {digest.begin(), digest.end()};
}

wire::RatchetMessage forged(const SecretBytes& header_key, const Bytes& associated_data, const wire::RatchetHeader& header)
{
    const auto encrypted_header = must(crypto::aead_seal(header_key, associated_data, wire::encode(header)));
    wire::RatchetMessage message;
    std::ranges::copy(encrypted_header, message.encrypted_header.begin());
    message.body = must(crypto::aead_seal(crypto::random_secret(crypto::aead_key_size), {}, text("forged")));
    return message;
}

const SecretBytes& sending_header_key_of(const State& state)
{
    if (!state.sending_header_key) {
        throw std::runtime_error("the state has no sending header key");
    }
    return *state.sending_header_key;
}

Error refusal(State& receiver, const wire::RatchetMessage& message)
{
    const auto before = fingerprint(receiver);
    const auto opened = decrypt(receiver, message, now, max_skipped_keys);
    EXPECT_EQ(fingerprint(receiver), before);
    return opened ? Error::library_failure : opened.error();
}

Bytes hex_field(const nlohmann::json& object, const char* name)
{
    return test::from_hex(object.at(name).get<std::string>());
}

Error error_named(const std::string& name)
{
    if (name == "old_or_duplicate") {
        return Error::old_or_duplicate;
    }
    if (name == "unknown_header") {
        return Error::unknown_header;
    }
    throw std::runtime_error("the vectors name an error the test does not know");
}

TEST(Ratchet, MatchesTheLumeTranscript)
{
    const auto handshake_case = test::load_vectors("lume/handshake.json").at("cases").at(0);
    const auto transcript = test::load_vectors("lume/ratchet.json");
    const handshake::SessionKeys keys{
        .root_key = SecretBytes::copy_of(hex_field(handshake_case, "root_key")),
        .header_key_alice = SecretBytes::copy_of(hex_field(handshake_case, "header_key_alice")),
        .next_header_key_bob = SecretBytes::copy_of(hex_field(handshake_case, "next_header_key_bob")),
        .associated_data = hex_field(handshake_case, "associated_data")};
    const auto signed_prekey =
        must(crypto::x25519_from_secret(SecretBytes::copy_of(hex_field(handshake_case.at("signed_prekey"), "secret"))));

    test::RandomStream alice_random(transcript.at("random_seeds").at("alice").get<std::string>());
    test::RandomStream bob_random(transcript.at("random_seeds").at("bob").get<std::string>());
    const detail::RandomSource alice_source = std::ref(alice_random);
    const detail::RandomSource bob_source = std::ref(bob_random);
    auto alice = must(detail::start_as_alice(keys, signed_prekey.public_key, alice_source));
    auto bob = start_as_bob(keys, signed_prekey);

    std::map<std::string, wire::RatchetMessage> sent;
    int steps = 0;
    int replays = 0;
    for (const auto& step : transcript.at("steps")) {
        const auto party = step.at("party").get<std::string>();
        const auto id = step.at("id").get<std::string>();
        const auto action = step.at("action").get<std::string>();
        auto& state = party == "alice" ? alice : bob;
        const auto& source = party == "alice" ? alice_source : bob_source;
        if (action == "send") {
            const auto message = detail::encrypt(state, hex_field(step, "plaintext"), source);
            ASSERT_TRUE(message.has_value()) << id;
            EXPECT_EQ(test::to_hex(message->encrypted_header), step.at("encrypted_header").get<std::string>()) << id;
            EXPECT_EQ(test::to_hex(message->body), step.at("body").get<std::string>()) << id;
            sent.emplace(id, *message);
        } else if (action == "receive") {
            const auto opened = detail::decrypt(state, sent.at(id), now, source);
            ASSERT_TRUE(opened.has_value()) << id;
            EXPECT_TRUE(opened->equals(hex_field(step, "plaintext"))) << id;
        } else {
            ASSERT_EQ(action, "replay");
            const auto before = fingerprint(state);
            const auto refused = detail::decrypt(state, sent.at(id), now, source);
            ASSERT_FALSE(refused.has_value()) << id;
            EXPECT_EQ(refused.error(), error_named(step.at("error").get<std::string>())) << id;
            EXPECT_EQ(fingerprint(state), before) << id;
            ++replays;
        }
        ++steps;
    }
    EXPECT_EQ(steps, 24);
    EXPECT_EQ(replays, 2);
}

TEST(Ratchet, AliceAndBobTalk)
{
    auto pair = new_pair();
    for (int round = 0; round < 5; ++round) {
        const auto ping = "ping " + std::to_string(round);
        const auto opened = decrypt(pair.bob, send(pair.alice, ping), now, max_skipped_keys);
        ASSERT_TRUE(opened.has_value()) << round;
        EXPECT_EQ(text_of(*opened), ping);
        const auto pong = "pong " + std::to_string(round);
        const auto answered = decrypt(pair.alice, send(pair.bob, pong), now, max_skipped_keys);
        ASSERT_TRUE(answered.has_value()) << round;
        EXPECT_EQ(text_of(*answered), pong);
    }
    EXPECT_TRUE(pair.alice.has_received);
    EXPECT_TRUE(pair.bob.has_received);
}

TEST(Ratchet, BobCannotSendBeforeAliceSpeaks)
{
    auto pair = new_pair();
    EXPECT_EQ(encrypt(pair.bob, text("too early")).error(), Error::cannot_send);
}

TEST(Ratchet, MessagesHaveTheSpecifiedShape)
{
    auto pair = new_pair();
    const auto message = send(pair.alice, "hello");
    EXPECT_EQ(message.encrypted_header.size(), wire::encrypted_header_size);
    EXPECT_EQ(message.body.size(), crypto::aead_overhead + 5);
    EXPECT_EQ(encrypt(pair.alice, Bytes(max_plaintext_size + 1)).error(), Error::message_too_large);
    const auto largest = encrypt(pair.alice, Bytes(max_plaintext_size));
    ASSERT_TRUE(largest.has_value());
    EXPECT_EQ(largest->body.size(), wire::ratchet_body_bound);
    EXPECT_EQ(wire::encode(*largest).size(), wire::encrypted_header_size + 4 + wire::ratchet_body_bound);
}

TEST(Ratchet, OutOfOrderMessagesInOneChainAllOpenOnce)
{
    auto pair = new_pair();
    std::vector<wire::RatchetMessage> sent;
    sent.reserve(5);
    for (int index = 0; index < 5; ++index) {
        sent.push_back(send(pair.alice, "message " + std::to_string(index)));
    }
    for (const int index : {3, 0, 4, 1, 2}) {
        const auto opened = decrypt(pair.bob, sent.at(static_cast<std::size_t>(index)), now, max_skipped_keys);
        ASSERT_TRUE(opened.has_value()) << index;
        EXPECT_EQ(text_of(*opened), "message " + std::to_string(index));
    }
    for (const auto& message : sent) {
        const auto before = fingerprint(pair.bob);
        const auto again = decrypt(pair.bob, message, now, max_skipped_keys);
        ASSERT_FALSE(again.has_value());
        EXPECT_EQ(again.error(), Error::old_or_duplicate);
        EXPECT_EQ(fingerprint(pair.bob), before);
    }
}

TEST(Ratchet, ALateMessageFromAnEarlierChainStillOpens)
{
    auto pair = new_pair();
    const auto first = send(pair.alice, "a0");
    const auto late = send(pair.alice, "a1");
    ASSERT_TRUE(decrypt(pair.bob, first, now, max_skipped_keys).has_value());
    ASSERT_TRUE(decrypt(pair.alice, send(pair.bob, "b0"), now, max_skipped_keys).has_value());
    const auto next_chain = send(pair.alice, "a2");
    ASSERT_TRUE(decrypt(pair.bob, next_chain, now, max_skipped_keys).has_value());
    const auto opened = decrypt(pair.bob, late, now, max_skipped_keys);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(text_of(*opened), "a1");
}

TEST(Ratchet, SkippingMoreThanTheBoundIsRefusedWithoutChangingTheSession)
{
    auto pair = new_pair();
    std::vector<wire::RatchetMessage> sent;
    sent.reserve(max_skip + 2);
    for (std::uint32_t index = 0; index <= max_skip + 1; ++index) {
        sent.push_back(send(pair.alice, "m"));
    }
    const auto before = fingerprint(pair.bob);
    const auto too_far = decrypt(pair.bob, sent.back(), now, max_skipped_keys);
    ASSERT_FALSE(too_far.has_value());
    EXPECT_EQ(too_far.error(), Error::too_many_skipped);
    EXPECT_EQ(fingerprint(pair.bob), before);
    ASSERT_TRUE(decrypt(pair.bob, sent.at(max_skip), now, max_skipped_keys).has_value());
    EXPECT_EQ(pair.bob.skipped.size(), max_skip);
}

TEST(Ratchet, AMessageFromAnotherSessionIsUnknown)
{
    auto first = new_pair();
    auto second = new_pair();
    const auto stranger = send(second.alice, "not for you");
    const auto before = fingerprint(first.bob);
    const auto opened = decrypt(first.bob, stranger, now, max_skipped_keys);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), Error::unknown_header);
    EXPECT_EQ(fingerprint(first.bob), before);
}

TEST(Ratchet, ASkippedKeyOpensUntilItsLifetimeEnds)
{
    auto pair = new_pair();
    const auto late = send(pair.alice, "late");
    ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "on time"), now, max_skipped_keys).has_value());
    EXPECT_EQ(pair.bob.skipped.size(), 1U);
    const auto in_time = decrypt(pair.bob, late, now + skipped_key_lifetime, max_skipped_keys);
    ASSERT_TRUE(in_time.has_value());
    EXPECT_EQ(text_of(*in_time), "late");
}

TEST(Ratchet, SkippedKeysExpireWithoutAnyMessageArriving)
{
    auto pair = new_pair();
    const auto late = send(pair.alice, "late");
    ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "on time"), now, max_skipped_keys).has_value());
    expire(pair.bob, now + skipped_key_lifetime);
    EXPECT_EQ(pair.bob.skipped.size(), 1U);
    expire(pair.bob, now + skipped_key_lifetime + 1);
    EXPECT_EQ(pair.bob.skipped.size(), 0U);
    EXPECT_EQ(pair.bob.skipped.chain_count(), 0U);
    const auto gone = decrypt(pair.bob, late, now, max_skipped_keys);
    ASSERT_FALSE(gone.has_value());
    EXPECT_EQ(gone.error(), Error::old_or_duplicate);
}

TEST(Ratchet, AFailedDecryptionStillForgetsExpiredKeys)
{
    auto pair = new_pair();
    const auto late = send(pair.alice, "late");
    ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "on time"), now, max_skipped_keys).has_value());
    auto other = new_pair();
    const auto stranger = send(other.alice, "not for you");
    EXPECT_EQ(decrypt(pair.bob, stranger, now + skipped_key_lifetime + 1, max_skipped_keys).error(), Error::unknown_header);
    EXPECT_EQ(pair.bob.skipped.size(), 0U);
    EXPECT_EQ(decrypt(pair.bob, late, now, max_skipped_keys).error(), Error::old_or_duplicate);
}

TEST(Ratchet, ARequestKeepsOnlyItsNewestSkippedKeys)
{
    auto pair = new_pair();
    std::vector<wire::RatchetMessage> sent;
    sent.reserve(max_skipped_keys_in_a_request + 9);
    for (std::size_t index = 0; index < max_skipped_keys_in_a_request + 9; ++index) {
        sent.push_back(send(pair.alice, "m" + std::to_string(index)));
    }
    ASSERT_TRUE(decrypt(pair.bob, sent.back(), now, max_skipped_keys_in_a_request).has_value());
    EXPECT_EQ(pair.bob.skipped.size(), max_skipped_keys_in_a_request);
    EXPECT_EQ(pair.bob.skipped.entries(0).front().number, 8U);
    EXPECT_EQ(decrypt(pair.bob, sent.at(7), now, max_skipped_keys_in_a_request).error(), Error::old_or_duplicate);
    const auto kept = decrypt(pair.bob, sent.at(8), now, max_skipped_keys_in_a_request);
    ASSERT_TRUE(kept.has_value());
    EXPECT_EQ(text_of(*kept), "m8");
}

TEST(Ratchet, ASkipAcrossADhStepIsBounded)
{
    const auto next_chain_after = [](std::uint32_t lost, Pair& pair) {
        static_cast<void>(must(decrypt(pair.bob, send(pair.alice, "a0"), now, max_skipped_keys)));
        const auto reply = send(pair.bob, "b0");
        for (std::uint32_t index = 0; index < lost; ++index) {
            static_cast<void>(send(pair.alice, "lost"));
        }
        static_cast<void>(must(decrypt(pair.alice, reply, now, max_skipped_keys)));
        return send(pair.alice, "next chain");
    };
    auto over = new_pair();
    const auto too_far = next_chain_after(max_skip + 1, over);
    EXPECT_EQ(refusal(over.bob, too_far), Error::too_many_skipped);

    auto at = new_pair();
    const auto just_in = next_chain_after(max_skip, at);
    ASSERT_TRUE(decrypt(at.bob, just_in, now, max_skipped_keys).has_value());
    EXPECT_EQ(at.bob.skipped.size(), max_skip);
}

TEST(Ratchet, AWeakOrNonCanonicalRatchetKeyIsRefused)
{
    auto pair = new_pair();
    const auto& first_header_key = sending_header_key_of(pair.alice);
    const auto header_with = [](const RatchetKey& key) {
        return wire::RatchetHeader{.ratchet_key = key, .previous_chain_length = 0, .message_number = 0};
    };
    const RatchetKey low_order{};
    EXPECT_EQ(refusal(pair.bob, forged(first_header_key, pair.alice.associated_data, header_with(low_order))), Error::weak_key);
    auto top_bit = pair.alice.sending_ratchet.public_key;
    top_bit.back() = static_cast<std::uint8_t>(top_bit.back() | 0x80U);
    EXPECT_EQ(refusal(pair.bob, forged(first_header_key, pair.alice.associated_data, header_with(top_bit))), Error::weak_key);
    EXPECT_TRUE(decrypt(pair.bob, send(pair.alice, "genuine"), now, max_skipped_keys).has_value());
}

TEST(Ratchet, ExhaustedCountersAreRefused)
{
    auto pair = new_pair();
    const auto last = std::numeric_limits<std::uint32_t>::max();
    const auto& first_header_key = sending_header_key_of(pair.alice);
    const wire::RatchetHeader at_the_end{
        .ratchet_key = pair.alice.sending_ratchet.public_key, .previous_chain_length = 0, .message_number = last};
    EXPECT_EQ(refusal(pair.bob, forged(first_header_key, pair.alice.associated_data, at_the_end)), Error::exhausted);

    ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "genuine"), now, max_skipped_keys).has_value());
    EXPECT_EQ(refusal(pair.bob, forged(first_header_key, pair.alice.associated_data, at_the_end)), Error::exhausted);

    pair.alice.sent = last;
    EXPECT_EQ(encrypt(pair.alice, text("one too many")).error(), Error::exhausted);
}

TEST(Ratchet, TheSkippedStoreKeepsAtMostEightChains)
{
    auto pair = new_pair();
    std::vector<wire::RatchetMessage> stragglers;
    stragglers.reserve(max_skipped_header_keys + 2);
    for (std::size_t chain = 0; chain < max_skipped_header_keys + 2; ++chain) {
        stragglers.push_back(send(pair.alice, "straggler"));
        ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "arrives"), now, max_skipped_keys).has_value());
        ASSERT_TRUE(decrypt(pair.alice, send(pair.bob, "reply"), now, max_skipped_keys).has_value());
    }
    EXPECT_EQ(pair.bob.skipped.size(), max_skipped_header_keys);
    EXPECT_FALSE(decrypt(pair.bob, stragglers.front(), now, max_skipped_keys).has_value());
    EXPECT_TRUE(decrypt(pair.bob, stragglers.back(), now, max_skipped_keys).has_value());
}

TEST(Ratchet, TheSkippedStoreKeepsAtMostItsLimitOfKeys)
{
    auto pair = new_pair();
    for (std::size_t chain = 0; chain < 5; ++chain) {
        for (std::uint32_t index = 0; index < max_skip; ++index) {
            static_cast<void>(send(pair.alice, "skipped"));
        }
        ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "arrives"), now, max_skipped_keys).has_value());
        ASSERT_TRUE(decrypt(pair.alice, send(pair.bob, "reply"), now, max_skipped_keys).has_value());
    }
    EXPECT_EQ(pair.bob.skipped.size(), max_skipped_keys);
}

Bytes bytes_of(crypto::ByteView view)
{
    return {view.begin(), view.end()};
}

Bytes keys_from(std::size_t count, std::uint8_t first)
{
    Bytes keys;
    for (std::size_t index = 0; index < count; ++index) {
        keys.insert(keys.end(), crypto::aead_key_size, static_cast<std::uint8_t>(first + index));
    }
    return keys;
}

RatchetKey ratchet_key_of(std::uint8_t value)
{
    RatchetKey key{};
    key.fill(value);
    return key;
}

TEST(SkippedKeys, KeepsRunsByChainAndFindsThem)
{
    const auto first_header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, 0xa1));
    const auto second_header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, 0xb2));
    SkippedKeys store;
    store.add(first_header, ratchet_key_of(1), 5, keys_from(3, 0x10), now, max_skipped_keys);
    store.add(first_header, ratchet_key_of(1), 8, keys_from(1, 0x13), now, max_skipped_keys);
    store.add(second_header, ratchet_key_of(2), 0, keys_from(2, 0x20), now, max_skipped_keys);
    ASSERT_EQ(store.chain_count(), 2U);
    EXPECT_EQ(store.size(), 6U);
    EXPECT_TRUE(first_header.equals(store.header_key(0)));
    EXPECT_TRUE(second_header.equals(store.header_key(1)));
    EXPECT_EQ(store.ratchet_key(1), ratchet_key_of(2));
    EXPECT_EQ(store.find(0, 8), std::optional<std::size_t>(3));
    EXPECT_EQ(store.find(0, 9), std::nullopt);
    const auto key_of = [](std::uint8_t value) { return Bytes(crypto::aead_key_size, value); };
    EXPECT_EQ(bytes_of(store.message_key(0, 2)), key_of(0x12));
    EXPECT_EQ(bytes_of(store.message_key(1, 1)), key_of(0x21));

    store.erase(0, 1);
    EXPECT_EQ(store.size(), 5U);
    EXPECT_EQ(store.find(0, 7), std::optional<std::size_t>(1));
    EXPECT_EQ(bytes_of(store.message_key(0, 1)), key_of(0x12));
    EXPECT_EQ(bytes_of(store.message_key(1, 0)), key_of(0x20));

    for (int round = 0; round < 3; ++round) {
        store.erase(0, 0);
    }
    ASSERT_EQ(store.chain_count(), 1U);
    EXPECT_TRUE(second_header.equals(store.header_key(0)));
    EXPECT_EQ(bytes_of(store.message_key(0, 1)), key_of(0x21));
}

TEST(SkippedKeys, EvictsTheOldestChainAndTheOldestKeys)
{
    SkippedKeys store;
    for (std::uint8_t chain = 0; chain < max_skipped_header_keys + 2; ++chain) {
        const auto header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, chain));
        store.add(header, ratchet_key_of(chain), 0, keys_from(2, static_cast<std::uint8_t>(chain * 2)), now, max_skipped_keys);
    }
    ASSERT_EQ(store.chain_count(), max_skipped_header_keys);
    EXPECT_EQ(store.ratchet_key(0), ratchet_key_of(2));
    EXPECT_EQ(store.size(), 2 * max_skipped_header_keys);

    SkippedKeys limited;
    const auto header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, 0x77));
    limited.add(header, ratchet_key_of(7), 0, keys_from(10, 0), now, 4);
    limited.add(header, ratchet_key_of(7), 10, keys_from(2, 10), now, 4);
    ASSERT_EQ(limited.size(), 4U);
    const auto entries = limited.entries(0);
    EXPECT_EQ(entries.front().number, 8U);
    EXPECT_EQ(entries.back().number, 11U);
    EXPECT_EQ(bytes_of(limited.message_key(0, 0)), Bytes(crypto::aead_key_size, 8));
}

TEST(SkippedKeys, RefusesToReachForAKeyItDoesNotHold)
{
    SkippedKeys store;
    EXPECT_THROW(static_cast<void>(store.header_key(0)), std::out_of_range);
    EXPECT_THROW(static_cast<void>(store.message_key(0, 0)), std::out_of_range);
    const auto header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, 0x01));
    store.add(header, ratchet_key_of(1), 0, keys_from(1, 0x10), now, max_skipped_keys);
    store.add(header, ratchet_key_of(1), 1, keys_from(1, 0x11), now, 0);
    store.add(header, ratchet_key_of(1), 1, {}, now, max_skipped_keys);
    EXPECT_EQ(store.size(), 1U);
    EXPECT_THROW(static_cast<void>(store.message_key(0, 1)), std::out_of_range);
    EXPECT_THROW(store.erase(0, 1), std::out_of_range);
    EXPECT_THROW(store.erase(1, 0), std::out_of_range);
    EXPECT_EQ(store.size(), 1U);
}

TEST(SkippedKeys, RefusesKeysThatAreNotWholeKeysBeforeChangingAnything)
{
    SkippedKeys store;
    const auto header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, 0x01));
    store.add(header, ratchet_key_of(1), 0, keys_from(1, 0x10), now, max_skipped_keys);
    EXPECT_THROW(store.add(header, ratchet_key_of(2), 1, Bytes(crypto::aead_key_size + 1, 0x11), now, 1), std::invalid_argument);
    const auto short_header = SecretBytes::copy_of(Bytes(crypto::aead_key_size - 1, 0x02));
    EXPECT_THROW(store.add(short_header, ratchet_key_of(2), 1, keys_from(1, 0x12), now, 1), std::invalid_argument);
    EXPECT_EQ(store.size(), 1U);
    EXPECT_EQ(store.chain_count(), 1U);
    EXPECT_EQ(Bytes(store.message_key(0, 0).begin(), store.message_key(0, 0).end()), Bytes(crypto::aead_key_size, 0x10));
}

TEST(SkippedKeys, ExpiresByAgeAndClonesIndependently)
{
    SkippedKeys store;
    const auto old_header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, 0x01));
    const auto new_header = SecretBytes::copy_of(Bytes(crypto::aead_key_size, 0x02));
    store.add(old_header, ratchet_key_of(1), 0, keys_from(2, 0x30), now, max_skipped_keys);
    store.add(new_header, ratchet_key_of(2), 0, keys_from(1, 0x40), now + 10, max_skipped_keys);
    auto copy = store.clone();

    store.expire(now + skipped_key_lifetime + 1);
    ASSERT_EQ(store.chain_count(), 1U);
    EXPECT_TRUE(new_header.equals(store.header_key(0)));
    EXPECT_EQ(bytes_of(store.message_key(0, 0)), Bytes(crypto::aead_key_size, 0x40));
    store.expire(now + skipped_key_lifetime + 11);
    EXPECT_EQ(store.size(), 0U);

    EXPECT_EQ(copy.size(), 3U);
    EXPECT_EQ(bytes_of(copy.message_key(0, 1)), Bytes(crypto::aead_key_size, 0x31));
}

struct ModelKey {
    std::uint8_t chain = 0;
    std::uint32_t number = 0;
    std::uint8_t key = 0;
    std::uint64_t stored_at = 0;

    friend bool operator==(const ModelKey&, const ModelKey&) = default;
};

std::size_t runs_of(const std::vector<ModelKey>& model)
{
    std::size_t runs = 0;
    for (std::size_t index = 0; index < model.size(); ++index) {
        if (index == 0 || model.at(index).chain != model.at(index - 1).chain) {
            ++runs;
        }
    }
    return runs;
}

void add_one_at_a_time(std::vector<ModelKey>& model, const std::vector<ModelKey>& added, std::size_t limit)
{
    const auto bound = std::min(limit, max_skipped_keys);
    if (bound == 0) {
        return;
    }
    for (const auto& key : added) {
        const bool new_chain = model.empty() || model.back().chain != key.chain;
        model.push_back(key);
        while (new_chain && runs_of(model) > max_skipped_header_keys) {
            const auto oldest = model.front().chain;
            std::erase_if(model, [oldest](const ModelKey& entry) { return entry.chain == oldest; });
        }
        while (model.size() > bound) {
            model.erase(model.begin());
        }
    }
}

std::vector<ModelKey> contents_of(const SkippedKeys& store)
{
    std::vector<ModelKey> keys;
    for (std::size_t chain = 0; chain < store.chain_count(); ++chain) {
        const auto id = store.ratchet_key(chain).front();
        RC_ASSERT(bytes_of(store.header_key(chain)) == Bytes(crypto::aead_key_size, id));
        std::size_t index = 0;
        for (const auto& entry : store.entries(chain)) {
            const auto key = bytes_of(store.message_key(chain, index));
            RC_ASSERT(key == Bytes(crypto::aead_key_size, key.front()));
            keys.push_back(ModelKey{.chain = id, .number = entry.number, .key = key.front(), .stored_at = entry.stored_at});
            ++index;
        }
    }
    return keys;
}

void erase_at(SkippedKeys& store, std::size_t position)
{
    for (std::size_t chain = 0; chain < store.chain_count(); ++chain) {
        const auto count = store.entries(chain).size();
        if (position < count) {
            store.erase(chain, position);
            return;
        }
        position -= count;
    }
}

RC_GTEST_PROP(SkippedKeysProperties, BehavesLikeAStoreThatAddsOneKeyAtATime, ())
{
    SkippedKeys store;
    std::vector<ModelKey> model;
    std::uint8_t chain = 1;
    std::uint8_t next_key = 0;
    std::uint32_t next_number = 0;
    const auto steps = *rc::gen::inRange(1, 40);
    for (int step = 0; step < steps; ++step) {
        const auto action = *rc::gen::inRange(0, 6);
        if (action < 4) {
            if (*rc::gen::arbitrary<bool>()) {
                ++chain;
            }
            const auto count = *rc::gen::inRange<std::size_t>(0, 40);
            const auto limit = *rc::gen::element<std::size_t>(std::size_t{0}, std::size_t{1}, std::size_t{4}, max_skipped_keys_in_a_request, std::size_t{100}, max_skipped_keys);
            const auto at = now + *rc::gen::inRange<std::uint64_t>(0, 3 * skipped_key_lifetime);
            std::vector<ModelKey> added;
            Bytes keys;
            for (std::size_t index = 0; index < count; ++index) {
                added.push_back(ModelKey{
                    .chain = chain, .number = next_number + static_cast<std::uint32_t>(index), .key = next_key, .stored_at = at});
                keys.insert(keys.end(), crypto::aead_key_size, next_key);
                ++next_key;
            }
            store.add(SecretBytes::copy_of(Bytes(crypto::aead_key_size, chain)), ratchet_key_of(chain), next_number, keys, at, limit);
            add_one_at_a_time(model, added, limit);
            next_number += static_cast<std::uint32_t>(count);
        } else if (action == 4 && !model.empty()) {
            const auto position = *rc::gen::inRange<std::size_t>(0, model.size());
            erase_at(store, position);
            model.erase(model.begin() + static_cast<std::ptrdiff_t>(position));
        } else {
            const auto at = now + *rc::gen::inRange<std::uint64_t>(0, 4 * skipped_key_lifetime);
            store.expire(at);
            std::erase_if(model, [at](const ModelKey& entry) {
                return at > entry.stored_at && at - entry.stored_at > skipped_key_lifetime;
            });
        }
        RC_ASSERT(contents_of(store) == model);
        RC_ASSERT(store.chain_count() == runs_of(model));
    }
}

RC_GTEST_PROP(RatchetProperties, AnyChangedBitIsRefusedAndChangesNothing, ())
{
    auto pair = new_pair();
    ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "warm up"), now, max_skipped_keys).has_value());
    const auto message = send(pair.bob, *rc::gen::arbitrary<std::string>());
    auto bytes = wire::encode(message);
    const auto index = *rc::gen::inRange<std::size_t>(0, bytes.size());
    const auto bit = *rc::gen::inRange<unsigned>(0, 8);
    bytes = test::flip_bit(bytes, index, bit);
    const auto forged = wire::decode(bytes, wire::read_ratchet_message);
    const auto before = fingerprint(pair.alice);
    if (forged) {
        RC_ASSERT_FALSE(decrypt(pair.alice, *forged, now, max_skipped_keys).has_value());
    }
    RC_ASSERT(fingerprint(pair.alice) == before);
    RC_ASSERT(decrypt(pair.alice, message, now, max_skipped_keys).has_value());
}

struct InFlight {
    bool from_alice = true;
    std::string plaintext;
    wire::RatchetMessage message;
};

RC_GTEST_PROP(RatchetProperties, EveryDeliveredMessageOpensExactlyOnceInAnyOrder, ())
{
    auto pair = new_pair();
    std::vector<InFlight> in_flight;
    std::vector<InFlight> delivered;
    int counter = 0;
    const auto steps = *rc::gen::inRange(1, 60);
    for (int step = 0; step < steps; ++step) {
        const auto action = *rc::gen::inRange(0, 4);
        if (action == 0 || (action == 1 && !pair.bob.has_received)) {
            const auto plaintext = "a" + std::to_string(counter++);
            in_flight.push_back(InFlight{.from_alice = true, .plaintext = plaintext, .message = send(pair.alice, plaintext)});
        } else if (action == 1) {
            const auto plaintext = "b" + std::to_string(counter++);
            in_flight.push_back(InFlight{.from_alice = false, .plaintext = plaintext, .message = send(pair.bob, plaintext)});
        } else if (!in_flight.empty()) {
            const auto pick = *rc::gen::inRange<std::size_t>(0, in_flight.size());
            auto item = std::move(in_flight.at(pick));
            in_flight.erase(in_flight.begin() + static_cast<std::ptrdiff_t>(pick));
            auto& receiver = item.from_alice ? pair.bob : pair.alice;
            const auto opened = decrypt(receiver, item.message, now, max_skipped_keys);
            RC_ASSERT(opened.has_value());
            RC_ASSERT(text_of(*opened) == item.plaintext);
            delivered.push_back(std::move(item));
        }
    }
    for (const auto& item : delivered) {
        auto& receiver = item.from_alice ? pair.bob : pair.alice;
        const auto before = fingerprint(receiver);
        RC_ASSERT_FALSE(decrypt(receiver, item.message, now, max_skipped_keys).has_value());
        RC_ASSERT(fingerprint(receiver) == before);
    }
}

}
}
