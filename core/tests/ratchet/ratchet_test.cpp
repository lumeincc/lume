// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/ratchet/ratchet.hpp"

#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/random.hpp"
#include "lume/handshake/prekey.hpp"
#include "lume/identity/phrase.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
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
            .one_time_prekey = std::nullopt}));
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
    for (const auto& key : state.skipped) {
        encoder.prefixed(key.header_key.view()).raw(key.ratchet_key).u32(key.number).prefixed(key.message_key.view()).u64(key.stored_at);
    }
    encoder.prefixed(state.associated_data);
    const auto digest = crypto::sha256(encoder.view());
    return {digest.begin(), digest.end()};
}

class RandomStream {
public:
    explicit RandomStream(std::string seed)
        : seed_(std::move(seed))
    {
    }

    void operator()(std::span<std::uint8_t> output)
    {
        for (auto& byte : output) {
            if (pool_.empty()) {
                const Bytes seed(seed_.begin(), seed_.end());
                const auto block = crypto::sha256({seed, crypto::Encoder{}.u64(counter_).view()});
                ++counter_;
                pool_.assign(block.begin(), block.end());
            }
            byte = pool_.front();
            pool_.pop_front();
        }
    }

private:
    std::string seed_;
    std::uint64_t counter_ = 0;
    std::deque<std::uint8_t> pool_;
};

Bytes hex_field(const nlohmann::json& object, const char* name)
{
    return test::from_hex(object.at(name).get<std::string>());
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

    RandomStream alice_random(transcript.at("random_seeds").at("alice").get<std::string>());
    RandomStream bob_random(transcript.at("random_seeds").at("bob").get<std::string>());
    const detail::RandomSource alice_source = std::ref(alice_random);
    const detail::RandomSource bob_source = std::ref(bob_random);
    auto alice = must(detail::start_as_alice(keys, signed_prekey.public_key, alice_source));
    auto bob = start_as_bob(keys, signed_prekey);

    std::map<std::string, wire::RatchetMessage> sent;
    int steps = 0;
    for (const auto& step : transcript.at("steps")) {
        const auto party = step.at("party").get<std::string>();
        const auto id = step.at("id").get<std::string>();
        auto& state = party == "alice" ? alice : bob;
        const auto& source = party == "alice" ? alice_source : bob_source;
        const auto plaintext = hex_field(step, "plaintext");
        if (step.at("action").get<std::string>() == "send") {
            const auto message = detail::encrypt(state, plaintext, source);
            ASSERT_TRUE(message.has_value()) << id;
            EXPECT_EQ(test::to_hex(message->encrypted_header), step.at("encrypted_header").get<std::string>()) << id;
            EXPECT_EQ(test::to_hex(message->body), step.at("body").get<std::string>()) << id;
            sent.emplace(id, *message);
        } else {
            const auto opened = detail::decrypt(state, sent.at(id), now, source);
            ASSERT_TRUE(opened.has_value()) << id;
            EXPECT_TRUE(opened->equals(plaintext)) << id;
        }
        ++steps;
    }
    EXPECT_EQ(steps, 14);
}

TEST(Ratchet, AliceAndBobTalk)
{
    auto pair = new_pair();
    for (int round = 0; round < 5; ++round) {
        const auto ping = "ping " + std::to_string(round);
        const auto opened = decrypt(pair.bob, send(pair.alice, ping), now);
        ASSERT_TRUE(opened.has_value()) << round;
        EXPECT_EQ(text_of(*opened), ping);
        const auto pong = "pong " + std::to_string(round);
        const auto answered = decrypt(pair.alice, send(pair.bob, pong), now);
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
        const auto opened = decrypt(pair.bob, sent.at(static_cast<std::size_t>(index)), now);
        ASSERT_TRUE(opened.has_value()) << index;
        EXPECT_EQ(text_of(*opened), "message " + std::to_string(index));
    }
    for (const auto& message : sent) {
        const auto before = fingerprint(pair.bob);
        const auto again = decrypt(pair.bob, message, now);
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
    ASSERT_TRUE(decrypt(pair.bob, first, now).has_value());
    ASSERT_TRUE(decrypt(pair.alice, send(pair.bob, "b0"), now).has_value());
    const auto next_chain = send(pair.alice, "a2");
    ASSERT_TRUE(decrypt(pair.bob, next_chain, now).has_value());
    const auto opened = decrypt(pair.bob, late, now);
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
    const auto too_far = decrypt(pair.bob, sent.back(), now);
    ASSERT_FALSE(too_far.has_value());
    EXPECT_EQ(too_far.error(), Error::too_many_skipped);
    EXPECT_EQ(fingerprint(pair.bob), before);
    ASSERT_TRUE(decrypt(pair.bob, sent.at(max_skip), now).has_value());
    EXPECT_EQ(pair.bob.skipped.size(), max_skip);
}

TEST(Ratchet, AMessageFromAnotherSessionIsUnknown)
{
    auto first = new_pair();
    auto second = new_pair();
    const auto stranger = send(second.alice, "not for you");
    const auto before = fingerprint(first.bob);
    const auto opened = decrypt(first.bob, stranger, now);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), Error::unknown_header);
    EXPECT_EQ(fingerprint(first.bob), before);
}

TEST(Ratchet, SkippedKeysExpireAfterFourteenDays)
{
    auto pair = new_pair();
    const auto late = send(pair.alice, "late");
    ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "on time"), now).has_value());
    EXPECT_EQ(pair.bob.skipped.size(), 1U);
    const auto too_late = decrypt(pair.bob, late, now + skipped_key_lifetime + 1);
    ASSERT_FALSE(too_late.has_value());
    EXPECT_EQ(too_late.error(), Error::old_or_duplicate);
    const auto in_time = decrypt(pair.bob, late, now + skipped_key_lifetime);
    ASSERT_TRUE(in_time.has_value());
    EXPECT_EQ(text_of(*in_time), "late");
}

TEST(Ratchet, TheSkippedStoreKeepsAtMostEightChains)
{
    auto pair = new_pair();
    std::vector<wire::RatchetMessage> stragglers;
    stragglers.reserve(max_skipped_header_keys + 2);
    for (std::size_t chain = 0; chain < max_skipped_header_keys + 2; ++chain) {
        stragglers.push_back(send(pair.alice, "straggler"));
        ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "arrives"), now).has_value());
        ASSERT_TRUE(decrypt(pair.alice, send(pair.bob, "reply"), now).has_value());
    }
    EXPECT_EQ(pair.bob.skipped.size(), max_skipped_header_keys);
    EXPECT_FALSE(decrypt(pair.bob, stragglers.front(), now).has_value());
    EXPECT_TRUE(decrypt(pair.bob, stragglers.back(), now).has_value());
}

TEST(Ratchet, TheSkippedStoreKeepsAtMostItsLimitOfKeys)
{
    auto pair = new_pair();
    for (std::size_t chain = 0; chain < 5; ++chain) {
        for (std::uint32_t index = 0; index < max_skip; ++index) {
            static_cast<void>(send(pair.alice, "skipped"));
        }
        ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "arrives"), now).has_value());
        ASSERT_TRUE(decrypt(pair.alice, send(pair.bob, "reply"), now).has_value());
    }
    EXPECT_EQ(pair.bob.skipped.size(), max_skipped_keys);
}

RC_GTEST_PROP(RatchetProperties, AnyChangedBitIsRefusedAndChangesNothing, ())
{
    auto pair = new_pair();
    ASSERT_TRUE(decrypt(pair.bob, send(pair.alice, "warm up"), now).has_value());
    const auto message = send(pair.bob, *rc::gen::arbitrary<std::string>());
    auto bytes = wire::encode(message);
    const auto index = *rc::gen::inRange<std::size_t>(0, bytes.size());
    const auto bit = *rc::gen::inRange<unsigned>(0, 8);
    bytes = test::flip_bit(bytes, index, bit);
    const auto forged = wire::decode(bytes, wire::read_ratchet_message);
    const auto before = fingerprint(pair.alice);
    if (forged) {
        RC_ASSERT_FALSE(decrypt(pair.alice, *forged, now).has_value());
    }
    RC_ASSERT(fingerprint(pair.alice) == before);
    RC_ASSERT(decrypt(pair.alice, message, now).has_value());
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
            const auto opened = decrypt(receiver, item.message, now);
            RC_ASSERT(opened.has_value());
            RC_ASSERT(text_of(*opened) == item.plaintext);
            delivered.push_back(std::move(item));
        }
    }
    for (const auto& item : delivered) {
        auto& receiver = item.from_alice ? pair.bob : pair.alice;
        const auto before = fingerprint(receiver);
        RC_ASSERT_FALSE(decrypt(receiver, item.message, now).has_value());
        RC_ASSERT(fingerprint(receiver) == before);
    }
}

}
}
