// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "walkthrough.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/library.hpp"
#include "lume/crypto/mlkem.hpp"
#include "lume/crypto/random.hpp"
#include "lume/crypto/x25519.hpp"
#include "lume/handshake/handshake.hpp"
#include "lume/handshake/prekey.hpp"
#include "lume/identity/identity.hpp"
#include "lume/identity/phrase.hpp"
#include "lume/safety/safety_number.hpp"
#include "lume/wire/structures.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lume::lab {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

constexpr std::uint32_t first_generation = identity::first_generation;
constexpr std::uint64_t ten_days = std::uint64_t{10} * 24 * 60 * 60;
constexpr std::size_t words_per_row = 6;

struct Account {
    SecretBytes entropy;
    SecretBytes phrase;
    identity::Identity identity;
};

struct Published {
    crypto::X25519KeyPair signed_prekey;
    crypto::MlKemKeyPair kem_prekey;
    crypto::X25519KeyPair seal_key;
    crypto::X25519KeyPair one_time_prekey;
    handshake::Bundle bundle;
};

template <typename T, typename E>
T must(std::expected<T, E> result, std::string_view step)
{
    if (!result) {
        throw std::runtime_error(std::format("the lab could not {}", step));
    }
    return std::move(*result);
}

std::uint64_t now_seconds()
{
    const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count());
}

std::string text_of(crypto::ByteView bytes)
{
    std::string text;
    text.reserve(bytes.size());
    for (const std::uint8_t byte : bytes) {
        text.push_back(static_cast<char>(byte));
    }
    return text;
}

Bytes bytes_of(std::string_view text)
{
    return {text.begin(), text.end()};
}

std::vector<std::string> words_of(std::string_view phrase)
{
    std::vector<std::string> words;
    std::size_t start = 0;
    while (start < phrase.size()) {
        const auto end = std::min(phrase.find(' ', start), phrase.size());
        words.emplace_back(phrase.substr(start, end - start));
        start = end + 1;
    }
    return words;
}

std::string joined(const std::vector<std::string>& words)
{
    std::string phrase;
    for (const auto& word : words) {
        phrase += phrase.empty() ? "" : " ";
        phrase += word;
    }
    return phrase;
}

void show_phrase(crypto::ByteView phrase)
{
    const auto words = words_of(text_of(phrase));
    std::string row;
    for (std::size_t index = 0; index < words.size(); ++index) {
        row += std::format("{:>2}. {:<9}", index + 1, words.at(index));
        if ((index + 1) % words_per_row == 0) {
            note(row);
            row.clear();
        }
    }
}

void show_identity(const identity::Identity& identity)
{
    note("signing key   " + short_hex(identity.signing.public_key));
    note("exchange key  " + short_hex(identity.exchange.public_key));
}

Account create_account()
{
    auto entropy = crypto::random_secret(identity::entropy_size);
    auto phrase = must(identity::phrase_from_entropy(entropy), "encode a recovery phrase");
    auto derived = must(identity::derive_identity(entropy), "derive an identity");
    return Account{.entropy = std::move(entropy), .phrase = std::move(phrase), .identity = std::move(derived)};
}

bool same_keys(const identity::Identity& left, const identity::Identity& right)
{
    return left.signing.public_key == right.signing.public_key && left.exchange.public_key == right.exchange.public_key
        && left.binding == right.binding;
}

Published publish(const identity::Identity& owner, std::uint64_t now)
{
    Published published{
        .signed_prekey = crypto::x25519_generate(),
        .kem_prekey = crypto::mlkem768_generate(),
        .seal_key = crypto::x25519_generate(),
        .one_time_prekey = crypto::x25519_generate(),
        .bundle = {}};
    const auto facts = [now](wire::PrekeyKind kind, std::uint32_t id) {
        return handshake::PrekeyFacts{.kind = kind, .id = id, .created_at = now, .generation = first_generation};
    };
    published.bundle = handshake::Bundle{
        .identity = identity::public_identity(owner),
        .generation = first_generation,
        .signed_prekey = must(
            handshake::make_prekey_x(owner, facts(wire::PrekeyKind::signed_prekey, 1), published.signed_prekey.public_key),
            "sign a prekey"),
        .kem_prekey = must(
            handshake::make_prekey_kem(owner, facts(wire::PrekeyKind::kem_last_resort, 2), published.kem_prekey.public_key),
            "sign a KEM prekey"),
        .seal_key = must(
            handshake::make_prekey_x(owner, facts(wire::PrekeyKind::seal_key, 3), published.seal_key.public_key),
            "sign a seal key"),
        .one_time_prekey = must(
            handshake::make_prekey_x(owner, facts(wire::PrekeyKind::one_time_prekey, 4), published.one_time_prekey.public_key),
            "make a one-time prekey")};
    return published;
}

handshake::ResponderKeys responder_keys(const Published& published)
{
    return handshake::ResponderKeys{
        .signed_prekey_id = published.bundle.signed_prekey.id,
        .signed_prekey = std::cref(published.signed_prekey),
        .kem_kind = published.bundle.kem_prekey.kind,
        .kem_id = published.bundle.kem_prekey.id,
        .kem_prekey = std::cref(published.kem_prekey),
        .one_time_prekey_id = published.bundle.one_time_prekey.transform([](const wire::PrekeyX& key) { return key.id; }),
        .one_time_prekey = std::cref(published.one_time_prekey)};
}

bool same_session(const handshake::SessionKeys& left, const handshake::SessionKeys& right)
{
    return left.root_key.equals(right.root_key.view()) && left.header_key_alice.equals(right.header_key_alice.view())
        && left.next_header_key_bob.equals(right.next_header_key_bob.view())
        && left.associated_data == right.associated_data;
}

void start_up(Report& report)
{
    report.section("The cryptographic core starts");
    const auto started = crypto::initialise();
    report.check("the self-test of every primitive passes (SHA-2, HMAC, HKDF, X25519, Ed25519, XChaCha20-Poly1305, ML-KEM-768)", started.has_value());
    if (!started) {
        throw std::runtime_error("the core refused to start");
    }
}

void recovery(Report& report, const Account& alice)
{
    report.section("Alice creates an account and writes down her recovery phrase");
    show_phrase(alice.phrase.view());
    show_identity(alice.identity);
    report.check("the identity binding verifies", identity::verify_binding(identity::public_identity(alice.identity)));

    report.section("Alice restores her account on a new phone from the phrase");
    const auto restored_entropy = identity::entropy_from_phrase(alice.phrase.view());
    const bool restored = restored_entropy.has_value()
        && same_keys(must(identity::derive_identity(*restored_entropy), "derive the restored identity"), alice.identity);
    report.check("the restored keys are exactly the same", restored);

    const auto text = text_of(alice.phrase.view());
    std::string shouted;
    for (const char letter : text) {
        shouted += letter == ' ' ? std::string("  \t") : std::string(1, static_cast<char>(letter - ('a' - 'A')));
    }
    const auto relaxed = identity::entropy_from_phrase(bytes_of("  " + shouted + "\n"));
    report.check("capital letters, tabs and extra spaces are accepted", relaxed && relaxed->equals(alice.entropy.view()));

    auto words = words_of(text);
    words.at(4) += "x";
    const auto misspelt = identity::entropy_from_phrase(bytes_of(joined(words)));
    report.check(
        std::format("a misspelt fifth word is refused: {}", misspelt ? "accepted" : phrase_problem(misspelt.error())),
        !misspelt && misspelt.error() == identity::PhraseError::unknown_word);

    words = words_of(text);
    std::swap(words.at(0), words.at(1));
    const auto swapped = identity::entropy_from_phrase(bytes_of(joined(words)));
    report.check(
        std::format("two swapped words are caught: {}", swapped ? "accepted as another account" : phrase_problem(swapped.error())),
        !swapped || !swapped->equals(alice.entropy.view()));
}

void cheating_relay(Report& report, const handshake::Bundle& bundle, const identity::Identity& stranger, std::uint64_t now)
{
    report.section("The relay tries to cheat Alice");
    auto forged = bundle;
    forged.signed_prekey.key.front() = static_cast<std::uint8_t>(forged.signed_prekey.key.front() ^ 1U);
    report.check("a replaced signed prekey is refused", handshake::check_bundle(forged, std::nullopt, now).error() == handshake::Error::invalid_prekey);

    auto recovered = bundle;
    recovered.generation = first_generation + 1;
    report.check("a fake recovery (generation 2 without Bob's signature) is refused", handshake::check_bundle(recovered, std::nullopt, now).error() == handshake::Error::invalid_prekey);

    report.check("keys more than 9 days old are refused", handshake::check_bundle(bundle, std::nullopt, now + ten_days).error() == handshake::Error::prekey_not_usable);

    report.check(
        "once Alice has pinned Bob, someone else's bundle is refused",
        handshake::check_bundle(bundle, identity::public_identity(stranger), now).error() == handshake::Error::identity_changed);
}

void session(Report& report, const Account& alice, const Account& bob, const Published& published, std::uint64_t now)
{
    report.section("Alice starts a post-quantum session with Bob (PQXDH)");
    const auto initiation = must(handshake::initiate(alice.identity, published.bundle, std::nullopt, now), "initiate the handshake");
    const auto sent = wire::encode(initiation.header);
    note(std::format("initial header on the wire: {} bytes, including a {}-byte ML-KEM-768 ciphertext", sent.size(), wire::kem_ciphertext_size));

    const auto received = wire::decode(sent, wire::read_initial_header);
    report.check("Bob decodes exactly what Alice sent", received.has_value() && *received == initiation.header);
    const auto response = handshake::respond(bob.identity, received.value(), responder_keys(published));
    report.check("Bob accepts the handshake", response.has_value());
    report.check("both sides derive the same root key, header keys and associated data", response && same_session(*response, initiation.keys));
    note("root key fingerprint (SHA-256 of the key, never the key)  " + short_hex(crypto::sha256(initiation.keys.root_key.view())));

    report.section("An attacker replays or alters Alice's first message");
    auto replay = initiation.header;
    replay.ephemeral_key.back() = static_cast<std::uint8_t>(replay.ephemeral_key.back() | 0x80U);
    const auto replayed = handshake::respond(bob.identity, replay, responder_keys(published));
    report.check("a second encoding of Alice's ephemeral key is refused, so the replay guard holds", !replayed && replayed.error() == handshake::Error::non_canonical_key);

    auto altered = initiation.header;
    altered.kem_ciphertext.front() = static_cast<std::uint8_t>(altered.kem_ciphertext.front() ^ 1U);
    const auto tampered = handshake::respond(bob.identity, altered, responder_keys(published));
    report.check("a changed KEM ciphertext gives Bob an unrelated key, so nothing would decrypt", tampered && !tampered->root_key.equals(initiation.keys.root_key.view()));

    auto truncated = sent;
    truncated.pop_back();
    report.check("a truncated header is refused by the wire decoder", !wire::decode(truncated, wire::read_initial_header));
}

void safety_numbers(Report& report, const Account& alice, const Account& bob, const Account& carol)
{
    report.section("Alice and Bob compare safety numbers in person");
    const auto alice_view = safety::safety_number(identity::public_identity(alice.identity), identity::public_identity(bob.identity));
    const auto bob_view = safety::safety_number(identity::public_identity(bob.identity), identity::public_identity(alice.identity));
    note(grouped(alice_view.substr(0, safety::fingerprint_digits), 5, " "));
    note(grouped(alice_view.substr(safety::fingerprint_digits), 5, " "));
    report.check("both phones show the same 60 digits", alice_view == bob_view);
    const auto with_carol = safety::safety_number(identity::public_identity(alice.identity), identity::public_identity(carol.identity));
    report.check("a conversation with someone else has a different number", with_carol != alice_view);
}

void device(Report& report, const Account& alice)
{
    report.section("Alice's phone is certified as her device");
    const auto phone = crypto::ed25519_generate();
    const auto certificate = identity::certify_device(alice.identity, phone.public_key, first_generation);
    report.check("the device certificate verifies for generation 1", certificate && identity::verify_device_certificate(alice.identity.signing.public_key, phone.public_key, first_generation, *certificate));
    report.check("the same certificate is refused for generation 2, after a recovery", certificate && !identity::verify_device_certificate(alice.identity.signing.public_key, phone.public_key, first_generation + 1, *certificate));
}

}

std::string phrase_problem(identity::PhraseError error)
{
    switch (error) {
    case identity::PhraseError::invalid_character:
        return "a character other than a letter or a space";
    case identity::PhraseError::wrong_word_count:
        return "not exactly 24 words";
    case identity::PhraseError::unknown_word:
        return "a word that is not on the list";
    case identity::PhraseError::checksum_mismatch:
        return "the checksum does not match, so a word is wrong or out of place";
    }
    return "an unknown problem";
}

void walk_through(Report& report)
{
    const auto now = now_seconds();
    start_up(report);
    const auto alice = create_account();
    recovery(report, alice);

    report.section("Bob creates an account and publishes his keys to the relay");
    const auto bob = create_account();
    show_identity(bob.identity);
    const auto published = publish(bob.identity, now);
    note(std::format("signed prekey, ML-KEM-768 prekey ({} bytes), seal key, one-time prekey", crypto::mlkem768_public_key_size));
    report.check("Alice accepts Bob's bundle: binding, signatures, generation and ages check out", handshake::check_bundle(published.bundle, std::nullopt, now).has_value());

    const auto carol = create_account();
    cheating_relay(report, published.bundle, carol.identity, now);
    session(report, alice, bob, published, now);
    safety_numbers(report, alice, bob, carol);
    device(report, alice);
}

void new_account(Report& report)
{
    start_up(report);
    const auto account = create_account();
    report.section("A new account");
    show_phrase(account.phrase.view());
    show_identity(account.identity);
    const auto fingerprint = safety::fingerprint(identity::public_identity(account.identity));
    note("fingerprint   " + grouped(fingerprint, 5, " "));
}

void check_phrase(Report& report, crypto::ByteView phrase)
{
    start_up(report);
    report.section("Checking a recovery phrase");
    const auto entropy = identity::entropy_from_phrase(phrase);
    if (!entropy) {
        report.check("the phrase is refused: " + phrase_problem(entropy.error()), true);
        return;
    }
    const auto account = must(identity::derive_identity(*entropy), "derive the identity");
    report.check("the phrase is valid", true);
    show_identity(account);
    note("fingerprint   " + grouped(safety::fingerprint(identity::public_identity(account)), 5, " "));
}

}
