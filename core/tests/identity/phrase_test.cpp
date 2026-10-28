// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/identity/phrase.hpp"

#include "identity/wordlist.hpp"
#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <stdexcept>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace lume::identity {
namespace {

using crypto::Bytes;
using crypto::SecretBytes;

constexpr std::string_view zero_entropy_phrase =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

Bytes text(std::string_view value)
{
    return {value.begin(), value.end()};
}

std::string as_text(crypto::ByteView bytes)
{
    return {bytes.begin(), bytes.end()};
}

std::vector<std::string> words_of(std::string_view phrase)
{
    std::vector<std::string> words;
    std::size_t start = 0;
    while (start <= phrase.size()) {
        const auto end = std::min(phrase.find(' ', start), phrase.size());
        words.emplace_back(phrase.substr(start, end - start));
        start = end + 1;
    }
    return words;
}

std::string joined(const std::vector<std::string>& words, std::string_view separator)
{
    std::string phrase;
    for (const auto& word : words) {
        if (!phrase.empty()) {
            phrase += separator;
        }
        phrase += word;
    }
    return phrase;
}

PhraseError error_of(std::string_view phrase)
{
    const auto decoded = entropy_from_phrase(text(phrase));
    if (decoded) {
        throw std::logic_error("the phrase was expected to be rejected");
    }
    return decoded.error();
}

TEST(Wordlist, IsTheBip39EnglishList)
{
    std::ifstream input(std::filesystem::path(LUME_THIRD_PARTY_DIR) / "bip39" / "english.txt");
    ASSERT_TRUE(input);
    std::vector<std::string> expected;
    for (std::string line; std::getline(input, line);) {
        expected.push_back(line);
    }
    ASSERT_EQ(expected.size(), detail::words.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        EXPECT_EQ(detail::words.at(index), expected.at(index)) << "word " << index;
    }
}

TEST(Phrase, MatchesTheTrezorVectors)
{
    const auto vectors = test::load_vectors("trezor/bip39_vectors.json").at("english");
    int full_length = 0;
    int shorter = 0;
    for (const auto& vector : vectors) {
        const auto entropy = test::from_hex(vector.at(0).get<std::string>());
        const auto mnemonic = vector.at(1).get<std::string>();
        const auto decoded = entropy_from_phrase(text(mnemonic));
        if (entropy.size() != entropy_size) {
            ++shorter;
            ASSERT_FALSE(decoded.has_value()) << mnemonic;
            EXPECT_EQ(decoded.error(), PhraseError::wrong_word_count) << mnemonic;
            continue;
        }
        ++full_length;
        const auto phrase = phrase_from_entropy(SecretBytes::copy_of(entropy));
        ASSERT_TRUE(phrase.has_value());
        EXPECT_EQ(as_text(phrase->view()), mnemonic);
        ASSERT_TRUE(decoded.has_value()) << mnemonic;
        EXPECT_TRUE(decoded->equals(entropy)) << mnemonic;
    }
    EXPECT_EQ(full_length, 8);
    EXPECT_EQ(shorter, 16);
}

TEST(Phrase, MatchesTheLumeVectors)
{
    const auto cases = test::load_vectors("lume/identity.json").at("cases");
    ASSERT_EQ(cases.size(), 8U);
    for (const auto& vector : cases) {
        const auto entropy = test::from_hex(vector.at("entropy").get<std::string>());
        const auto expected = vector.at("phrase").get<std::string>();
        const auto phrase = phrase_from_entropy(SecretBytes::copy_of(entropy));
        ASSERT_TRUE(phrase.has_value());
        EXPECT_EQ(as_text(phrase->view()), expected);
        const auto decoded = entropy_from_phrase(text(expected));
        ASSERT_TRUE(decoded.has_value());
        EXPECT_TRUE(decoded->equals(entropy));
    }
}

TEST(Phrase, IgnoresCaseAndSpacing)
{
    std::string upper(zero_entropy_phrase);
    std::ranges::transform(upper, upper.begin(), [](char letter) { return letter == ' ' ? letter : static_cast<char>(letter - ('a' - 'A')); });
    const auto words = words_of(zero_entropy_phrase);
    for (const std::string& variant :
         {upper, "  " + std::string(zero_entropy_phrase) + "\n", joined(words, "\t"), joined(words, " \r\n "),
          "Abandon " + joined(std::vector<std::string>(words.begin() + 1, words.end()), "   ")}) {
        const auto decoded = entropy_from_phrase(text(variant));
        ASSERT_TRUE(decoded.has_value()) << variant;
        EXPECT_TRUE(decoded->equals(Bytes(entropy_size, 0))) << variant;
    }
}

TEST(Phrase, RejectsCharactersOtherThanLettersAndWhitespace)
{
    const std::string phrase(zero_entropy_phrase);
    for (const std::string& variant :
         {phrase + "1", phrase + ",", phrase + ".", "abandon-" + phrase.substr(8), phrase + std::string(1, '\0'),
          phrase + "\xc3\xa9", "abandon\xc2\xa0" + phrase.substr(8), phrase + "\v"}) {
        EXPECT_EQ(error_of(variant), PhraseError::invalid_character) << variant;
    }
}

TEST(Phrase, RejectsAnyOtherNumberOfWords)
{
    const auto words = words_of(zero_entropy_phrase);
    EXPECT_EQ(error_of(""), PhraseError::wrong_word_count);
    EXPECT_EQ(error_of(" \t\n "), PhraseError::wrong_word_count);
    EXPECT_EQ(error_of(joined(std::vector<std::string>(words.begin(), words.end() - 1), " ")),
        PhraseError::wrong_word_count);
    EXPECT_EQ(error_of(std::string(zero_entropy_phrase) + " art"), PhraseError::wrong_word_count);
    EXPECT_EQ(error_of(std::string(zero_entropy_phrase) + " " + std::string(zero_entropy_phrase)),
        PhraseError::wrong_word_count);
}

TEST(Phrase, RejectsWordsOutsideTheList)
{
    auto words = words_of(zero_entropy_phrase);
    for (const std::string_view stranger : {"lume", "aban", "abandons", "abandoned", "zzzzzzzzzzzz", "a"}) {
        words.at(5) = std::string(stranger);
        EXPECT_EQ(error_of(joined(words, " ")), PhraseError::unknown_word) << stranger;
    }
}

TEST(Phrase, RejectsAWrongChecksum)
{
    auto words = words_of(zero_entropy_phrase);
    words.back() = "abandon";
    EXPECT_EQ(error_of(joined(words, " ")), PhraseError::checksum_mismatch);
}

TEST(Phrase, ExactlyEightLastWordsCompleteTwentyThreeWords)
{
    auto words = words_of(zero_entropy_phrase);
    int valid = 0;
    int original = 0;
    for (const std::string_view candidate : detail::words) {
        words.back() = std::string(candidate);
        const auto decoded = entropy_from_phrase(text(joined(words, " ")));
        if (!decoded) {
            EXPECT_EQ(decoded.error(), PhraseError::checksum_mismatch) << candidate;
            continue;
        }
        ++valid;
        if (decoded->equals(Bytes(entropy_size, 0))) {
            ++original;
            EXPECT_EQ(candidate, "art");
        }
    }
    EXPECT_EQ(valid, 8);
    EXPECT_EQ(original, 1);
}

TEST(Phrase, TheLongestPossiblePhraseEncodes)
{
    constexpr std::size_t longest = (phrase_word_count * (detail::longest_word + 1)) - 1;
    for (const std::string_view repeated : detail::words) {
        if (repeated.size() != detail::longest_word) {
            continue;
        }
        std::vector<std::string> words(phrase_word_count, std::string(repeated));
        for (const std::string_view last : detail::words) {
            if (last.size() != detail::longest_word) {
                continue;
            }
            words.back() = std::string(last);
            const auto phrase = joined(words, " ");
            const auto entropy = entropy_from_phrase(text(phrase));
            if (!entropy) {
                continue;
            }
            ASSERT_EQ(phrase.size(), longest);
            const auto encoded = phrase_from_entropy(*entropy);
            ASSERT_TRUE(encoded.has_value());
            EXPECT_EQ(as_text(encoded->view()), phrase);
            return;
        }
    }
    FAIL() << "no phrase of twenty-four eight-letter words has a valid checksum";
}

TEST(Phrase, ReportsErrorsInAFixedOrder)
{
    const std::string phrase(zero_entropy_phrase);
    const auto words = words_of(zero_entropy_phrase);
    EXPECT_EQ(error_of(phrase + " art 1"), PhraseError::invalid_character);
    EXPECT_EQ(error_of(phrase + " " + phrase + " 1"), PhraseError::invalid_character);
    EXPECT_EQ(error_of("lume " + phrase), PhraseError::wrong_word_count);
    auto unknown_and_bad_checksum = words;
    unknown_and_bad_checksum.front() = "lume";
    unknown_and_bad_checksum.back() = "abandon";
    EXPECT_EQ(error_of(joined(unknown_and_bad_checksum, " ")), PhraseError::unknown_word);
}

TEST(Phrase, RejectsEntropyOfTheWrongSize)
{
    EXPECT_EQ(phrase_from_entropy(SecretBytes(entropy_size - 1)).error(), crypto::Error::invalid_size);
    EXPECT_EQ(phrase_from_entropy(SecretBytes(entropy_size + 1)).error(), crypto::Error::invalid_size);
    EXPECT_EQ(phrase_from_entropy(SecretBytes(16)).error(), crypto::Error::invalid_size);
}

SecretBytes random_entropy()
{
    return SecretBytes::copy_of(test::random_bytes_of(entropy_size));
}

std::string random_phrase(const SecretBytes& entropy)
{
    const auto phrase = phrase_from_entropy(entropy);
    RC_ASSERT(phrase.has_value());
    return as_text(phrase->view());
}

RC_GTEST_PROP(PhraseProperties, DecodingReversesEncoding, ())
{
    const auto entropy = random_entropy();
    const auto decoded = entropy_from_phrase(text(random_phrase(entropy)));
    RC_ASSERT(decoded.has_value());
    RC_ASSERT(decoded->equals(entropy.view()));
}

RC_GTEST_PROP(PhraseProperties, IsTwentyFourListWordsSeparatedBySingleSpaces, ())
{
    const auto words = words_of(random_phrase(random_entropy()));
    RC_ASSERT(words.size() == phrase_word_count);
    for (const auto& word : words) {
        RC_ASSERT(std::ranges::binary_search(detail::words, std::string_view(word)));
    }
}

RC_GTEST_PROP(PhraseProperties, CaseAndSpacingDoNotMatter, ())
{
    const auto entropy = random_entropy();
    const auto words = words_of(random_phrase(entropy));
    std::string phrase = *rc::gen::element<std::string>("", " ", "\n");
    for (const auto& word : words) {
        for (const char letter : word) {
            phrase += *rc::gen::arbitrary<bool>() ? static_cast<char>(letter - ('a' - 'A')) : letter;
        }
        phrase += *rc::gen::element<std::string>(" ", "  ", "\t", "\r\n", " \n\t ");
    }
    const auto decoded = entropy_from_phrase(text(phrase));
    RC_ASSERT(decoded.has_value());
    RC_ASSERT(decoded->equals(entropy.view()));
}

RC_GTEST_PROP(PhraseProperties, ReplacingAWordIsNeverSilentlyAccepted, ())
{
    const auto entropy = random_entropy();
    auto words = words_of(random_phrase(entropy));
    const auto position = *rc::gen::inRange<std::size_t>(0, phrase_word_count);
    const auto replacement = *rc::gen::inRange<std::size_t>(0, detail::words.size());
    RC_PRE(detail::words.at(replacement) != words.at(position));
    words.at(position) = std::string(detail::words.at(replacement));
    const auto decoded = entropy_from_phrase(text(joined(words, " ")));
    if (decoded) {
        RC_ASSERT_FALSE(decoded->equals(entropy.view()));
    } else {
        RC_ASSERT(decoded.error() == PhraseError::checksum_mismatch);
    }
}

RC_GTEST_PROP(PhraseProperties, AnyTwentyFourListWordsDecodeOnlyWithTheirChecksum, ())
{
    std::vector<std::string> words;
    for (std::size_t position = 0; position < phrase_word_count; ++position) {
        const auto index = *rc::gen::resize(rc::kNominalSize, rc::gen::inRange<std::size_t>(0, detail::words.size()));
        words.emplace_back(detail::words.at(index));
    }
    const auto phrase = joined(words, " ");
    const auto decoded = entropy_from_phrase(text(phrase));
    if (!decoded) {
        RC_ASSERT(decoded.error() == PhraseError::checksum_mismatch);
        return;
    }
    RC_ASSERT(decoded->size() == entropy_size);
    RC_ASSERT(random_phrase(*decoded) == phrase);
}

RC_GTEST_PROP(PhraseProperties, ArbitraryBytesNeverCrashTheDecoder, (const Bytes& input))
{
    const auto decoded = entropy_from_phrase(input);
    if (decoded) {
        RC_ASSERT(decoded->size() == entropy_size);
    }
}

}
}
