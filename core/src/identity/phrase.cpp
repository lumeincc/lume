// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/identity/phrase.hpp"

#include "identity/wordlist.hpp"
#include "lume/crypto/hash.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

namespace lume::identity {
namespace {

using crypto::ByteView;
using crypto::SecretBytes;

constexpr std::size_t bits_per_word = 11;
constexpr std::size_t bits_per_byte = 8;
constexpr std::uint32_t index_mask = (1U << bits_per_word) - 1U;
constexpr std::size_t encoded_size = entropy_size + 1;
constexpr std::size_t longest_phrase = (phrase_word_count * (detail::longest_word + 1)) - 1;
constexpr std::uint8_t separator = ' ';
constexpr std::uint8_t lowercase_bit = 0x20;
constexpr std::uint64_t byte_mask = 0xff;

static_assert(detail::words.size() == std::size_t{1} << bits_per_word);
static_assert(phrase_word_count * bits_per_word == encoded_size * bits_per_byte);
static_assert(detail::longest_word * bits_per_byte <= 64);

using PackedWords = std::array<std::uint64_t, detail::words.size()>;

struct Token {
    std::size_t offset = 0;
    std::size_t length = 0;
};

using Tokens = std::array<Token, phrase_word_count>;

struct Match {
    std::uint32_t index = 0;
    std::uint32_t found = 0;
};

[[nodiscard]] constexpr bool is_letter(std::uint8_t byte) noexcept
{
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z');
}

[[nodiscard]] constexpr bool is_space(std::uint8_t byte) noexcept
{
    return byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r';
}

[[nodiscard]] constexpr std::uint64_t mask_if_zero(std::uint64_t value) noexcept
{
    const std::uint64_t non_zero = (value | (0U - value)) >> 63U;
    return non_zero - 1U;
}

[[nodiscard]] std::uint64_t pack(std::string_view word)
{
    std::uint64_t packed = 0;
    std::size_t shift = 0;
    for (const char letter : word) {
        packed |= std::uint64_t{static_cast<std::uint8_t>(letter)} << shift;
        shift += bits_per_byte;
    }
    return packed;
}

[[nodiscard]] const PackedWords& packed_words()
{
    static const PackedWords packed = [] {
        PackedWords table{};
        std::ranges::transform(detail::words, table.begin(), pack);
        return table;
    }();
    return packed;
}

[[nodiscard]] Match find_word(std::uint64_t token)
{
    Match match;
    const auto& packed = packed_words();
    for (std::uint32_t candidate = 0; candidate < packed.size(); ++candidate) {
        const auto mask = static_cast<std::uint32_t>(mask_if_zero(token ^ packed.at(candidate)));
        match.index |= mask & candidate;
        match.found |= mask & 1U;
    }
    return match;
}

[[nodiscard]] std::uint64_t select_word(std::uint32_t index)
{
    std::uint64_t selected = 0;
    const auto& packed = packed_words();
    for (std::uint32_t candidate = 0; candidate < packed.size(); ++candidate) {
        selected |= mask_if_zero(candidate ^ index) & packed.at(candidate);
    }
    return selected;
}

[[nodiscard]] std::size_t letters_in(std::uint64_t packed)
{
    std::size_t count = 0;
    for (std::size_t shift = 0; shift < detail::longest_word * bits_per_byte; shift += bits_per_byte) {
        count += static_cast<std::size_t>(1U + mask_if_zero((packed >> shift) & byte_mask)) & 1U;
    }
    return count;
}

[[nodiscard]] std::uint8_t checksum_of(ByteView entropy)
{
    return crypto::sha256_secret({entropy}).view().front();
}

[[nodiscard]] std::expected<Tokens, PhraseError> split_words(ByteView phrase)
{
    if (!std::ranges::all_of(phrase, [](std::uint8_t byte) { return is_letter(byte) || is_space(byte); })) {
        return std::unexpected(PhraseError::invalid_character);
    }
    Tokens tokens{};
    std::size_t count = 0;
    std::size_t offset = 0;
    bool inside_word = false;
    for (const std::uint8_t byte : phrase) {
        if (is_space(byte)) {
            inside_word = false;
        } else {
            if (!inside_word) {
                if (count == tokens.size()) {
                    return std::unexpected(PhraseError::wrong_word_count);
                }
                tokens.at(count) = Token{.offset = offset, .length = 0};
                ++count;
                inside_word = true;
            }
            ++tokens.at(count - 1).length;
        }
        ++offset;
    }
    if (count != tokens.size()) {
        return std::unexpected(PhraseError::wrong_word_count);
    }
    return tokens;
}

[[nodiscard]] std::uint64_t pack_lowercase(ByteView letters)
{
    std::uint64_t packed = 0;
    std::size_t shift = 0;
    for (const std::uint8_t letter : letters) {
        packed |= std::uint64_t{static_cast<std::uint8_t>(letter | lowercase_bit)} << shift;
        shift += bits_per_byte;
    }
    return packed;
}

}

crypto::Result<SecretBytes> phrase_from_entropy(const SecretBytes& entropy)
{
    if (entropy.size() != entropy_size) {
        return std::unexpected(crypto::Error::invalid_size);
    }
    SecretBytes encoded(encoded_size);
    const auto checksum_slot = std::ranges::copy(entropy.view(), encoded.writable().begin()).out;
    *checksum_slot = checksum_of(entropy.view());

    SecretBytes text(longest_phrase);
    const auto output = text.writable();
    auto next = output.begin();
    std::uint32_t buffer = 0;
    std::size_t buffered = 0;
    for (const std::uint8_t byte : encoded.view()) {
        buffer = (buffer << bits_per_byte) | byte;
        buffered += bits_per_byte;
        if (buffered < bits_per_word) {
            continue;
        }
        buffered -= bits_per_word;
        if (next != output.begin()) {
            *next++ = separator;
        }
        const std::uint64_t word = select_word((buffer >> buffered) & index_mask);
        auto slot = next;
        for (std::size_t shift = 0; shift < detail::longest_word * bits_per_byte; shift += bits_per_byte) {
            *slot++ = static_cast<std::uint8_t>(word >> shift);
        }
        next += static_cast<std::ptrdiff_t>(letters_in(word));
        buffer &= (1U << buffered) - 1U;
    }
    const auto length = static_cast<std::size_t>(next - output.begin());
    return SecretBytes::copy_of(text.view().first(length));
}

std::expected<SecretBytes, PhraseError> entropy_from_phrase(ByteView phrase)
{
    const auto tokens = split_words(phrase);
    if (!tokens) {
        return std::unexpected(tokens.error());
    }

    SecretBytes encoded(encoded_size);
    auto next = encoded.writable().begin();
    std::uint32_t buffer = 0;
    std::size_t buffered = 0;
    std::uint32_t all_found = 1;
    for (const Token& token : *tokens) {
        if (token.length > detail::longest_word) {
            return std::unexpected(PhraseError::unknown_word);
        }
        const Match match = find_word(pack_lowercase(phrase.subspan(token.offset, token.length)));
        all_found &= match.found;
        buffer = (buffer << bits_per_word) | match.index;
        buffered += bits_per_word;
        while (buffered >= bits_per_byte) {
            buffered -= bits_per_byte;
            *next++ = static_cast<std::uint8_t>(buffer >> buffered);
            buffer &= (1U << buffered) - 1U;
        }
    }
    if (all_found == 0) {
        return std::unexpected(PhraseError::unknown_word);
    }

    const ByteView entropy = encoded.view().first(entropy_size);
    if (mask_if_zero(static_cast<std::uint64_t>(checksum_of(entropy) ^ encoded.view().back())) == 0) {
        return std::unexpected(PhraseError::checksum_mismatch);
    }
    return SecretBytes::copy_of(entropy);
}

}
