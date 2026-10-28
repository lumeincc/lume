// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/crypto/x25519.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace lume::ratchet {

inline constexpr std::size_t max_skipped_keys = 1024;
inline constexpr std::size_t max_skipped_header_keys = 8;
inline constexpr std::uint64_t skipped_key_lifetime = std::uint64_t{14} * 24 * 60 * 60;

using RatchetKey = crypto::ByteArray<crypto::x25519_key_size>;

struct SkippedEntry {
    std::uint32_t number = 0;
    std::uint64_t stored_at = 0;
};

class SkippedKeys {
public:
    [[nodiscard]] SkippedKeys clone() const;

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::size_t chain_count() const noexcept;
    [[nodiscard]] crypto::ByteView header_key(std::size_t chain) const;
    [[nodiscard]] const RatchetKey& ratchet_key(std::size_t chain) const;
    [[nodiscard]] std::span<const SkippedEntry> entries(std::size_t chain) const;
    [[nodiscard]] crypto::ByteView message_key(std::size_t chain, std::size_t index) const;
    [[nodiscard]] std::optional<std::size_t> find(std::size_t chain, std::uint32_t number) const;

    void reserve(std::size_t limit);
    void add(
        const crypto::SecretBytes& header_key, const RatchetKey& ratchet_key, std::uint32_t first_number,
        crypto::ByteView message_keys, std::uint64_t stored_at, std::size_t limit);
    void erase(std::size_t chain, std::size_t index);
    void expire(std::uint64_t now);

private:
    struct Chain {
        RatchetKey ratchet_key{};
        std::size_t count = 0;
    };

    [[nodiscard]] std::size_t offset(std::size_t chain) const;
    [[nodiscard]] bool continues_last_chain(const crypto::SecretBytes& header_key, const RatchetKey& ratchet_key) const;

    template <typename Keep>
    void keep_only(Keep keep);

    crypto::SecretBytes header_keys_;
    crypto::SecretBytes message_keys_;
    std::vector<Chain> chains_;
    std::vector<SkippedEntry> entries_;
};

}
