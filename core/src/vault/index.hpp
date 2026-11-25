// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "crypto/wiping_allocator.hpp"
#include "lume/crypto/bytes.hpp"
#include "lume/vault/vault.hpp"
#include "lume/wire/structures.hpp"
#include "vault/keys.hpp"
#include "vault/records.hpp"
#include "vault/store.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <utility>
#include <vector>

namespace lume::vault {

inline constexpr std::size_t record_type_count = 256;

struct Entry {
    std::uint64_t slot = 0;
    std::uint64_t counter = 0;
    Nonce nonce{};
    Nonce address_nonce{};

    friend bool operator==(const Entry&, const Entry&) = default;
};

struct TypeState {
    std::uint32_t count = 0;
    Root root{};

    friend bool operator==(const TypeState&, const TypeState&) = default;
};

using TypeStates = std::array<TypeState, record_type_count>;

struct Plan;
class Index;

namespace detail {

struct Draws;

[[nodiscard]] Result<Plan> plan(const Index& index, const OpenedHeader& opened, const TermHasher& hasher,
    std::span<const Change> changes, const Draws& draws);

}

class Index {
public:
    using Id = std::vector<std::uint8_t, crypto::WipingAllocator<std::uint8_t>>;
    using Key = std::pair<RecordType, Id>;

    struct KeyView {
        RecordType type = 0;
        crypto::ByteView id;
    };

    struct Order {
        using is_transparent = void;

        [[nodiscard]] static KeyView view(const Key& key) noexcept
        {
            return KeyView{.type = key.first, .id = key.second};
        }

        [[nodiscard]] static KeyView view(const KeyView& key) noexcept
        {
            return key;
        }

        template <typename Left, typename Right>
        [[nodiscard]] bool operator()(const Left& left, const Right& right) const noexcept
        {
            const KeyView first = view(left);
            const KeyView second = view(right);
            if (first.type != second.type) {
                return first.type < second.type;
            }
            const auto [left_at, right_at] = std::ranges::mismatch(first.id, second.id);
            if (right_at == second.id.end()) {
                return false;
            }
            return left_at == first.id.end() || *left_at < *right_at;
        }
    };

    using Map = std::map<Key, Entry, Order, crypto::WipingAllocator<std::pair<const Key, Entry>>>;

    [[nodiscard]] const Entry* find(RecordType type, crypto::ByteView id) const noexcept;
    [[nodiscard]] Result<void> admit(const Located& located, std::uint64_t slot, const Nonce& address_nonce, const Root& term);
    [[nodiscard]] Result<wire::Manifest> manifest(std::uint64_t epoch) const;
    [[nodiscard]] bool matches(const wire::Manifest& manifest) const noexcept;
    [[nodiscard]] std::uint64_t records() const noexcept;
    [[nodiscard]] const Map& entries() const noexcept;
    [[nodiscard]] Result<Plan> plan(const OpenedHeader& opened, const TermHasher& hasher, std::span<const Change> changes) const;
    void apply(Plan&& plan) noexcept;

private:
    friend Result<Plan> detail::plan(const Index& index, const OpenedHeader& opened, const TermHasher& hasher,
        std::span<const Change> changes, const detail::Draws& draws);

    Map entries_;
    TypeStates types_{};
};

struct Plan {
    std::vector<RowChange> rows;
    crypto::Bytes manifest;
    TypeStates types{};
    std::vector<Index::Key> erased;
    std::vector<std::pair<Index::Key, Entry>> replaced;
    std::vector<Index::Map::node_type> new_nodes;
};

}
