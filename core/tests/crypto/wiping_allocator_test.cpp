// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "crypto/wiping_allocator.hpp"

#include "crypto/backend.hpp"
#include "support/wiping_ledger.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace lume::crypto {
namespace {

constexpr std::uint8_t secret_fill = 0xa5;

struct Releases {
    std::size_t count = 0;
    std::size_t bytes = 0;
    std::size_t unwiped = 0;
};

Releases& releases() noexcept
{
    thread_local Releases seen;
    return seen;
}

template <typename T>
class InspectingAllocator {
public:
    using value_type = T;

    InspectingAllocator() noexcept = default;

    template <typename U>
    InspectingAllocator([[maybe_unused]] const InspectingAllocator<U>& other) noexcept
    {
    }

    [[nodiscard]] T* allocate(std::size_t count)
    {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* data, std::size_t count) noexcept
    {
        const void* const storage = data;
        const std::span bytes(static_cast<const std::uint8_t*>(storage), count * sizeof(T));
        auto& seen = releases();
        ++seen.count;
        seen.bytes += bytes.size();
        if (!detail::is_zero(bytes)) {
            ++seen.unwiped;
        }
        std::allocator<T>{}.deallocate(data, count);
    }
};

template <typename T>
using Inspected = WipingAllocator<T, InspectingAllocator<T>>;

TEST(WipingAllocator, WipesEveryBufferAVectorGrowsOutOfOrReleases)
{
    releases() = {};
    {
        std::vector<std::uint8_t, Inspected<std::uint8_t>> secret(16, secret_fill);
        const auto first = secret.capacity();
        while (secret.capacity() == first) {
            secret.push_back(secret_fill);
        }
        EXPECT_GE(releases().count, 1U);
        EXPECT_GE(releases().bytes, first);
    }
    EXPECT_GE(releases().count, 2U);
    EXPECT_EQ(releases().unwiped, 0U);
}

TEST(WipingAllocator, WipesEveryNodeAMapReleases)
{
    using Value = std::array<std::uint8_t, 32>;
    using Map = std::map<int, Value, std::less<>, Inspected<std::pair<const int, Value>>>;
    releases() = {};
    {
        Map secrets;
        Value value{};
        value.fill(secret_fill);
        for (int key = 0; key < 8; ++key) {
            secrets.emplace(key, value);
        }
        const auto before = releases().count;
        secrets.erase(3);
        EXPECT_EQ(releases().count, before + 1);
        EXPECT_GE(releases().bytes, sizeof(Value));
    }
    EXPECT_GE(releases().count, 8U);
    EXPECT_EQ(releases().unwiped, 0U);
}

TEST(WipingAllocator, CountsWhatItAllocatesAndRefusesPastItsLimit)
{
    auto& ledger = detail::wiping_ledger();
    WipingAllocator<std::uint64_t> allocator;
    const auto before = ledger.made;
    auto* const data = allocator.allocate(4);
    EXPECT_EQ(ledger.made, before + 1);
    allocator.deallocate(data, 4);
    EXPECT_EQ(ledger.made, before + 1);
    {
        const test::LedgerLimit none(0);
        EXPECT_THROW(static_cast<void>(allocator.allocate(1)), std::bad_alloc);
        EXPECT_EQ(ledger.made, before + 1);
    }
    auto* const again = allocator.allocate(1);
    EXPECT_EQ(ledger.made, before + 2);
    allocator.deallocate(again, 1);
}

TEST(WipingAllocator, RebindsItsUpstreamAndComparesEqualAcrossTypes)
{
    static_assert(std::is_same_v<std::allocator_traits<Inspected<int>>::rebind_alloc<double>, Inspected<double>>);
    static_assert(std::is_same_v<std::allocator_traits<WipingAllocator<int>>::rebind_alloc<double>, WipingAllocator<double>>);
    static_assert(std::allocator_traits<WipingAllocator<int>>::is_always_equal::value);
    const WipingAllocator<int> first;
    const WipingAllocator<double> second(first);
    EXPECT_TRUE(first == second);
    EXPECT_FALSE(first != second);
}

}
}
