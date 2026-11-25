// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "crypto/backend.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <span>

namespace lume::crypto {

namespace detail {

struct WipingLedger {
    std::uint64_t made = 0;
    std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
};

[[nodiscard]] inline WipingLedger& wiping_ledger() noexcept
{
    thread_local WipingLedger ledger;
    return ledger;
}

}

template <typename T, typename Upstream = std::allocator<T>>
class WipingAllocator {
public:
    using value_type = T;

    template <typename U>
    struct rebind {
        using other = WipingAllocator<U, typename std::allocator_traits<Upstream>::template rebind_alloc<U>>;
    };

    WipingAllocator() noexcept = default;

    template <typename U, typename Other>
    WipingAllocator([[maybe_unused]] const WipingAllocator<U, Other>& other) noexcept
    {
    }

    [[nodiscard]] T* allocate(std::size_t count)
    {
        auto& ledger = detail::wiping_ledger();
        if (ledger.made >= ledger.limit) {
            throw std::bad_alloc();
        }
        T* const data = Upstream{}.allocate(count);
        ++ledger.made;
        return data;
    }

    void deallocate(T* data, std::size_t count) noexcept
    {
        void* const storage = data;
        detail::wipe(std::span(static_cast<std::uint8_t*>(storage), count * sizeof(T)));
        Upstream{}.deallocate(data, count);
    }
};

template <typename T, typename Upstream, typename U, typename Other>
[[nodiscard]] constexpr bool operator==(
    [[maybe_unused]] const WipingAllocator<T, Upstream>& left, [[maybe_unused]] const WipingAllocator<U, Other>& right) noexcept
{
    return true;
}

}
