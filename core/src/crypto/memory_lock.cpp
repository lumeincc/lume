// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "memory_lock.hpp"

#include "lume/crypto/library.hpp"

#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <cstdint>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/resource.h>
#endif

namespace lume::crypto {
namespace {

std::atomic<bool>& limit_reached() noexcept
{
    static std::atomic<bool> reached{false};
    return reached;
}

std::atomic<std::uint64_t>& failed_locks() noexcept
{
    static std::atomic<std::uint64_t> failed{0};
    return failed;
}

#ifdef _WIN32
bool reach_target() noexcept
{
    auto* const process = GetCurrentProcess();
    SIZE_T minimum = 0;
    SIZE_T maximum = 0;
    DWORD flags = 0;
    if (GetProcessWorkingSetSizeEx(process, &minimum, &maximum, &flags) == 0) {
        return false;
    }
    if (minimum >= locked_memory_target) {
        return true;
    }
    return SetProcessWorkingSetSizeEx(process, locked_memory_target, locked_memory_target + maximum,
               QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE)
        != 0;
}
#else
bool reach_target() noexcept
{
    rlimit limit{};
    if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
        return false;
    }
    const auto target = static_cast<rlim_t>(locked_memory_target);
    if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur >= target) {
        return true;
    }
    const rlim_t wanted = limit.rlim_max == RLIM_INFINITY ? target : std::min(limit.rlim_max, target);
    if (wanted <= limit.rlim_cur) {
        return false;
    }
    limit.rlim_cur = wanted;
    return setrlimit(RLIMIT_MEMLOCK, &limit) == 0 && wanted >= target;
}
#endif

}

MemoryLocking memory_locking() noexcept
{
    return MemoryLocking{
        .limit_reaches_target = limit_reached().load(std::memory_order_relaxed),
        .failed_locks = failed_locks().load(std::memory_order_relaxed)};
}

namespace detail {

void raise_lock_limit() noexcept
{
    limit_reached().store(reach_target(), std::memory_order_relaxed);
}

void lock_or_count(void* data, std::size_t size) noexcept
{
    if (sodium_mlock(data, size) != 0) {
        failed_locks().fetch_add(1, std::memory_order_relaxed);
    }
}

}

}
