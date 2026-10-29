// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/library.hpp"

#include "crypto/backend.hpp"
#include "crypto/self_test.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <expected>
#include <stdexcept>
#include <thread>
#include <vector>

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
#include <unistd.h>
#endif

#ifdef __SANITIZE_ADDRESS__
#define LUME_ADDRESS_SANITIZER
#endif
#ifdef __has_feature
#if __has_feature(address_sanitizer)
#define LUME_ADDRESS_SANITIZER
#endif
#endif

namespace lume::crypto {
namespace {

#ifdef LUME_ADDRESS_SANITIZER
constexpr bool locks_are_intercepted = true;
#else
constexpr bool locks_are_intercepted = false;
#endif

bool system_lock_limit_reaches_target()
{
#ifdef _WIN32
    SIZE_T minimum = 0;
    SIZE_T maximum = 0;
    DWORD flags = 0;
    return GetProcessWorkingSetSizeEx(GetCurrentProcess(), &minimum, &maximum, &flags) != 0
        && minimum >= locked_memory_target;
#else
    rlimit limit{};
    return getrlimit(RLIMIT_MEMLOCK, &limit) == 0
        && (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur >= locked_memory_target);
#endif
}

TEST(Library, InitialisationPassesTheSelfTest)
{
    const auto outcome = initialise();
    EXPECT_TRUE(outcome.has_value());
}

TEST(Library, InitialisationIsIdempotent)
{
    EXPECT_TRUE(initialise().has_value());
    EXPECT_TRUE(initialise().has_value());
}

TEST(Library, TheGateReportsTheSelfTestOutcome)
{
    EXPECT_TRUE(detail::operational_state().has_value());
    EXPECT_NO_THROW(detail::require_operational());
}

TEST(Library, AFailedStateStopsEveryCaller)
{
    EXPECT_THROW(
        detail::throw_unless_operational(std::unexpected(Error::self_test_failed)), std::runtime_error);
    EXPECT_THROW(
        detail::throw_unless_operational(std::unexpected(Error::library_failure)), std::runtime_error);
    EXPECT_NO_THROW(detail::throw_unless_operational({}));
}

TEST(Library, SelfTestPassesWhenRunDirectly)
{
    EXPECT_TRUE(detail::run_self_test().has_value());
}

TEST(Library, PrimitivesUsedFromManyThreadsAtOnceAgree)
{
    constexpr int thread_count = 8;
    std::atomic<int> matching{0};
    std::vector<std::jthread> threads;
    threads.reserve(thread_count);
    for (int index = 0; index < thread_count; ++index) {
        threads.emplace_back([&matching] {
            if (sha256(Bytes{'a', 'b', 'c'}) == sha256(Bytes{'a', 'b', 'c'})) {
                ++matching;
            }
        });
    }
    threads.clear();
    EXPECT_EQ(matching.load(), thread_count);
}

TEST(Library, ReportsWhetherTheLockLimitReachesItsTarget)
{
    ASSERT_TRUE(initialise().has_value());
    EXPECT_EQ(memory_locking().limit_reaches_target, system_lock_limit_reaches_target());
#ifdef _WIN32
    EXPECT_TRUE(memory_locking().limit_reaches_target);
#endif
}

TEST(Library, CountsEveryLockThatFails)
{
    if (locks_are_intercepted) {
        GTEST_SKIP() << "AddressSanitizer turns mlock into a no-op that always succeeds";
    }
#ifndef _WIN32
    if (geteuid() == 0) {
        GTEST_SKIP() << "root locks memory without a limit";
    }
#endif
    ASSERT_TRUE(initialise().has_value());
    const auto before = memory_locking().failed_locks;
    const std::size_t pages = (locked_memory_target / 4096) + 2048;
    std::vector<SecretBytes> held;
    held.reserve(pages);
    for (std::size_t index = 0; index < pages; ++index) {
        held.emplace_back(1);
    }
    EXPECT_GT(memory_locking().failed_locks, before);

    held.clear();
    const auto after_release = memory_locking().failed_locks;
    const SecretBytes fits(1);
    EXPECT_EQ(memory_locking().failed_locks, after_release);
}

}
}
