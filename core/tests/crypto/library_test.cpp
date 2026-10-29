// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/library.hpp"

#include "crypto/backend.hpp"
#include "crypto/memory_lock.hpp"
#include "crypto/self_test.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <fstream>
#include <ios>
#include <string>
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

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__) || defined(__SANITIZE_HWADDRESS__)
#define LUME_LOCKS_INTERCEPTED
#endif
#ifdef __has_feature
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer) \
    || __has_feature(hwaddress_sanitizer)
#define LUME_LOCKS_INTERCEPTED
#endif
#endif

namespace lume::crypto {
namespace {

#ifdef LUME_LOCKS_INTERCEPTED
constexpr bool locks_are_intercepted = true;
#else
constexpr bool locks_are_intercepted = false;
#endif

std::size_t page_size()
{
#ifdef _WIN32
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return info.dwPageSize;
#else
    return static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
#endif
}

#ifndef _WIN32
bool can_lock_without_limit()
{
    constexpr std::uint64_t ipc_lock = std::uint64_t{1} << 14U;
    std::ifstream status("/proc/self/status");
    std::string field;
    while (status >> field) {
        if (field == "CapEff:") {
            std::uint64_t capabilities = 0;
            status >> std::hex >> capabilities;
            return (capabilities & ipc_lock) != 0;
        }
    }
    return false;
}

class LockLimit {
public:
    LockLimit()
    {
        getrlimit(RLIMIT_MEMLOCK, &original_);
    }
    ~LockLimit()
    {
        setrlimit(RLIMIT_MEMLOCK, &original_);
    }
    LockLimit(const LockLimit&) = delete;
    LockLimit& operator=(const LockLimit&) = delete;
    LockLimit(LockLimit&&) = delete;
    LockLimit& operator=(LockLimit&&) = delete;

    [[nodiscard]] const rlimit& original() const noexcept { return original_; }

    [[nodiscard]] rlim_t lower_to(rlim_t soft) const
    {
        rlimit lowered = original_;
        lowered.rlim_cur = std::min(soft, original_.rlim_max);
        setrlimit(RLIMIT_MEMLOCK, &lowered);
        return lowered.rlim_cur;
    }

private:
    rlimit original_{};
};
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
}

TEST(Library, RaisesTheLockLimitAgainAfterItWasLowered)
{
    ASSERT_TRUE(initialise().has_value());
#ifdef _WIN32
    auto* const process = GetCurrentProcess();
    SIZE_T minimum = 0;
    SIZE_T maximum = 0;
    DWORD flags = 0;
    ASSERT_NE(GetProcessWorkingSetSizeEx(process, &minimum, &maximum, &flags), 0);
    if (SetProcessWorkingSetSizeEx(process, 204800, 1413120, flags) == 0) {
        GTEST_SKIP() << "the working set cannot be lowered here";
    }
    SetLastError(0);
    detail::raise_lock_limit();
    const auto error = GetLastError();
    SIZE_T raised = 0;
    SIZE_T raised_maximum = 0;
    DWORD raised_flags = 0;
    GetProcessWorkingSetSizeEx(process, &raised, &raised_maximum, &raised_flags);
    SetProcessWorkingSetSizeEx(process, minimum, maximum, flags);
    if (error == ERROR_PRIVILEGE_NOT_HELD) {
        GTEST_SKIP() << "the process does not hold SeIncreaseWorkingSetPrivilege";
    }
    EXPECT_TRUE(memory_locking().limit_reaches_target);
    EXPECT_GE(raised, locked_memory_target);
    EXPECT_GE(raised_maximum, raised);
    EXPECT_EQ(raised_flags, flags);
#else
    const LockLimit limit;
    const rlim_t lowered = limit.lower_to(static_cast<rlim_t>(page_size()));
    detail::raise_lock_limit();
    rlimit raised{};
    ASSERT_EQ(getrlimit(RLIMIT_MEMLOCK, &raised), 0);
    const auto target = static_cast<rlim_t>(locked_memory_target);
    const rlim_t hard = limit.original().rlim_max;
    const rlim_t expected = hard == RLIM_INFINITY ? target : std::max(lowered, std::min(hard, target));
    EXPECT_EQ(raised.rlim_cur, expected);
    EXPECT_EQ(raised.rlim_max, hard);
    EXPECT_EQ(memory_locking().limit_reaches_target, raised.rlim_cur >= target);
#endif
}

TEST(Library, HoldsThousandsOfLockedSecretsOnceTheLimitIsRaised)
{
    ASSERT_TRUE(initialise().has_value());
    if (!memory_locking().limit_reaches_target) {
        GTEST_SKIP() << "the lock limit could not be raised here";
    }
    const auto before = memory_locking().failed_locks;
    const std::size_t secrets = locked_memory_target / page_size() / 2;
    std::vector<SecretBytes> held;
    held.reserve(secrets);
    for (std::size_t index = 0; index < secrets; ++index) {
        held.emplace_back(1);
    }
    EXPECT_EQ(memory_locking().failed_locks, before);
}

TEST(Library, CountsEveryLockThatFails)
{
    if (locks_are_intercepted) {
        GTEST_SKIP() << "this sanitizer turns mlock into a no-op that always succeeds";
    }
    ASSERT_TRUE(initialise().has_value());
#ifdef _WIN32
    SIZE_T minimum = 0;
    SIZE_T maximum = 0;
    DWORD flags = 0;
    ASSERT_NE(GetProcessWorkingSetSizeEx(GetCurrentProcess(), &minimum, &maximum, &flags), 0);
    const std::size_t secrets = (minimum / page_size()) + 2048;
    const bool can_lock_again = true;
#else
    if (can_lock_without_limit()) {
        GTEST_SKIP() << "the process holds CAP_IPC_LOCK, so no lock can fail";
    }
    const LockLimit limit;
    const rlim_t lowered = limit.lower_to(static_cast<rlim_t>(16 * page_size()));
    const std::size_t secrets = (static_cast<std::size_t>(lowered) / page_size()) + 64;
    const rlim_t original = limit.original().rlim_cur;
    const bool can_lock_again = original == RLIM_INFINITY || original >= static_cast<rlim_t>(4 * page_size());
#endif
    const auto before = memory_locking().failed_locks;
    std::vector<SecretBytes> held;
    held.reserve(secrets);
    for (std::size_t index = 0; index < secrets; ++index) {
        held.emplace_back(1);
    }
    EXPECT_GT(memory_locking().failed_locks, before);

    held.clear();
#ifndef _WIN32
    setrlimit(RLIMIT_MEMLOCK, &limit.original());
#endif
    if (can_lock_again) {
        const auto after_release = memory_locking().failed_locks;
        const SecretBytes fits(1);
        EXPECT_EQ(memory_locking().failed_locks, after_release);
    }
}

}
}
