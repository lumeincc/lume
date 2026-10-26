// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/library.hpp"

#include "crypto/backend.hpp"
#include "crypto/self_test.hpp"
#include "lume/crypto/hash.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <expected>
#include <stdexcept>
#include <thread>
#include <vector>

namespace lume::crypto {
namespace {

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

}
}
