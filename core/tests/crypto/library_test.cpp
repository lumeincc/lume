// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/library.hpp"

#include "crypto/self_test.hpp"

#include <gtest/gtest.h>

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

TEST(Library, SelfTestPassesWhenRunDirectly)
{
    EXPECT_TRUE(detail::run_self_test().has_value());
}

}
}
