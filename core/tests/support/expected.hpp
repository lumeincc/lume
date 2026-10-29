// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include <gtest/gtest.h>

#include <expected>

namespace lume::test {

template <typename T, typename E>
[[nodiscard]] E error_of(const std::expected<T, E>& result)
{
    if (result.has_value()) {
        ADD_FAILURE() << "expected a refusal, got a value";
        return E{};
    }
    return result.error();
}

}
