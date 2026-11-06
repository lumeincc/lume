// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include <gtest/gtest.h>

#include <bit>
#include <expected>
#include <limits>
#include <type_traits>

namespace lume::test {

template <typename T, typename E>
[[nodiscard]] E error_of(const std::expected<T, E>& result)
{
    if (result.has_value()) {
        ADD_FAILURE() << "expected a refusal, got a value";
        return std::bit_cast<E>(std::numeric_limits<std::underlying_type_t<E>>::max());
    }
    return result.error();
}

}
