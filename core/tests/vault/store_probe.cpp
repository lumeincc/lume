// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/store.hpp"

#include <cstddef>
#include <exception>
#include <span>

namespace {

constexpr int usage_error = 254;
constexpr int unexpected_error = 255;

}

int main(int argc, char** argv)
{
    try {
        const std::span arguments(argv, static_cast<std::size_t>(argc));
        if (arguments.size() != 2) {
            return usage_error;
        }
        const auto store = lume::vault::Store::open_existing(arguments.back(), nullptr);
        return store.has_value() ? 0 : static_cast<int>(store.error());
    } catch (const std::exception&) {
        return unexpected_error;
    }
}
