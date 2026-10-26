// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "report.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <iostream>

namespace lume::lab {

void Report::section(std::string_view title)
{
    ++sections_;
    std::cout << std::format("\n{}. {}\n", sections_, title);
}

void note(std::string_view text)
{
    std::cout << std::format("       {}\n", text);
}

void Report::check(std::string_view claim, bool holds)
{
    ++checks_;
    if (!holds) {
        ++failures_;
    }
    std::cout << std::format("   {} {}\n", holds ? "[ ok ]" : "[FAIL]", claim);
}

int Report::checks() const noexcept
{
    return checks_;
}

int Report::failures() const noexcept
{
    return failures_;
}

void Report::summary() const
{
    if (failures_ == 0) {
        std::cout << std::format("\nAll {} checks passed.\n", checks_);
    } else {
        std::cout << std::format("\n{} of {} checks FAILED.\n", failures_, checks_);
    }
}

std::string short_hex(crypto::ByteView bytes, std::size_t shown)
{
    std::string text;
    for (const std::uint8_t byte : bytes.first(std::min(shown, bytes.size()))) {
        text += std::format("{:02x}", byte);
    }
    if (bytes.size() > shown) {
        text += std::format("... ({} bytes)", bytes.size());
    }
    return text;
}

std::string grouped(std::string_view text, std::size_t group, std::string_view separator)
{
    std::string result;
    for (std::size_t start = 0; start < text.size(); start += group) {
        if (start != 0) {
            result += separator;
        }
        result += text.substr(start, group);
    }
    return result;
}

}
