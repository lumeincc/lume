// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace lume::lab {

class Report {
public:
    void section(std::string_view title);
    void check(std::string_view claim, bool holds);

    [[nodiscard]] int checks() const noexcept;
    [[nodiscard]] int failures() const noexcept;
    void summary() const;

private:
    int sections_ = 0;
    int checks_ = 0;
    int failures_ = 0;
};

void note(std::string_view text);

[[nodiscard]] std::string short_hex(crypto::ByteView bytes, std::size_t shown = 8);

[[nodiscard]] std::string grouped(std::string_view text, std::size_t group, std::string_view separator);

}
