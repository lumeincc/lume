// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <string_view>

namespace lume::test {

struct WycheproofCase {
    const nlohmann::json& group;
    const nlohmann::json& test;

    [[nodiscard]] int id() const;
    [[nodiscard]] std::string result() const;
    [[nodiscard]] bool has_flag(std::string_view flag) const;
    [[nodiscard]] crypto::Bytes bytes(std::string_view field) const;
    [[nodiscard]] crypto::Bytes group_bytes(std::string_view field) const;
};

[[nodiscard]] nlohmann::json load_wycheproof(std::string_view file_name);

int for_each_wycheproof_case(const nlohmann::json& suite, const std::function<void(const WycheproofCase&)>& check);

[[nodiscard]] crypto::Bytes from_hex(std::string_view hex);

[[nodiscard]] std::string to_hex(crypto::ByteView bytes);

}
