// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "support/vectors.hpp"

#include "support/hex.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <utility>

namespace lume::test {

int WycheproofCase::id() const
{
    return test.at("tcId").get<int>();
}

std::string WycheproofCase::result() const
{
    return test.at("result").get<std::string>();
}

bool WycheproofCase::has_flag(std::string_view flag) const
{
    if (!test.contains("flags")) {
        return false;
    }
    const auto& flags = test.at("flags");
    return std::ranges::any_of(flags, [flag](const nlohmann::json& value) { return value.get<std::string>() == flag; });
}

crypto::Bytes WycheproofCase::bytes(std::string_view field) const
{
    return from_hex(test.at(std::string(field)).get<std::string>());
}

crypto::Bytes WycheproofCase::group_bytes(std::string_view field) const
{
    return from_hex(group.at(std::string(field)).get<std::string>());
}

nlohmann::json load_wycheproof(std::string_view file_name)
{
    const auto path = std::filesystem::path(LUME_TEST_VECTORS_DIR) / "wycheproof" / file_name;
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot open test vectors: " + path.string());
    }
    return nlohmann::json::parse(input);
}

int for_each_wycheproof_case(const nlohmann::json& suite, const std::function<void(const WycheproofCase&)>& check)
{
    int checked = 0;
    for (const auto& group : suite.at("testGroups")) {
        for (const auto& test : group.at("tests")) {
            check(WycheproofCase{.group = group, .test = test});
            ++checked;
        }
    }
    return checked;
}

crypto::Bytes from_hex(std::string_view hex)
{
    auto bytes = decode_hex(hex);
    if (!bytes) {
        throw std::invalid_argument("malformed hex in test vectors");
    }
    return std::move(*bytes);
}

std::string to_hex(crypto::ByteView bytes)
{
    return encode_hex(bytes);
}

}
