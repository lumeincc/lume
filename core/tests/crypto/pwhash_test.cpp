// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/pwhash.hpp"

#include "support/expected.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

namespace lume::crypto {
namespace {

std::string text_of(const Bytes& bytes)
{
    return {bytes.begin(), bytes.end()};
}

TEST(Argon2id, MatchesTheLumeVectors)
{
    const auto vectors = test::load_vectors("lume/vault.json");
    int checked = 0;
    for (const auto& vector : vectors.at("argon2id")) {
        const auto name = vector.at("name").get<std::string>();
        const auto key = argon2id(text_of(test::from_hex(vector.at("passphrase").get<std::string>())),
            test::from_hex(vector.at("salt").get<std::string>()), vector.at("ops").get<std::uint32_t>(),
            vector.at("mem").get<std::uint32_t>());
        ASSERT_TRUE(key.has_value()) << name;
        EXPECT_EQ(test::to_hex(key->view()), vector.at("key").get<std::string>()) << name;
        ++checked;
    }
    EXPECT_EQ(checked, 3);
}

TEST(Argon2id, RefusesWhatLibsodiumCannotRun)
{
    const Bytes salt(argon2id_salt_size, 1);
    EXPECT_EQ(test::error_of(argon2id("x", Bytes(argon2id_salt_size - 1, 1), 1, 8)), Error::invalid_size);
    EXPECT_EQ(test::error_of(argon2id("x", Bytes(argon2id_salt_size + 1, 1), 1, 8)), Error::invalid_size);
    EXPECT_EQ(test::error_of(argon2id("x", salt, 0, 8)), Error::out_of_range);
    EXPECT_EQ(test::error_of(argon2id("x", salt, 1, 7)), Error::out_of_range);
    EXPECT_TRUE(argon2id("x", salt, 1, 8).has_value());
}

TEST(Argon2id, DependsOnEveryInput)
{
    const Bytes salt(argon2id_salt_size, 1);
    const auto base = argon2id("passphrase", salt, 1, 16);
    ASSERT_TRUE(base.has_value());
    EXPECT_EQ(base->size(), argon2id_key_size);
    const auto differs = [&base](const Result<SecretBytes>& other) {
        return other.has_value() && !other->equals(base->view());
    };
    EXPECT_TRUE(differs(argon2id("passphrasf", salt, 1, 16)));
    EXPECT_TRUE(differs(argon2id("passphrase", Bytes(argon2id_salt_size, 2), 1, 16)));
    EXPECT_TRUE(differs(argon2id("passphrase", salt, 2, 16)));
    EXPECT_TRUE(differs(argon2id("passphrase", salt, 1, 24)));
    const auto again = argon2id("passphrase", salt, 1, 16);
    ASSERT_TRUE(again.has_value());
    EXPECT_TRUE(again->equals(base->view()));
}

}
}
