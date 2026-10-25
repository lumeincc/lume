// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/kdf.hpp"

#include "support/mutate.hpp"
#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <algorithm>
#include <cstddef>

namespace lume::crypto {
namespace {

TEST(HmacSha256, MatchesWycheproof)
{
    const auto suite = test::load_wycheproof("hmac_sha256_test.json");
    const int checked = test::for_each_wycheproof_case(suite, [](const test::WycheproofCase& vector) {
        const auto tag_bytes = vector.group.at("tagSize").get<std::size_t>() / 8;
        const auto expected = vector.bytes("tag");
        const auto tag = hmac_sha256(vector.bytes("key"), vector.bytes("msg"));
        const bool matches = expected.size() == tag_bytes && std::ranges::equal(tag.view().first(tag_bytes), expected);
        EXPECT_EQ(matches, vector.result() == "valid") << "tcId " << vector.id();
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(HkdfSha256, MatchesWycheproof)
{
    const auto suite = test::load_wycheproof("hkdf_sha256_test.json");
    const int checked = test::for_each_wycheproof_case(suite, [](const test::WycheproofCase& vector) {
        const auto output = hkdf_sha256(
            vector.bytes("salt"), vector.bytes("ikm"), vector.bytes("info"), vector.test.at("size").get<std::size_t>());
        if (vector.result() == "valid") {
            ASSERT_TRUE(output.has_value()) << "tcId " << vector.id();
            EXPECT_TRUE(output->equals(vector.bytes("okm"))) << "tcId " << vector.id();
        } else {
            ASSERT_FALSE(output.has_value()) << "tcId " << vector.id();
            EXPECT_EQ(output.error(), Error::invalid_size) << "tcId " << vector.id();
        }
    });
    EXPECT_EQ(checked, suite.at("numberOfTests").get<int>());
}

TEST(HkdfSha256, RefusesEmptyOutput)
{
    const auto output = hkdf_sha256({}, Bytes{1, 2, 3}, {}, 0);
    ASSERT_FALSE(output.has_value());
    EXPECT_EQ(output.error(), Error::invalid_size);
}

TEST(HkdfSha256, AcceptsTheLargestOutputAndRefusesOneMore)
{
    const Bytes input_key(32, 7);
    EXPECT_TRUE(hkdf_sha256({}, input_key, {}, hkdf_sha256_max_length).has_value());
    EXPECT_FALSE(hkdf_sha256({}, input_key, {}, hkdf_sha256_max_length + 1).has_value());
}

RC_GTEST_PROP(KdfProperties, ShorterHkdfOutputIsAPrefixOfLongerOutput,
    (const Bytes& salt, const Bytes& input_key, const Bytes& info))
{
    const auto short_length = *rc::gen::inRange<std::size_t>(1, 100);
    const auto long_length = short_length + *rc::gen::inRange<std::size_t>(1, 100);
    const auto short_output = hkdf_sha256(salt, input_key, info, short_length);
    const auto long_output = hkdf_sha256(salt, input_key, info, long_length);
    RC_ASSERT(short_output.has_value() && long_output.has_value());
    RC_ASSERT(std::ranges::equal(short_output->view(), long_output->view().first(short_length)));
}

RC_GTEST_PROP(KdfProperties, DifferentInfoGivesDifferentKeys, (const Bytes& input_key, const Bytes& info))
{
    Bytes other_info(info);
    other_info.push_back(0);
    const auto first = hkdf_sha256({}, input_key, info, 32);
    const auto second = hkdf_sha256({}, input_key, other_info, 32);
    RC_ASSERT(first.has_value() && second.has_value());
    RC_ASSERT_FALSE(first->equals(second->view()));
}

RC_GTEST_PROP(KdfProperties, HmacDependsOnEveryKeyBit, (const Bytes& key, const Bytes& message))
{
    RC_PRE(!key.empty());
    const auto original = hmac_sha256(key, message);
    const auto changed = hmac_sha256(test::flip_random_bit(key), message);
    RC_ASSERT_FALSE(original.equals(changed.view()));
}

}
}
