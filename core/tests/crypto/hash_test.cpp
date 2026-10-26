// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/hash.hpp"

#include "support/vectors.hpp"

#include <gtest/gtest.h>
#include "support/properties.hpp"

#include <string_view>

namespace lume::crypto {
namespace {

Bytes ascii(std::string_view text)
{
    return {text.begin(), text.end()};
}

TEST(Sha256, MatchesFips180Vectors)
{
    EXPECT_EQ(test::to_hex(sha256(ascii(""))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(test::to_hex(sha256(ascii("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(
        test::to_hex(sha256(ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha512, MatchesFips180Vectors)
{
    EXPECT_EQ(
        test::to_hex(sha512(ascii(""))),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    EXPECT_EQ(
        test::to_hex(sha512(ascii("abc"))),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

RC_GTEST_PROP(HashProperties, Sha256OfPartsEqualsSha256OfConcatenation, (const Bytes& first, const Bytes& second))
{
    Bytes joined(first);
    joined.insert(joined.end(), second.begin(), second.end());
    RC_ASSERT(sha256({ByteView(first), ByteView(second)}) == sha256(joined));
}

RC_GTEST_PROP(HashProperties, SecretSha256MatchesSha256, (const Bytes& first, const Bytes& second))
{
    const auto digest = sha256({ByteView(first), ByteView(second)});
    const auto secret = sha256_secret({ByteView(first), ByteView(second)});
    RC_ASSERT(secret.size() == sha256_size);
    RC_ASSERT(secret.equals(digest));
}

RC_GTEST_PROP(HashProperties, Sha512OfPartsEqualsSha512OfConcatenation, (const Bytes& first, const Bytes& second))
{
    Bytes joined(first);
    joined.insert(joined.end(), second.begin(), second.end());
    RC_ASSERT(sha512({ByteView(first), ByteView(second)}) == sha512(joined));
}

}
}
