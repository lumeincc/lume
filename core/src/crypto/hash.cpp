// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/hash.hpp"

#include "backend.hpp"

#include <sodium.h>

#include <cstdint>
#include <span>

namespace lume::crypto {

ByteArray<sha256_size> sha256(ByteView data)
{
    return sha256({data});
}

namespace {

void sha256_into(std::initializer_list<ByteView> parts, std::span<std::uint8_t, sha256_size> digest)
{
    detail::require_operational();
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    for (const ByteView part : parts) {
        crypto_hash_sha256_update(&state, detail::pointer_to(part), part.size());
    }
    crypto_hash_sha256_final(&state, digest.data());
    sodium_memzero(&state, sizeof state);
}

}

ByteArray<sha256_size> sha256(std::initializer_list<ByteView> parts)
{
    ByteArray<sha256_size> digest{};
    sha256_into(parts, digest);
    return digest;
}

SecretBytes sha256_secret(std::initializer_list<ByteView> parts)
{
    SecretBytes digest(sha256_size);
    sha256_into(parts, digest.writable().first<sha256_size>());
    return digest;
}

ByteArray<sha512_size> sha512(ByteView data)
{
    return sha512({data});
}

ByteArray<sha512_size> sha512(std::initializer_list<ByteView> parts)
{
    detail::require_operational();
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    for (const ByteView part : parts) {
        crypto_hash_sha512_update(&state, detail::pointer_to(part), part.size());
    }
    ByteArray<sha512_size> digest{};
    crypto_hash_sha512_final(&state, digest.data());
    sodium_memzero(&state, sizeof state);
    return digest;
}

}
