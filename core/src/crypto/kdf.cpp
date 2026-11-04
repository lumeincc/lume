// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/kdf.hpp"

#include "backend.hpp"
#include "crypto/hmac_internal.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <expected>
#include <string>
#include <utility>

namespace lume::crypto {

namespace detail {

HmacKey::HmacKey(SecretBytes state) noexcept
    : state_(std::move(state))
{
}

HmacKey HmacKey::of(ByteView key)
{
    require_operational();
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, pointer_to(key), key.size());
    SecretBytes stored(sizeof state);
    std::memcpy(stored.writable().data(), &state, sizeof state);
    sodium_memzero(&state, sizeof state);
    return HmacKey(std::move(stored));
}

void HmacKey::tag(ByteView message, std::span<std::uint8_t, hmac_sha256_size> out) const noexcept
{
    crypto_auth_hmacsha256_state state;
    if (state_.size() != sizeof state) {
        std::ranges::fill(out, std::uint8_t{0});
        return;
    }
    std::memcpy(&state, state_.view().data(), sizeof state);
    crypto_auth_hmacsha256_update(&state, pointer_to(message), message.size());
    crypto_auth_hmacsha256_final(&state, out.data());
    sodium_memzero(&state, sizeof state);
}

}

SecretBytes hmac_sha256(ByteView key, ByteView message)
{
    detail::require_operational();
    SecretBytes tag(hmac_sha256_size);
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, detail::pointer_to(key), key.size());
    crypto_auth_hmacsha256_update(&state, detail::pointer_to(message), message.size());
    crypto_auth_hmacsha256_final(&state, tag.writable().data());
    sodium_memzero(&state, sizeof state);
    return tag;
}

Result<SecretBytes> hkdf_sha256(ByteView salt, ByteView input_key, ByteView info, std::size_t length)
{
    if (length == 0 || length > hkdf_sha256_max_length) {
        return std::unexpected(Error::invalid_size);
    }
    detail::require_operational();

    SecretBytes pseudorandom_key(crypto_kdf_hkdf_sha256_KEYBYTES);
    if (crypto_kdf_hkdf_sha256_extract(
            pseudorandom_key.writable().data(), detail::pointer_to(salt), salt.size(), detail::pointer_to(input_key),
            input_key.size())
        != 0) {
        return std::unexpected(Error::library_failure);
    }

    SecretBytes output(length);
    std::string context(info.size(), '\0');
    std::ranges::transform(info, context.begin(), [](std::uint8_t byte) { return static_cast<char>(byte); });
    if (crypto_kdf_hkdf_sha256_expand(
            output.writable().data(), output.size(), context.data(), context.size(),
            pseudorandom_key.view().data())
        != 0) {
        return std::unexpected(Error::library_failure);
    }
    return output;
}

}
