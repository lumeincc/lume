// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/kdf.hpp"

#include "backend.hpp"

#include <sodium.h>

#include <expected>

namespace lume::crypto {

SecretBytes hmac_sha256(ByteView key, ByteView message)
{
    detail::ensure_backends_ready();
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
    detail::ensure_backends_ready();

    SecretBytes pseudorandom_key(crypto_kdf_hkdf_sha256_KEYBYTES);
    if (crypto_kdf_hkdf_sha256_extract(
            pseudorandom_key.writable().data(), detail::pointer_to(salt), salt.size(), detail::pointer_to(input_key),
            input_key.size())
        != 0) {
        return std::unexpected(Error::library_failure);
    }

    SecretBytes output(length);
    const auto* context = reinterpret_cast<const char*>(detail::pointer_to(info));
    if (crypto_kdf_hkdf_sha256_expand(
            output.writable().data(), output.size(), context, info.size(), pseudorandom_key.view().data())
        != 0) {
        return std::unexpected(Error::library_failure);
    }
    return output;
}

}
