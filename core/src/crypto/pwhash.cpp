// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/pwhash.hpp"

#include "backend.hpp"

#include <sodium.h>

#include <expected>

namespace lume::crypto {

static_assert(argon2id_salt_size == crypto_pwhash_argon2id_SALTBYTES);

Result<SecretBytes> argon2id(std::string_view passphrase, ByteView salt, std::uint32_t passes, std::uint32_t memory_kib)
{
    constexpr std::uint64_t kibibyte = 1024;
    const std::uint64_t memory = memory_kib * kibibyte;
    if (salt.size() != argon2id_salt_size) {
        return std::unexpected(Error::invalid_size);
    }
    if (passphrase.size() > crypto_pwhash_argon2id_PASSWD_MAX || passes < crypto_pwhash_argon2id_OPSLIMIT_MIN
        || memory < crypto_pwhash_argon2id_MEMLIMIT_MIN || memory > crypto_pwhash_argon2id_MEMLIMIT_MAX) {
        return std::unexpected(Error::out_of_range);
    }
    detail::require_operational();
    SecretBytes key(argon2id_key_size);
    if (crypto_pwhash(
            key.writable().data(), key.size(), passphrase.data(), passphrase.size(), salt.data(), passes,
            static_cast<std::size_t>(memory), crypto_pwhash_ALG_ARGON2ID13)
        != 0) {
        return std::unexpected(Error::library_failure);
    }
    return key;
}

}
