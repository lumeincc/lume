// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/random.hpp"

#include "backend.hpp"

#include <sodium.h>

namespace lume::crypto {

void random_fill(std::span<std::uint8_t> output)
{
    if (output.empty()) {
        return;
    }
    detail::ensure_backends_ready();
    randombytes_buf(output.data(), output.size());
}

SecretBytes random_secret(std::size_t size)
{
    SecretBytes secret(size);
    random_fill(secret.writable());
    return secret;
}

}
