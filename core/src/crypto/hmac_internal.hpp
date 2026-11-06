// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/secret_bytes.hpp"

#include <cstdint>
#include <span>

namespace lume::crypto::detail {

class HmacKey {
public:
    [[nodiscard]] static HmacKey of(ByteView key);

    [[nodiscard]] bool tag(ByteView message, std::span<std::uint8_t, hmac_sha256_size> out) const noexcept;

private:
    explicit HmacKey(SecretBytes state) noexcept;

    SecretBytes state_;
};

}
