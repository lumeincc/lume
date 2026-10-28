// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/x25519.hpp"

namespace lume::test {

[[nodiscard]] crypto::ByteArray<crypto::x25519_key_size> x25519_twin(crypto::ByteView public_key);

}
