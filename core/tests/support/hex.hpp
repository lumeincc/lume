// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace lume::test {

[[nodiscard]] std::optional<crypto::Bytes> decode_hex(std::string_view hex);

[[nodiscard]] std::string encode_hex(crypto::ByteView bytes);

}
