// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstdint>

namespace lume::test {

inline crypto::Bytes utf8_of(std::uint32_t code_point)
{
    if (code_point < 0x80) {
        return {static_cast<std::uint8_t>(code_point)};
    }
    if (code_point < 0x800) {
        return {static_cast<std::uint8_t>(0xc0U | (code_point >> 6U)), static_cast<std::uint8_t>(0x80U | (code_point & 0x3fU))};
    }
    if (code_point < 0x10000) {
        return {static_cast<std::uint8_t>(0xe0U | (code_point >> 12U)),
            static_cast<std::uint8_t>(0x80U | ((code_point >> 6U) & 0x3fU)),
            static_cast<std::uint8_t>(0x80U | (code_point & 0x3fU))};
    }
    return {static_cast<std::uint8_t>(0xf0U | (code_point >> 18U)),
        static_cast<std::uint8_t>(0x80U | ((code_point >> 12U) & 0x3fU)),
        static_cast<std::uint8_t>(0x80U | ((code_point >> 6U) & 0x3fU)),
        static_cast<std::uint8_t>(0x80U | (code_point & 0x3fU))};
}

}
