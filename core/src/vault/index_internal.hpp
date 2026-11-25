// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "vault/index.hpp"
#include "vault/records.hpp"

#include <cstdint>
#include <functional>

namespace lume::vault::detail {

struct Draws {
    std::function<std::uint64_t()> slot;
    std::function<Nonce()> record_nonce;
    std::function<Nonce()> address_nonce;
    std::function<Nonce()> manifest_nonce;
};

}
