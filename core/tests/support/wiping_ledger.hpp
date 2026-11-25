// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "crypto/wiping_allocator.hpp"

#include <cstdint>

namespace lume::test {

class LedgerLimit {
public:
    explicit LedgerLimit(std::uint64_t allowed) noexcept
        : saved_(crypto::detail::wiping_ledger().limit)
    {
        auto& ledger = crypto::detail::wiping_ledger();
        ledger.limit = ledger.made + allowed;
    }

    LedgerLimit(const LedgerLimit&) = delete;
    LedgerLimit& operator=(const LedgerLimit&) = delete;
    LedgerLimit(LedgerLimit&&) = delete;
    LedgerLimit& operator=(LedgerLimit&&) = delete;

    ~LedgerLimit()
    {
        crypto::detail::wiping_ledger().limit = saved_;
    }

private:
    std::uint64_t saved_;
};

}
