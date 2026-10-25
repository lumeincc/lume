// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/library.hpp"

#include "backend.hpp"
#include "self_test.hpp"

#include <exception>
#include <expected>

namespace lume::crypto {

namespace {

Result<void> start()
{
    try {
        detail::ensure_backends_ready();
        return detail::run_self_test();
    } catch (const std::exception&) {
        return std::unexpected(Error::library_failure);
    }
}

}

Result<void> initialise()
{
    static const Result<void> outcome = start();
    return outcome;
}

}
