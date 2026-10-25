// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/library.hpp"

#include "backend.hpp"

#include <exception>
#include <expected>

namespace lume::crypto {

Result<void> initialise()
{
    try {
        return detail::operational_state();
    } catch (const std::exception&) {
        return std::unexpected(Error::library_failure);
    }
}

}
