// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include <cstddef>

namespace lume::crypto::detail {

void raise_lock_limit() noexcept;

void lock_or_count(void* data, std::size_t size) noexcept;

}
