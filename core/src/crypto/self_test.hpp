// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/error.hpp"

namespace lume::crypto::detail {

[[nodiscard]] Result<void> run_self_test();

}
