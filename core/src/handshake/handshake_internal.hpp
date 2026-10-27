// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/handshake/handshake.hpp"

namespace lume::handshake::detail {

[[nodiscard]] Result<Initiation> initiate_with(
    const identity::Identity& alice, const Bundle& bob, const std::optional<Pin>& pinned, std::uint64_t now,
    crypto::SecretBytes ephemeral_secret, const crypto::MlKemEncapsulation& encapsulation);

}
