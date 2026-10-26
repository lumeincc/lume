// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/identity/identity.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace lume::safety {

inline constexpr std::size_t fingerprint_digits = 30;
inline constexpr std::size_t safety_number_digits = 2 * fingerprint_digits;
inline constexpr std::size_t invite_fingerprint_size = 16;
inline constexpr std::uint32_t fingerprint_iterations = 5200;

using InviteFingerprint = crypto::ByteArray<invite_fingerprint_size>;

[[nodiscard]] bool same_identity(const identity::PublicIdentity& first, const identity::PublicIdentity& second);

[[nodiscard]] std::string fingerprint(const identity::PublicIdentity& identity);

[[nodiscard]] std::string safety_number(const identity::PublicIdentity& first, const identity::PublicIdentity& second);

[[nodiscard]] InviteFingerprint invite_fingerprint(const identity::PublicIdentity& identity);

[[nodiscard]] bool matches_invite(const identity::PublicIdentity& identity, crypto::ByteView fingerprint);

}
