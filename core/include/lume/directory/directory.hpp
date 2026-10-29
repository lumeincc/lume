// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/identity/identity.hpp"
#include "lume/wire/structures.hpp"

#include <cstdint>
#include <expected>
#include <optional>

namespace lume::directory {

inline constexpr std::uint64_t day = std::uint64_t{24} * 60 * 60;
inline constexpr std::uint64_t list_lifetime = 14 * day;
inline constexpr std::uint64_t certificate_lifetime = 30 * day;
inline constexpr std::uint64_t certificate_horizon = 31 * day;
inline constexpr std::uint64_t revocation_margin = day;

enum class Error : std::uint8_t {
    invalid_signature,
    malformed,
    lifetime_too_long,
    not_yet_valid,
    expired,
    rolled_back,
    conflicting_list,
    list_expired,
    unknown_key,
    key_outside_window,
    wrong_identity,
    wrong_account,
};

template <typename T>
using Result = std::expected<T, Error>;

[[nodiscard]] crypto::Bytes list_message(const wire::DirectoryKeys& list);

[[nodiscard]] crypto::Bytes certificate_message(const wire::UsernameCertificate& certificate);

class TrustedList {
public:
    [[nodiscard]] static Result<TrustedList> verify(crypto::ByteView root_key, wire::DirectoryKeys list);

    [[nodiscard]] const wire::DirectoryKeys& keys() const noexcept;
    [[nodiscard]] bool current_at(std::uint64_t now) const noexcept;

private:
    explicit TrustedList(wire::DirectoryKeys list) noexcept;

    wire::DirectoryKeys list_;
};

[[nodiscard]] Result<TrustedList> accept_list(
    crypto::ByteView root_key, wire::DirectoryKeys candidate, std::uint64_t now,
    const std::optional<TrustedList>& held);

[[nodiscard]] Result<void> check_certificate(
    const TrustedList& list, const wire::UsernameCertificate& certificate, std::uint64_t now,
    const identity::PublicIdentity& peer, const crypto::ByteArray<wire::account_id_size>& account_id);

[[nodiscard]] bool distrusts(const TrustedList& list, std::uint32_t key_id, std::uint64_t accepted_at) noexcept;

}
