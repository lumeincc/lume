// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/identity/identity.hpp"
#include "lume/wire/structures.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>

namespace lume::directory {

inline constexpr std::uint64_t day = std::uint64_t{24} * 60 * 60;
inline constexpr std::uint64_t list_lifetime = 14 * day;
inline constexpr std::uint64_t certificate_lifetime = 30 * day;
inline constexpr std::uint64_t certificate_horizon = 31 * day;
inline constexpr std::uint64_t revocation_margin = day;

enum class Error : std::uint8_t {
    invalid_signature,
    malformed,
    bad_lifetime,
    not_yet_valid,
    expired,
    rolled_back,
    conflicting_list,
    no_current_list,
    invalid_username,
    unknown_key,
    key_outside_window,
    wrong_identity,
    wrong_account,
};

template <typename T>
using Result = std::expected<T, Error>;

[[nodiscard]] crypto::Bytes list_message(const wire::DirectoryKeys& list);

[[nodiscard]] crypto::Bytes certificate_message(const wire::UsernameCertificate& certificate);

[[nodiscard]] bool is_valid_username(std::string_view username) noexcept;

class Directory {
public:
    explicit Directory(const crypto::ByteArray<wire::ed25519_key_size>& root_key) noexcept;

    [[nodiscard]] Result<void> restore(wire::DirectoryKeys stored);
    [[nodiscard]] Result<void> accept(wire::DirectoryKeys fetched, std::uint64_t now);

    [[nodiscard]] const std::optional<wire::DirectoryKeys>& list() const noexcept;
    [[nodiscard]] bool current_at(std::uint64_t now) const noexcept;

    [[nodiscard]] Result<void> check_certificate(
        const wire::UsernameCertificate& certificate, std::uint64_t now, const identity::PublicIdentity& peer,
        const crypto::ByteArray<wire::account_id_size>& account_id) const;

    [[nodiscard]] bool distrusts(std::uint32_t key_id, std::uint64_t accepted_at) const noexcept;

private:
    [[nodiscard]] Result<void> verify(const wire::DirectoryKeys& list) const;
    [[nodiscard]] Result<void> follows(const wire::DirectoryKeys& list) const;

    crypto::ByteArray<wire::ed25519_key_size> root_key_;
    std::optional<wire::DirectoryKeys> list_;
};

}
