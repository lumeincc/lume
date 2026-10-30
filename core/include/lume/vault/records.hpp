// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/vault/keys.hpp"
#include "lume/wire/structures.hpp"

#include <cstddef>
#include <cstdint>

namespace lume::vault {

inline constexpr std::size_t record_id_bound = 64;

using Root = crypto::ByteArray<wire::manifest_root_size>;
using Tag = crypto::ByteArray<crypto::hmac_sha256_size>;

struct RecordAddress {
    std::uint8_t type = 0;
    crypto::Bytes id;
    std::uint64_t counter = 0;
};

[[nodiscard]] Result<crypto::Bytes> seal_record(const Keys& keys, const RecordAddress& address, crypto::ByteView payload);

[[nodiscard]] Result<crypto::SecretBytes> open_record(
    const Keys& keys, const RecordAddress& address, crypto::ByteView record);

[[nodiscard]] Result<Root> root_term(const Keys& keys, const RecordAddress& address, crypto::ByteView record);

[[nodiscard]] Root add_term(const Root& root, const Root& term);

[[nodiscard]] Root remove_term(const Root& root, const Root& term);

[[nodiscard]] Result<Tag> manifest_tag(const Keys& keys, const wire::Manifest& manifest);

[[nodiscard]] Result<void> check_manifest(
    const Keys& keys, const wire::Manifest& manifest, crypto::ByteView tag, std::uint64_t epoch);

}
