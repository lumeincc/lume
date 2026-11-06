// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/aead.hpp"
#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/wire/structures.hpp"
#include "vault/keys.hpp"
#include "vault/records.hpp"

#include <cstdint>
#include <vector>

namespace lume::vault::detail {

using Nonce = crypto::ByteArray<crypto::aead_nonce_size>;

[[nodiscard]] Result<OpenedHeader> first_header(
    const MasterKey& master_key, const crypto::SecretBytes& data_key, const Nonce& nonce);

[[nodiscard]] Result<OpenedHeader> next_header(const HardwareKey& hardware_key, const OpenedHeader& current, const Nonce& nonce);

[[nodiscard]] Result<OpenedHeader> rekeyed_header(
    const MasterKey& master_key, const OpenedHeader& current, const Confirmed& confirmed, const Nonce& nonce);

[[nodiscard]] Result<crypto::Bytes> seal_record(
    const Keys& keys, const RecordAddress& address, crypto::ByteView payload, const Nonce& nonce);

[[nodiscard]] Result<crypto::Bytes> seal_address(
    const Keys& keys, std::uint64_t slot, const Located& located, const Nonce& nonce);

[[nodiscard]] Result<crypto::Bytes> seal_manifest(
    const OpenedHeader& opened, const std::vector<wire::ManifestEntry>& types, const Nonce& nonce);

}
