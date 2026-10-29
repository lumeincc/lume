// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/aead.hpp"
#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/vault/keys.hpp"
#include "lume/vault/records.hpp"
#include "lume/wire/structures.hpp"

namespace lume::vault::detail {

using Nonce = crypto::ByteArray<crypto::aead_nonce_size>;

[[nodiscard]] Result<wire::VaultHeader> seal_header(
    const crypto::SecretBytes& master_key, const Keys& keys, const Protection& protection, const Nonce& nonce);

[[nodiscard]] Result<crypto::Bytes> seal_record(
    const Keys& keys, const RecordAddress& address, crypto::ByteView payload, const Nonce& nonce);

}
