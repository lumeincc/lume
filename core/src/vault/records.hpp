// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "crypto/hmac_internal.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/vault/vault.hpp"
#include "lume/wire/structures.hpp"
#include "vault/keys.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace lume::vault {

inline constexpr std::array<std::size_t, 10> record_buckets{
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072};
inline constexpr std::size_t manifest_encoded_bound = 8 + 2 + (wire::manifest_types_bound * (1 + 4 + wire::manifest_root_size));
inline constexpr std::array<std::size_t, 1> manifest_buckets{manifest_encoded_bound + 1};
inline constexpr std::size_t sealed_manifest_size = crypto::aead_overhead + manifest_buckets.front();
inline constexpr std::size_t sealed_address_size = crypto::aead_overhead + wire::vault_address_size;
inline constexpr std::size_t record_minimum = crypto::aead_overhead + record_buckets.front();
inline constexpr std::size_t record_maximum = crypto::aead_overhead + record_buckets.back();
inline constexpr std::uint64_t slot_bound = (std::uint64_t{1} << 63U) - 1;

using Nonce = crypto::ByteArray<crypto::aead_nonce_size>;
using Root = crypto::ByteArray<wire::manifest_root_size>;

struct RecordAddress {
    RecordType type = 0;
    crypto::Bytes id;
    std::uint64_t counter = 0;
};

struct Located {
    RecordAddress address;
    Nonce nonce{};
};

class TermHasher {
public:
    [[nodiscard]] static Result<TermHasher> of(const Keys& keys);
    [[nodiscard]] Result<Root> term(const RecordAddress& address, const Nonce& nonce) const;

private:
    explicit TermHasher(crypto::detail::HmacKey key) noexcept;

    crypto::detail::HmacKey key_;
};

[[nodiscard]] std::uint64_t fresh_slot();
[[nodiscard]] Result<Nonce> nonce_of(crypto::ByteView record);
[[nodiscard]] Result<crypto::Bytes> seal_record(const Keys& keys, const RecordAddress& address, crypto::ByteView payload);
[[nodiscard]] Result<crypto::SecretBytes> open_record(
    const Keys& keys, const RecordAddress& address, const Nonce& expected, crypto::ByteView record);
[[nodiscard]] Result<crypto::Bytes> seal_address(const Keys& keys, std::uint64_t slot, const Located& located);
[[nodiscard]] Result<Located> open_address(
    const Keys& keys, std::uint64_t slot, crypto::ByteView sealed, crypto::SecretBytes& scratch);
[[nodiscard]] Result<Root> root_term(const Keys& keys, const RecordAddress& address, const Nonce& nonce);
[[nodiscard]] Root add_term(const Root& root, const Root& term) noexcept;
[[nodiscard]] Root remove_term(const Root& root, const Root& term) noexcept;
[[nodiscard]] Result<crypto::Bytes> seal_manifest(const OpenedHeader& opened, const std::vector<wire::ManifestEntry>& types);
[[nodiscard]] Result<wire::Manifest> open_manifest(const OpenedHeader& opened, crypto::ByteView sealed);

}
