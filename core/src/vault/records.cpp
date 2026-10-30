// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/vault/records.hpp"

#include "crypto/aead_internal.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/random.hpp"
#include "vault/vault_internal.hpp"

#include <algorithm>
#include <ranges>
#include <string_view>
#include <utility>

namespace lume::vault {
namespace {

constexpr unsigned byte_base = 256;
constexpr unsigned byte_mask = 0xff;
constexpr unsigned byte_bits = 8;

crypto::Bytes address_of(std::string_view name, const RecordAddress& address)
{
    return crypto::Encoder{}.label(name).u8(address.type).prefixed(address.id).u64(address.counter).take();
}

bool usable(const Keys& keys) noexcept
{
    return keys.record.size() == key_size && keys.manifest.size() == key_size && keys.root.size() == key_size;
}

crypto::SecretBytes tag_of(const Keys& keys, const wire::Manifest& manifest)
{
    return crypto::hmac_sha256(
        keys.manifest.view(), crypto::Encoder{}.label("vault/manifest").raw(wire::encode(manifest)).take());
}

}

Result<crypto::Bytes> seal_record(const Keys& keys, const RecordAddress& address, crypto::ByteView payload)
{
    return detail::seal_record(keys, address, payload, crypto::random_public_bytes<crypto::aead_nonce_size>());
}

Result<crypto::SecretBytes> open_record(const Keys& keys, const RecordAddress& address, crypto::ByteView record)
{
    if (!usable(keys)) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (address.id.size() > record_id_bound) {
        return std::unexpected(Error::integrity);
    }
    auto payload = crypto::aead_open(keys.record, address_of("vault/record", address), record);
    if (!payload) {
        return std::unexpected(Error::integrity);
    }
    return std::move(*payload);
}

Result<Root> root_term(const Keys& keys, const RecordAddress& address, crypto::ByteView record)
{
    if (!usable(keys)) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (address.id.size() > record_id_bound || record.size() < crypto::aead_overhead) {
        return std::unexpected(Error::integrity);
    }
    const auto term = crypto::hmac_sha256(keys.root.view(),
        crypto::Encoder{}.raw(address_of("vault/root", address)).raw(record.first(crypto::aead_nonce_size)).take());
    Root value{};
    std::ranges::copy(term.view(), value.begin());
    return value;
}

Root add_term(const Root& root, const Root& term)
{
    Root sum{};
    unsigned carry = 0;
    for (auto&& [out, left, right] : std::views::reverse(std::views::zip(sum, root, term))) {
        const unsigned total = unsigned{left} + unsigned{right} + carry;
        out = static_cast<std::uint8_t>(total & byte_mask);
        carry = total >> byte_bits;
    }
    return sum;
}

Root remove_term(const Root& root, const Root& term)
{
    Root difference{};
    unsigned borrow = 0;
    for (auto&& [out, left, right] : std::views::reverse(std::views::zip(difference, root, term))) {
        const unsigned total = unsigned{left} + byte_base - unsigned{right} - borrow;
        out = static_cast<std::uint8_t>(total & byte_mask);
        borrow = total < byte_base ? 1U : 0U;
    }
    return difference;
}

Result<Tag> manifest_tag(const Keys& keys, const wire::Manifest& manifest)
{
    if (!usable(keys) || !wire::is_canonical(manifest)) {
        return std::unexpected(Error::invalid_parameters);
    }
    Tag value{};
    std::ranges::copy(tag_of(keys, manifest).view(), value.begin());
    return value;
}

Result<void> check_manifest(const Keys& keys, const wire::Manifest& manifest, crypto::ByteView tag, std::uint64_t epoch)
{
    if (!usable(keys)) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (!wire::is_canonical(manifest) || !tag_of(keys, manifest).equals(tag) || manifest.epoch != epoch) {
        return std::unexpected(Error::integrity);
    }
    return {};
}

namespace detail {

Result<crypto::Bytes> seal_record(
    const Keys& keys, const RecordAddress& address, crypto::ByteView payload, const Nonce& nonce)
{
    if (!usable(keys) || address.id.size() > record_id_bound) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (payload.size() > crypto::aead_max_plaintext_size) {
        return std::unexpected(Error::record_too_large);
    }
    const auto sealed = crypto::detail::aead_encrypt(keys.record, nonce, address_of("vault/record", address), payload);
    if (!sealed) {
        return std::unexpected(Error::library_failure);
    }
    crypto::Bytes record(nonce.begin(), nonce.end());
    record.insert(record.end(), sealed->begin(), sealed->end());
    return record;
}

}

}
