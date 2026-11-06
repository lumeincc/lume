// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/records.hpp"

#include "crypto/aead_internal.hpp"
#include "crypto/backend.hpp"
#include "crypto/padding.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/random.hpp"
#include "lume/wire/codec.hpp"
#include "vault/key_access.hpp"
#include "vault/vault_internal.hpp"

#include <algorithm>
#include <array>
#include <iterator>
#include <ranges>
#include <span>
#include <string_view>
#include <utility>

namespace lume::vault {
namespace {

using crypto::SecretBytes;
using detail::KeyAccess;

static_assert(record_id_bound == wire::vault_record_id_bound);
static_assert(record_buckets.back() == crypto::aead_max_plaintext_size);
static_assert(payload_bound == record_buckets.back() - 1);
static_assert(sealed_address_size == 138);
static_assert(sealed_manifest_size == 1235);

constexpr unsigned byte_base = 256;
constexpr unsigned byte_mask = 0xff;
constexpr unsigned byte_bits = 8;
constexpr std::size_t term_message_bound = 128;

class StackMessage {
public:
    void raw(crypto::ByteView bytes) noexcept
    {
        const auto room = std::span(bytes_).subspan(size_);
        const auto count = std::min(bytes.size(), room.size());
        std::ranges::copy(bytes.first(count), room.begin());
        size_ += count;
        overflowed_ = overflowed_ || count != bytes.size();
    }

    void u8(std::uint8_t value) noexcept
    {
        raw(std::array<std::uint8_t, 1>{value});
    }

    void u32(std::uint32_t value) noexcept
    {
        raw(std::array<std::uint8_t, 4>{static_cast<std::uint8_t>(value >> 24U), static_cast<std::uint8_t>(value >> 16U),
            static_cast<std::uint8_t>(value >> 8U), static_cast<std::uint8_t>(value)});
    }

    void u64(std::uint64_t value) noexcept
    {
        raw(std::array<std::uint8_t, 8>{static_cast<std::uint8_t>(value >> 56U), static_cast<std::uint8_t>(value >> 48U),
            static_cast<std::uint8_t>(value >> 40U), static_cast<std::uint8_t>(value >> 32U),
            static_cast<std::uint8_t>(value >> 24U), static_cast<std::uint8_t>(value >> 16U),
            static_cast<std::uint8_t>(value >> 8U), static_cast<std::uint8_t>(value)});
    }

    [[nodiscard]] bool overflowed() const noexcept
    {
        return overflowed_;
    }

    [[nodiscard]] crypto::ByteView view() const noexcept
    {
        return std::span(bytes_).first(size_);
    }

private:
    std::array<std::uint8_t, term_message_bound> bytes_{};
    std::size_t size_ = 0;
    bool overflowed_ = false;
};

bool valid_address(const RecordAddress& address) noexcept
{
    return address.type != 0 && address.id.size() <= record_id_bound;
}

crypto::Bytes record_data(const RecordAddress& address)
{
    return crypto::Encoder{}.label("vault/record").u8(address.type).prefixed(address.id).u64(address.counter).take();
}

crypto::Bytes address_data(std::uint64_t slot)
{
    return crypto::Encoder{}.label("vault/address").u64(slot).take();
}

bool constant_time_equal(crypto::ByteView first, crypto::ByteView second)
{
    return SecretBytes::copy_of(first).equals(second);
}

Result<SecretBytes> padded_manifest(const wire::Manifest& manifest)
{
    if (!wire::is_canonical(manifest)) {
        return std::unexpected(Error::invalid_parameters);
    }
    const auto encoded = wire::encode(manifest);
    SecretBytes padded(manifest_buckets.front());
    if (!crypto::detail::pad_into(encoded, padded.writable(), manifest_buckets)) {
        return std::unexpected(Error::invalid_parameters);
    }
    return padded;
}

}

TermHasher::TermHasher(crypto::detail::HmacKey key) noexcept
    : key_(std::move(key))
{
}

Result<TermHasher> TermHasher::of(const Keys& keys)
{
    const auto& root = KeyAccess::root(keys);
    if (root.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    return TermHasher(crypto::detail::HmacKey::of(root.view()));
}

Result<Root> TermHasher::term(const RecordAddress& address, const Nonce& nonce) const
{
    if (!valid_address(address)) {
        return std::unexpected(Error::invalid_parameters);
    }
    StackMessage message;
    message.raw(crypto::label("vault/root"));
    message.u8(address.type);
    message.u32(static_cast<std::uint32_t>(address.id.size()));
    message.raw(address.id);
    message.u64(address.counter);
    message.raw(nonce);
    if (message.overflowed()) {
        return std::unexpected(Error::invalid_parameters);
    }
    Root term{};
    if (!key_.tag(message.view(), term)) {
        return std::unexpected(Error::invalid_parameters);
    }
    return term;
}

std::uint64_t fresh_slot()
{
    for (;;) {
        const auto bytes = crypto::random_public_bytes<8>();
        std::uint64_t slot = 0;
        for (const auto byte : bytes) {
            slot = (slot << byte_bits) | byte;
        }
        slot &= slot_bound;
        if (slot != 0) {
            return slot;
        }
    }
}

Result<Nonce> nonce_of(crypto::ByteView record)
{
    if (record.size() < record_minimum) {
        return std::unexpected(Error::integrity);
    }
    Nonce nonce{};
    std::ranges::copy(record.first(crypto::aead_nonce_size), nonce.begin());
    return nonce;
}

Result<crypto::Bytes> seal_record(const Keys& keys, const RecordAddress& address, crypto::ByteView payload)
{
    return detail::seal_record(keys, address, payload, crypto::random_public_bytes<crypto::aead_nonce_size>());
}

Result<SecretBytes> open_record(const Keys& keys, const RecordAddress& address, const Nonce& expected, crypto::ByteView record)
{
    const auto& key = KeyAccess::record(keys);
    if (key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (record.size() < record_minimum || record.size() > record_maximum || !valid_address(address)) {
        return std::unexpected(Error::integrity);
    }
    if (!constant_time_equal(record.first(crypto::aead_nonce_size), expected)) {
        return std::unexpected(Error::integrity);
    }
    const auto padded = crypto::aead_open(key, record_data(address), record);
    if (!padded) {
        return std::unexpected(Error::integrity);
    }
    const auto payload = crypto::detail::unpad(padded->view(), record_buckets);
    if (!payload) {
        return std::unexpected(Error::integrity);
    }
    return SecretBytes::copy_of(*payload);
}

Result<crypto::Bytes> seal_address(const Keys& keys, std::uint64_t slot, const Located& located)
{
    return detail::seal_address(keys, slot, located, crypto::random_public_bytes<crypto::aead_nonce_size>());
}

Result<Located> open_address(const Keys& keys, std::uint64_t slot, crypto::ByteView sealed, SecretBytes& scratch)
{
    const auto& key = KeyAccess::address(keys);
    if (key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (slot == 0 || slot > slot_bound || sealed.size() != sealed_address_size) {
        return std::unexpected(Error::integrity);
    }
    if (scratch.size() != wire::vault_address_size) {
        scratch = SecretBytes(wire::vault_address_size);
    }
    if (!crypto::detail::aead_open_into(key.view(), address_data(slot), sealed, scratch.writable())) {
        return std::unexpected(Error::integrity);
    }
    auto decoded = wire::decode(scratch.view(), wire::read_vault_address);
    if (!decoded) {
        return std::unexpected(Error::integrity);
    }
    Located located;
    located.address.type = decoded->type;
    located.address.id.assign(decoded->id.begin(), std::next(decoded->id.begin(), decoded->id_length));
    located.address.counter = decoded->counter;
    located.nonce = decoded->nonce;
    crypto::detail::wipe(decoded->id);
    crypto::detail::wipe(decoded->nonce);
    return located;
}

Result<Root> root_term(const Keys& keys, const RecordAddress& address, const Nonce& nonce)
{
    const auto hasher = TermHasher::of(keys);
    if (!hasher) {
        return std::unexpected(hasher.error());
    }
    return hasher->term(address, nonce);
}

Root add_term(const Root& root, const Root& term) noexcept
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

Root remove_term(const Root& root, const Root& term) noexcept
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

Result<crypto::Bytes> seal_manifest(const OpenedHeader& opened, const std::vector<wire::ManifestEntry>& types)
{
    return detail::seal_manifest(opened, types, crypto::random_public_bytes<crypto::aead_nonce_size>());
}

Result<wire::Manifest> open_manifest(const OpenedHeader& opened, crypto::ByteView sealed)
{
    const auto& key = KeyAccess::manifest(opened.keys());
    if (key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (sealed.size() != sealed_manifest_size) {
        return std::unexpected(Error::integrity);
    }
    const auto padded = crypto::aead_open(key, crypto::label("vault/manifest"), sealed);
    if (!padded) {
        return std::unexpected(Error::integrity);
    }
    const auto encoded = crypto::detail::unpad(padded->view(), manifest_buckets);
    if (!encoded) {
        return std::unexpected(Error::integrity);
    }
    auto manifest = wire::decode(*encoded, wire::read_manifest);
    if (!manifest || manifest->epoch != opened.header().epoch) {
        return std::unexpected(Error::integrity);
    }
    return std::move(*manifest);
}

namespace detail {

Result<crypto::Bytes> seal_record(const Keys& keys, const RecordAddress& address, crypto::ByteView payload, const Nonce& nonce)
{
    const auto& key = KeyAccess::record(keys);
    if (key.size() != key_size || !valid_address(address)) {
        return std::unexpected(Error::invalid_parameters);
    }
    if (payload.size() > payload_bound) {
        return std::unexpected(Error::record_too_large);
    }
    const auto size = crypto::detail::padded_size(payload.size(), record_buckets);
    if (!size) {
        return std::unexpected(Error::record_too_large);
    }
    SecretBytes padded(*size);
    if (!crypto::detail::pad_into(payload, padded.writable(), record_buckets)) {
        return std::unexpected(Error::library_failure);
    }
    const auto sealed = crypto::detail::aead_encrypt(key, nonce, record_data(address), padded.view());
    if (!sealed) {
        return std::unexpected(Error::library_failure);
    }
    crypto::Bytes record(nonce.begin(), nonce.end());
    record.insert(record.end(), sealed->begin(), sealed->end());
    return record;
}

Result<crypto::Bytes> seal_address(const Keys& keys, std::uint64_t slot, const Located& located, const Nonce& nonce)
{
    const auto& key = KeyAccess::address(keys);
    if (key.size() != key_size || slot == 0 || slot > slot_bound || !valid_address(located.address)) {
        return std::unexpected(Error::invalid_parameters);
    }
    wire::VaultAddress address;
    address.type = located.address.type;
    address.id_length = static_cast<std::uint8_t>(located.address.id.size());
    std::ranges::copy(located.address.id, address.id.begin());
    address.counter = located.address.counter;
    address.nonce = located.nonce;
    auto plain = wire::encode(address);
    const auto encoded = SecretBytes::copy_of(plain);
    crypto::detail::wipe(plain);
    crypto::detail::wipe(address.id);
    crypto::detail::wipe(address.nonce);
    const auto sealed = crypto::detail::aead_encrypt(key, nonce, address_data(slot), encoded.view());
    if (!sealed) {
        return std::unexpected(Error::library_failure);
    }
    crypto::Bytes box(nonce.begin(), nonce.end());
    box.insert(box.end(), sealed->begin(), sealed->end());
    return box;
}

Result<crypto::Bytes> seal_manifest(const OpenedHeader& opened, const std::vector<wire::ManifestEntry>& types, const Nonce& nonce)
{
    const auto& key = KeyAccess::manifest(opened.keys());
    if (key.size() != key_size) {
        return std::unexpected(Error::invalid_parameters);
    }
    const auto padded = padded_manifest(wire::Manifest{.epoch = opened.header().epoch, .types = types});
    if (!padded) {
        return std::unexpected(padded.error());
    }
    const auto sealed = crypto::detail::aead_encrypt(key, nonce, crypto::label("vault/manifest"), padded->view());
    if (!sealed) {
        return std::unexpected(Error::library_failure);
    }
    crypto::Bytes box(nonce.begin(), nonce.end());
    box.insert(box.end(), sealed->begin(), sealed->end());
    return box;
}

}

}
