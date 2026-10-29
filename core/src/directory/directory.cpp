// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/directory/directory.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/handshake/prekey.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace lume::directory {
namespace {

constexpr std::string_view list_label = "directory-keys";
constexpr std::string_view certificate_label = "certificate";
constexpr std::size_t shortest_username = 3;

static_assert(certificate_lifetime + handshake::allowed_clock_skew <= certificate_horizon);

bool in_future(std::uint64_t moment, std::uint64_t now) noexcept
{
    return moment > now && moment - now > handshake::allowed_clock_skew;
}

template <typename T>
bool sorted_without_duplicates(std::vector<T>& values)
{
    std::ranges::sort(values);
    return std::ranges::adjacent_find(values) == values.end();
}

bool well_formed(const wire::DirectoryKeys& list)
{
    if (list.keys.size() > wire::directory_keys_bound || list.revoked.size() > wire::revoked_keys_bound) {
        return false;
    }
    if (!std::ranges::all_of(list.keys, [](const auto& key) { return key.not_before < key.not_after; })) {
        return false;
    }
    std::vector<std::uint32_t> listed;
    std::vector<crypto::ByteArray<wire::ed25519_key_size>> public_keys;
    listed.reserve(list.keys.size());
    public_keys.reserve(list.keys.size());
    for (const auto& key : list.keys) {
        listed.push_back(key.key_id);
        public_keys.push_back(key.public_key);
    }
    std::vector<std::uint32_t> revoked;
    revoked.reserve(list.revoked.size());
    for (const auto& entry : list.revoked) {
        revoked.push_back(entry.key_id);
    }
    if (!sorted_without_duplicates(listed) || !sorted_without_duplicates(public_keys)
        || !sorted_without_duplicates(revoked)) {
        return false;
    }
    return std::ranges::none_of(revoked, [&listed](std::uint32_t id) { return std::ranges::binary_search(listed, id); });
}

bool reuses_a_key_id(const wire::DirectoryKeys& candidate, const wire::DirectoryKeys& held)
{
    return std::ranges::any_of(candidate.keys, [&held](const wire::DirectoryKey& key) {
        const auto previous = std::ranges::find(held.keys, key.key_id, &wire::DirectoryKey::key_id);
        if (previous != held.keys.end() && previous->public_key != key.public_key) {
            return true;
        }
        return std::ranges::find(held.revoked, key.key_id, &wire::RevokedKey::key_id) != held.revoked.end();
    });
}

}

crypto::Bytes list_message(const wire::DirectoryKeys& list)
{
    return crypto::Encoder{}.label(list_label).raw(wire::encode_unsigned(list)).take();
}

crypto::Bytes certificate_message(const wire::UsernameCertificate& certificate)
{
    return crypto::Encoder{}.label(certificate_label).raw(wire::encode_unsigned(certificate)).take();
}

bool is_valid_username(std::string_view username) noexcept
{
    if (username.size() < shortest_username || username.size() > wire::username_bound) {
        return false;
    }
    return std::ranges::all_of(username, [](char letter) {
        return (letter >= 'a' && letter <= 'z') || (letter >= '0' && letter <= '9') || letter == '_';
    });
}

Directory::Directory(const crypto::ByteArray<wire::ed25519_key_size>& root_key) noexcept
    : root_key_(root_key)
{
}

Result<void> Directory::verify(const wire::DirectoryKeys& list) const
{
    if (!well_formed(list)) {
        return std::unexpected(Error::malformed);
    }
    if (!crypto::ed25519_verify(root_key_, list_message(list), list.signature)) {
        return std::unexpected(Error::invalid_signature);
    }
    if (list.expires_at <= list.issued_at || list.expires_at - list.issued_at > list_lifetime) {
        return std::unexpected(Error::bad_lifetime);
    }
    return {};
}

Result<void> Directory::follows(const wire::DirectoryKeys& list) const
{
    if (!list_) {
        return {};
    }
    if (list.sequence < list_->sequence) {
        return std::unexpected(Error::rolled_back);
    }
    if (list.sequence == list_->sequence) {
        if (wire::encode_unsigned(list) != wire::encode_unsigned(*list_)) {
            return std::unexpected(Error::conflicting_list);
        }
        return {};
    }
    if (reuses_a_key_id(list, *list_)) {
        return std::unexpected(Error::conflicting_list);
    }
    return {};
}

Result<void> Directory::restore(wire::DirectoryKeys stored)
{
    if (auto checked = verify(stored); !checked) {
        return checked;
    }
    if (auto checked = follows(stored); !checked) {
        return checked;
    }
    list_ = std::move(stored);
    return {};
}

Result<void> Directory::accept(wire::DirectoryKeys fetched, std::uint64_t now)
{
    if (auto checked = verify(fetched); !checked) {
        return checked;
    }
    if (in_future(fetched.issued_at, now)) {
        return std::unexpected(Error::not_yet_valid);
    }
    if (now >= fetched.expires_at) {
        return std::unexpected(Error::expired);
    }
    if (auto checked = follows(fetched); !checked) {
        return checked;
    }
    list_ = std::move(fetched);
    return {};
}

const std::optional<wire::DirectoryKeys>& Directory::list() const noexcept
{
    return list_;
}

bool Directory::current_at(std::uint64_t now) const noexcept
{
    return list_ && !in_future(list_->issued_at, now) && now < list_->expires_at;
}

Result<void> Directory::check_certificate(
    const wire::UsernameCertificate& certificate, std::uint64_t now, const identity::PublicIdentity& peer,
    const crypto::ByteArray<wire::account_id_size>& account_id) const
{
    if (!list_ || !current_at(now)) {
        return std::unexpected(Error::no_current_list);
    }
    if (!is_valid_username(certificate.username)) {
        return std::unexpected(Error::invalid_username);
    }
    const auto& keys = list_->keys;
    const auto key = std::ranges::find(keys, certificate.key_id, &wire::DirectoryKey::key_id);
    if (key == keys.end()) {
        return std::unexpected(Error::unknown_key);
    }
    if (in_future(key->not_before, now) || now >= key->not_after) {
        return std::unexpected(Error::key_outside_window);
    }
    if (!crypto::ed25519_verify(key->public_key, certificate_message(certificate), certificate.signature)) {
        return std::unexpected(Error::invalid_signature);
    }
    if (in_future(certificate.issued_at, now)) {
        return std::unexpected(Error::not_yet_valid);
    }
    if (now >= certificate.expires_at) {
        return std::unexpected(Error::expired);
    }
    if (certificate.expires_at <= certificate.issued_at
        || certificate.expires_at - certificate.issued_at > certificate_lifetime) {
        return std::unexpected(Error::bad_lifetime);
    }
    if (certificate.ik_sig != peer.signing_key || certificate.ik_dh != peer.exchange_key) {
        return std::unexpected(Error::wrong_identity);
    }
    if (certificate.account_id != account_id) {
        return std::unexpected(Error::wrong_account);
    }
    return {};
}

bool Directory::distrusts(std::uint32_t key_id, std::uint64_t accepted_at) const noexcept
{
    if (!list_) {
        return false;
    }
    const auto& revoked = list_->revoked;
    const auto entry = std::ranges::find(revoked, key_id, &wire::RevokedKey::key_id);
    if (entry == revoked.end()) {
        return false;
    }
    return accepted_at >= entry->since || entry->since - accepted_at <= revocation_margin;
}

}
