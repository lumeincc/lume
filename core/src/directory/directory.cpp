// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/directory/directory.hpp"

#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/handshake/prekey.hpp"

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace lume::directory {
namespace {

constexpr std::string_view list_label = "directory-keys";
constexpr std::string_view certificate_label = "certificate";

bool in_future(std::uint64_t moment, std::uint64_t now) noexcept
{
    return moment > now && moment - now > handshake::allowed_clock_skew;
}

bool has_duplicates(std::vector<std::uint32_t>& ids)
{
    std::ranges::sort(ids);
    return std::ranges::adjacent_find(ids) != ids.end();
}

bool well_formed(const wire::DirectoryKeys& list)
{
    if (!std::ranges::all_of(list.keys, [](const auto& key) { return key.not_before < key.not_after; })) {
        return false;
    }
    std::vector<std::uint32_t> listed;
    listed.reserve(list.keys.size());
    for (const auto& key : list.keys) {
        listed.push_back(key.key_id);
    }
    std::vector<std::uint32_t> revoked;
    revoked.reserve(list.revoked.size());
    for (const auto& entry : list.revoked) {
        revoked.push_back(entry.key_id);
    }
    if (has_duplicates(listed) || has_duplicates(revoked)) {
        return false;
    }
    return std::ranges::none_of(revoked, [&listed](std::uint32_t id) { return std::ranges::binary_search(listed, id); });
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

TrustedList::TrustedList(wire::DirectoryKeys list) noexcept
    : list_(std::move(list))
{
}

Result<TrustedList> TrustedList::verify(crypto::ByteView root_key, wire::DirectoryKeys list)
{
    if (!crypto::ed25519_verify(root_key, list_message(list), list.signature)) {
        return std::unexpected(Error::invalid_signature);
    }
    if (!well_formed(list)) {
        return std::unexpected(Error::malformed);
    }
    if (list.expires_at <= list.issued_at || list.expires_at - list.issued_at > list_lifetime) {
        return std::unexpected(Error::lifetime_too_long);
    }
    return TrustedList(std::move(list));
}

const wire::DirectoryKeys& TrustedList::keys() const noexcept
{
    return list_;
}

bool TrustedList::current_at(std::uint64_t now) const noexcept
{
    return !in_future(list_.issued_at, now) && now < list_.expires_at;
}

Result<TrustedList> accept_list(
    crypto::ByteView root_key, wire::DirectoryKeys candidate, std::uint64_t now,
    const std::optional<TrustedList>& held)
{
    auto trusted = TrustedList::verify(root_key, std::move(candidate));
    if (!trusted) {
        return trusted;
    }
    const auto& list = trusted->keys();
    if (in_future(list.issued_at, now)) {
        return std::unexpected(Error::not_yet_valid);
    }
    if (now >= list.expires_at) {
        return std::unexpected(Error::expired);
    }
    if (held) {
        const auto& previous = held->keys();
        if (list.sequence < previous.sequence) {
            return std::unexpected(Error::rolled_back);
        }
        if (list.sequence == previous.sequence && list != previous) {
            return std::unexpected(Error::conflicting_list);
        }
    }
    return trusted;
}

Result<void> check_certificate(
    const TrustedList& list, const wire::UsernameCertificate& certificate, std::uint64_t now,
    const identity::PublicIdentity& peer, const crypto::ByteArray<wire::account_id_size>& account_id)
{
    if (!list.current_at(now)) {
        return std::unexpected(Error::list_expired);
    }
    const auto& keys = list.keys().keys;
    const auto key = std::ranges::find(keys, certificate.key_id, &wire::DirectoryKey::key_id);
    if (key == keys.end()) {
        return std::unexpected(Error::unknown_key);
    }
    if (now < key->not_before || now > key->not_after) {
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
        || certificate.expires_at - certificate.issued_at > certificate_lifetime
        || certificate.expires_at - now > certificate_horizon) {
        return std::unexpected(Error::lifetime_too_long);
    }
    if (certificate.ik_sig != peer.signing_key || certificate.ik_dh != peer.exchange_key) {
        return std::unexpected(Error::wrong_identity);
    }
    if (certificate.account_id != account_id) {
        return std::unexpected(Error::wrong_account);
    }
    return {};
}

bool distrusts(const TrustedList& list, std::uint32_t key_id, std::uint64_t accepted_at) noexcept
{
    const auto& revoked = list.keys().revoked;
    const auto entry = std::ranges::find(revoked, key_id, &wire::RevokedKey::key_id);
    if (entry == revoked.end()) {
        return false;
    }
    return accepted_at >= entry->since || entry->since - accepted_at <= revocation_margin;
}

}
