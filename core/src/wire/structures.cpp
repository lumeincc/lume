// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/wire/structures.hpp"

#include <algorithm>
#include <cstddef>
#include <expected>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <utility>

namespace lume::wire {
namespace {

constexpr std::size_t directory_key_size = 4 + ed25519_key_size + 8 + 8;
constexpr std::size_t revoked_key_size = 4 + 8;
constexpr std::size_t manifest_entry_size = 1 + 4 + manifest_root_size;

constexpr std::initializer_list<PrekeyKind> x25519_kinds{
    PrekeyKind::signed_prekey, PrekeyKind::seal_key, PrekeyKind::one_time_prekey};
constexpr std::initializer_list<PrekeyKind> kem_kinds{PrekeyKind::kem_last_resort, PrekeyKind::kem_one_time};
constexpr std::initializer_list<HardwareMode> hardware_modes{
    HardwareMode::keystore, HardwareMode::tpm, HardwareMode::software};

bool valid_tpm_point(const VaultHeader& value) noexcept
{
    if (value.tpm_point.has_value() != (value.hw_mode == HardwareMode::tpm)) {
        return false;
    }
    return !value.tpm_point || value.tpm_point->front() == tpm_point_uncompressed;
}

bool canonical_types(const std::vector<ManifestEntry>& types)
{
    const auto out_of_order = std::ranges::adjacent_find(
        types, [](const ManifestEntry& first, const ManifestEntry& second) { return first.type >= second.type; });
    return out_of_order == types.end()
        && std::ranges::none_of(types, [](const ManifestEntry& entry) { return entry.count == 0; });
}

void require_kind(PrekeyKind kind, std::initializer_list<PrekeyKind> allowed)
{
    if (std::ranges::find(allowed, kind) == allowed.end()) {
        throw std::invalid_argument("a prekey kind its structure does not allow");
    }
}

bool read_kind(Reader& reader, PrekeyKind& target, std::initializer_list<PrekeyKind> allowed)
{
    std::uint8_t value = 0;
    if (!reader.into(value)) {
        return false;
    }
    const auto* const match = std::ranges::find(allowed, static_cast<PrekeyKind>(value));
    if (match == allowed.end()) {
        return reader.fail(Error::invalid_value);
    }
    target = *match;
    return true;
}

bool read_optional_u32(Reader& reader, std::optional<std::uint32_t>& target)
{
    bool present = false;
    if (!reader.into(present)) {
        return false;
    }
    if (!present) {
        target.reset();
        return true;
    }
    std::uint32_t value = 0;
    if (!reader.into(value)) {
        return false;
    }
    target = value;
    return true;
}

bool read_text(Reader& reader, std::string& target, std::size_t bound)
{
    auto text = reader.text(bound);
    if (!text) {
        return reader.fail(text.error());
    }
    target = std::move(*text);
    return true;
}

template <typename T>
bool read_nested(Reader& reader, T& target, Result<T> (*read)(Reader&))
{
    auto value = read(reader);
    if (!value) {
        return reader.fail(value.error());
    }
    target = std::move(*value);
    return true;
}

template <typename T>
bool read_optional(Reader& reader, std::optional<T>& target, Result<T> (*read)(Reader&))
{
    bool present = false;
    if (!reader.into(present)) {
        return false;
    }
    if (!present) {
        target.reset();
        return true;
    }
    T value;
    if (!read_nested(reader, value, read)) {
        return false;
    }
    target = std::move(value);
    return true;
}

void write_unsigned(Writer& writer, const UsernameCertificate& value)
{
    writer.u32(value.key_id)
        .text(value.username, username_bound)
        .fixed(value.account_id)
        .fixed(value.ik_sig)
        .fixed(value.ik_dh)
        .u32(value.generation)
        .u64(value.issued_at)
        .u64(value.expires_at);
}

void write_unsigned(Writer& writer, const DirectoryKeys& value)
{
    writer.u64(value.sequence).u64(value.issued_at).u64(value.expires_at);
    writer.count(value.keys.size(), directory_keys_bound);
    for (const auto& key : value.keys) {
        writer.u32(key.key_id).fixed(key.public_key).u64(key.not_before).u64(key.not_after);
    }
    writer.count(value.revoked.size(), revoked_keys_bound);
    for (const auto& revoked : value.revoked) {
        writer.u32(revoked.key_id).u64(revoked.since);
    }
}

void write_unsigned(Writer& writer, const VaultHeader& value)
{
    if (std::ranges::find(hardware_modes, value.hw_mode) == hardware_modes.end() || !valid_tpm_point(value)) {
        throw std::invalid_argument("a vault header whose hardware mode and TPM point disagree");
    }
    writer.u8(vault_version)
        .fixed(value.salt)
        .u32(value.ops)
        .u32(value.mem)
        .u8(static_cast<std::uint8_t>(value.hw_mode))
        .present(value.tpm_point.has_value());
    if (value.tpm_point) {
        writer.fixed(*value.tpm_point);
    }
    writer.fixed(value.wrapped_data_key).u64(value.epoch);
}

template <typename T>
void write_optional(Writer& writer, const std::optional<T>& value)
{
    writer.present(value.has_value());
    if (value) {
        write(writer, *value);
    }
}

}

void write(Writer& writer, const PrekeyX& value)
{
    require_kind(value.kind, x25519_kinds);
    if (value.signature.has_value() != (value.kind != PrekeyKind::one_time_prekey)) {
        throw std::invalid_argument("a prekey is signed exactly when it is not a one-time prekey");
    }
    writer.u8(static_cast<std::uint8_t>(value.kind)).u32(value.id).u64(value.created_at).fixed(value.key);
    writer.present(value.signature.has_value());
    if (value.signature) {
        writer.fixed(*value.signature);
    }
}

void write(Writer& writer, const PrekeyKem& value)
{
    require_kind(value.kind, kem_kinds);
    writer.u8(static_cast<std::uint8_t>(value.kind))
        .u32(value.id)
        .u64(value.created_at)
        .fixed(value.key)
        .fixed(value.signature);
}

void write(Writer& writer, const UsernameCertificate& value)
{
    write_unsigned(writer, value);
    writer.fixed(value.signature);
}

void write(Writer& writer, const DirectoryKeys& value)
{
    write_unsigned(writer, value);
    writer.fixed(value.signature);
}

crypto::Bytes encode_unsigned(const UsernameCertificate& value)
{
    Writer writer;
    write_unsigned(writer, value);
    return writer.take();
}

crypto::Bytes encode_unsigned(const DirectoryKeys& value)
{
    Writer writer;
    write_unsigned(writer, value);
    return writer.take();
}

void write(Writer& writer, const VaultHeader& value)
{
    write_unsigned(writer, value);
    writer.fixed(value.check);
}

crypto::Bytes encode_unsigned(const VaultHeader& value)
{
    Writer writer;
    write_unsigned(writer, value);
    return writer.take();
}

bool is_canonical(const Manifest& value)
{
    return value.types.size() <= manifest_types_bound && canonical_types(value.types);
}

void write(Writer& writer, const Manifest& value)
{
    if (!canonical_types(value.types)) {
        throw std::invalid_argument("manifest types must be strictly ascending, each with a live record");
    }
    writer.u64(value.epoch).count(value.types.size(), manifest_types_bound);
    for (const auto& entry : value.types) {
        writer.u8(entry.type).u32(entry.count).fixed(entry.root);
    }
}

void write(Writer& writer, const InitialHeader& value)
{
    require_kind(value.pq_kind, kem_kinds);
    writer.fixed(value.ik_sig)
        .fixed(value.ik_dh)
        .fixed(value.bind)
        .fixed(value.ephemeral_key)
        .fixed(value.kem_ciphertext)
        .u32(value.spk_id)
        .u8(static_cast<std::uint8_t>(value.pq_kind))
        .u32(value.pq_id)
        .present(value.opk_id.has_value());
    if (value.opk_id) {
        writer.u32(*value.opk_id);
    }
}

void write(Writer& writer, const Introduction& value)
{
    require_kind(value.seal_key.kind, {PrekeyKind::seal_key});
    writer.fixed(value.account_id).u32(value.generation).fixed(value.token);
    write(writer, value.seal_key);
    write_optional(writer, value.certificate);
}

void write(Writer& writer, const Content& value)
{
    writer.fixed(value.id).u8(value.kind);
    write_optional(writer, value.introduction);
    writer.bytes(value.body, content_body_bound);
}

void write(Writer& writer, const Card& value)
{
    require_kind(value.spk.kind, {PrekeyKind::signed_prekey});
    require_kind(value.pqspk.kind, {PrekeyKind::kem_last_resort});
    require_kind(value.ssk.kind, {PrekeyKind::seal_key});
    write(writer, value.certificate);
    writer.fixed(value.bind).u32(value.generation);
    write(writer, value.spk);
    write(writer, value.pqspk);
    write(writer, value.ssk);
    writer.fixed(value.token).fixed(value.group_id).u64(value.expires_at).fixed(value.signature);
}

void write(Writer& writer, const RatchetHeader& value)
{
    writer.fixed(value.ratchet_key).u32(value.previous_chain_length).u32(value.message_number);
}

void write(Writer& writer, const RatchetMessage& value)
{
    writer.fixed(value.encrypted_header).bytes(value.body, ratchet_body_bound);
}

void write(Writer& writer, const Inner& value)
{
    writer.fixed(value.sender);
    write_optional(writer, value.initial);
    write(writer, value.message);
}

void write(Writer& writer, const Seal& value)
{
    writer.u8(seal_version)
        .u32(value.ssk_id)
        .fixed(value.ephemeral_key)
        .fixed(value.nonce)
        .bytes(value.box, seal_box_bound);
}

Result<PrekeyX> read_prekey_x(Reader& reader)
{
    PrekeyX value;
    bool signed_key = false;
    if (!read_kind(reader, value.kind, x25519_kinds)
        || !reader.into(value.id) || !reader.into(value.created_at) || !reader.into(value.key)
        || !reader.into(signed_key)) {
        return std::unexpected(reader.error());
    }
    if (signed_key != (value.kind != PrekeyKind::one_time_prekey)) {
        return std::unexpected(Error::invalid_value);
    }
    if (!signed_key) {
        value.signature.reset();
        return value;
    }
    crypto::ByteArray<signature_size> signature{};
    if (!reader.into(signature)) {
        return std::unexpected(reader.error());
    }
    value.signature = signature;
    return value;
}

Result<PrekeyKem> read_prekey_kem(Reader& reader)
{
    PrekeyKem value;
    if (!read_kind(reader, value.kind, kem_kinds)
        || !reader.into(value.id) || !reader.into(value.created_at) || !reader.into(value.key)
        || !reader.into(value.signature)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<UsernameCertificate> read_username_certificate(Reader& reader)
{
    UsernameCertificate value;
    if (!reader.into(value.key_id) || !read_text(reader, value.username, username_bound)
        || !reader.into(value.account_id) || !reader.into(value.ik_sig) || !reader.into(value.ik_dh)
        || !reader.into(value.generation) || !reader.into(value.issued_at) || !reader.into(value.expires_at)
        || !reader.into(value.signature)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<DirectoryKeys> read_directory_keys(Reader& reader)
{
    DirectoryKeys value;
    if (!reader.into(value.sequence) || !reader.into(value.issued_at) || !reader.into(value.expires_at)) {
        return std::unexpected(reader.error());
    }
    const auto keys = reader.count(directory_keys_bound);
    if (!keys) {
        return std::unexpected(keys.error());
    }
    if (reader.remaining() / directory_key_size < *keys) {
        return std::unexpected(Error::truncated);
    }
    value.keys.resize(*keys);
    for (auto& key : value.keys) {
        if (!reader.into(key.key_id) || !reader.into(key.public_key) || !reader.into(key.not_before)
            || !reader.into(key.not_after)) {
            return std::unexpected(reader.error());
        }
    }
    const auto revoked = reader.count(revoked_keys_bound);
    if (!revoked) {
        return std::unexpected(revoked.error());
    }
    if (reader.remaining() / revoked_key_size < *revoked) {
        return std::unexpected(Error::truncated);
    }
    value.revoked.resize(*revoked);
    for (auto& entry : value.revoked) {
        if (!reader.into(entry.key_id) || !reader.into(entry.since)) {
            return std::unexpected(reader.error());
        }
    }
    if (!reader.into(value.signature)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<InitialHeader> read_initial_header(Reader& reader)
{
    InitialHeader value;
    if (!reader.into(value.ik_sig) || !reader.into(value.ik_dh) || !reader.into(value.bind)
        || !reader.into(value.ephemeral_key) || !reader.into(value.kem_ciphertext) || !reader.into(value.spk_id)
        || !read_kind(reader, value.pq_kind, kem_kinds)
        || !reader.into(value.pq_id) || !read_optional_u32(reader, value.opk_id)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<Introduction> read_introduction(Reader& reader)
{
    Introduction value;
    if (!reader.into(value.account_id) || !reader.into(value.generation) || !reader.into(value.token)
        || !read_nested(reader, value.seal_key, read_prekey_x)) {
        return std::unexpected(reader.error());
    }
    if (value.seal_key.kind != PrekeyKind::seal_key) {
        return std::unexpected(Error::invalid_value);
    }
    if (!read_optional(reader, value.certificate, read_username_certificate)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<Content> read_content(Reader& reader)
{
    Content value;
    if (!reader.into(value.id) || !reader.into(value.kind)
        || !read_optional(reader, value.introduction, read_introduction)
        || !reader.into(value.body, content_body_bound)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<Card> read_card(Reader& reader)
{
    Card value;
    if (!read_nested(reader, value.certificate, read_username_certificate) || !reader.into(value.bind)
        || !reader.into(value.generation) || !read_nested(reader, value.spk, read_prekey_x)
        || !read_nested(reader, value.pqspk, read_prekey_kem) || !read_nested(reader, value.ssk, read_prekey_x)) {
        return std::unexpected(reader.error());
    }
    if (value.spk.kind != PrekeyKind::signed_prekey || value.pqspk.kind != PrekeyKind::kem_last_resort
        || value.ssk.kind != PrekeyKind::seal_key) {
        return std::unexpected(Error::invalid_value);
    }
    if (!reader.into(value.token) || !reader.into(value.group_id) || !reader.into(value.expires_at)
        || !reader.into(value.signature)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<RatchetHeader> read_ratchet_header(Reader& reader)
{
    RatchetHeader value;
    if (!reader.into(value.ratchet_key) || !reader.into(value.previous_chain_length)
        || !reader.into(value.message_number)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<RatchetMessage> read_ratchet_message(Reader& reader)
{
    RatchetMessage value;
    if (!reader.into(value.encrypted_header) || !reader.into(value.body, ratchet_body_bound)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<Inner> read_inner(Reader& reader)
{
    Inner value;
    if (!reader.into(value.sender) || !read_optional(reader, value.initial, read_initial_header)
        || !read_nested(reader, value.message, read_ratchet_message)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<Seal> read_seal(Reader& reader)
{
    Seal value;
    std::uint8_t version = 0;
    if (!reader.into(version)) {
        return std::unexpected(reader.error());
    }
    if (version != seal_version) {
        return std::unexpected(Error::unsupported_version);
    }
    if (!reader.into(value.ssk_id) || !reader.into(value.ephemeral_key) || !reader.into(value.nonce)
        || !reader.into(value.box, seal_box_bound)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<VaultHeader> read_vault_header(Reader& reader)
{
    VaultHeader value;
    std::uint8_t version = 0;
    if (!reader.into(version)) {
        return std::unexpected(reader.error());
    }
    if (version != vault_version) {
        return std::unexpected(Error::unsupported_version);
    }
    std::uint8_t mode = 0;
    bool has_point = false;
    if (!reader.into(value.salt) || !reader.into(value.ops) || !reader.into(value.mem) || !reader.into(mode)
        || !reader.into(has_point)) {
        return std::unexpected(reader.error());
    }
    const auto* const match = std::ranges::find(hardware_modes, static_cast<HardwareMode>(mode));
    if (match == hardware_modes.end()) {
        return std::unexpected(Error::invalid_value);
    }
    value.hw_mode = *match;
    if (has_point) {
        crypto::ByteArray<tpm_point_size> point{};
        if (!reader.into(point)) {
            return std::unexpected(reader.error());
        }
        value.tpm_point = point;
    }
    if (!valid_tpm_point(value)) {
        return std::unexpected(Error::invalid_value);
    }
    if (!reader.into(value.wrapped_data_key) || !reader.into(value.epoch) || !reader.into(value.check)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<Manifest> read_manifest(Reader& reader)
{
    Manifest value;
    if (!reader.into(value.epoch)) {
        return std::unexpected(reader.error());
    }
    const auto types = reader.count(manifest_types_bound);
    if (!types) {
        return std::unexpected(types.error());
    }
    if (reader.remaining() / manifest_entry_size < *types) {
        return std::unexpected(Error::truncated);
    }
    value.types.resize(*types);
    for (auto& entry : value.types) {
        if (!reader.into(entry.type) || !reader.into(entry.count) || !reader.into(entry.root)) {
            return std::unexpected(reader.error());
        }
    }
    if (!canonical_types(value.types)) {
        return std::unexpected(Error::non_canonical);
    }
    return value;
}

}
