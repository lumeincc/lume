// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/wire/structures.hpp"

#include <algorithm>
#include <expected>
#include <initializer_list>
#include <utility>

namespace lume::wire {
namespace {

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

}

void write(Writer& writer, const PrekeyX& value)
{
    writer.u8(static_cast<std::uint8_t>(value.kind)).u32(value.id).u64(value.created_at).fixed(value.key);
    writer.present(value.signature.has_value());
    if (value.signature) {
        writer.fixed(*value.signature);
    }
}

void write(Writer& writer, const PrekeyKem& value)
{
    writer.u8(static_cast<std::uint8_t>(value.kind))
        .u32(value.id)
        .u64(value.created_at)
        .fixed(value.key)
        .fixed(value.signature);
}

void write(Writer& writer, const InitialHeader& value)
{
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
    writer.fixed(value.sender).present(value.initial.has_value());
    if (value.initial) {
        write(writer, *value.initial);
    }
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
    if (!read_kind(reader, value.kind, {PrekeyKind::signed_prekey, PrekeyKind::seal_key, PrekeyKind::one_time_prekey})
        || !reader.into(value.id) || !reader.into(value.created_at) || !reader.into(value.key)
        || !reader.into(signed_key)) {
        return std::unexpected(reader.error());
    }
    if (signed_key != (value.kind != PrekeyKind::one_time_prekey)) {
        return std::unexpected(Error::invalid_value);
    }
    if (signed_key) {
        crypto::ByteArray<signature_size> signature{};
        if (!reader.into(signature)) {
            return std::unexpected(reader.error());
        }
        value.signature = signature;
    }
    return value;
}

Result<PrekeyKem> read_prekey_kem(Reader& reader)
{
    PrekeyKem value;
    if (!read_kind(reader, value.kind, {PrekeyKind::kem_last_resort, PrekeyKind::kem_one_time})
        || !reader.into(value.id) || !reader.into(value.created_at) || !reader.into(value.key)
        || !reader.into(value.signature)) {
        return std::unexpected(reader.error());
    }
    return value;
}

Result<InitialHeader> read_initial_header(Reader& reader)
{
    InitialHeader value;
    if (!reader.into(value.ik_sig) || !reader.into(value.ik_dh) || !reader.into(value.bind)
        || !reader.into(value.ephemeral_key) || !reader.into(value.kem_ciphertext) || !reader.into(value.spk_id)
        || !read_kind(reader, value.pq_kind, {PrekeyKind::kem_last_resort, PrekeyKind::kem_one_time})
        || !reader.into(value.pq_id) || !read_optional_u32(reader, value.opk_id)) {
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
    bool has_initial = false;
    if (!reader.into(value.sender) || !reader.into(has_initial)) {
        return std::unexpected(reader.error());
    }
    if (has_initial) {
        auto initial = read_initial_header(reader);
        if (!initial) {
            return std::unexpected(initial.error());
        }
        value.initial = *initial;
    }
    auto message = read_ratchet_message(reader);
    if (!message) {
        return std::unexpected(message.error());
    }
    value.message = std::move(*message);
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

}
