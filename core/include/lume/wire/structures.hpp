// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/wire/codec.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lume::wire {

enum class PrekeyKind : std::uint8_t {
    signed_prekey = 1,
    kem_last_resort = 2,
    kem_one_time = 3,
    seal_key = 4,
    one_time_prekey = 5,
};

enum class HardwareMode : std::uint8_t {
    keystore = 1,
    tpm = 2,
    software = 3,
};

inline constexpr std::size_t x25519_key_size = 32;
inline constexpr std::size_t ed25519_key_size = 32;
inline constexpr std::size_t signature_size = 64;
inline constexpr std::size_t kem_public_key_size = 1184;
inline constexpr std::size_t kem_ciphertext_size = 1088;
inline constexpr std::size_t nonce_size = 24;
inline constexpr std::size_t encrypted_header_size = 80;
inline constexpr std::size_t account_id_size = 16;
inline constexpr std::size_t content_id_size = 16;
inline constexpr std::size_t token_size = 32;
inline constexpr std::size_t group_id_size = 16;
inline constexpr std::size_t username_bound = 32;
inline constexpr std::size_t content_body_bound = 67000;
inline constexpr std::size_t directory_keys_bound = 8;
inline constexpr std::size_t revoked_keys_bound = 16;
inline constexpr std::size_t ratchet_body_bound = 69000;
inline constexpr std::size_t seal_box_bound = 69648;
inline constexpr std::uint8_t seal_version = 1;
inline constexpr std::uint8_t vault_version = 1;
inline constexpr std::size_t vault_salt_size = 16;
inline constexpr std::size_t tpm_point_size = 65;
inline constexpr std::uint8_t tpm_point_uncompressed = 0x04;
inline constexpr std::size_t wrapped_data_key_size = nonce_size + 32 + 16;
inline constexpr std::size_t vault_check_size = 32;
inline constexpr std::size_t manifest_root_size = 32;
inline constexpr std::size_t manifest_types_bound = 32;

struct PrekeyX {
    PrekeyKind kind = PrekeyKind::signed_prekey;
    std::uint32_t id = 0;
    std::uint64_t created_at = 0;
    crypto::ByteArray<x25519_key_size> key{};
    std::optional<crypto::ByteArray<signature_size>> signature = crypto::ByteArray<signature_size>{};

    friend bool operator==(const PrekeyX&, const PrekeyX&) = default;
};

struct PrekeyKem {
    PrekeyKind kind = PrekeyKind::kem_last_resort;
    std::uint32_t id = 0;
    std::uint64_t created_at = 0;
    crypto::ByteArray<kem_public_key_size> key{};
    crypto::ByteArray<signature_size> signature{};

    friend bool operator==(const PrekeyKem&, const PrekeyKem&) = default;
};

struct UsernameCertificate {
    std::uint32_t key_id = 0;
    std::string username;
    crypto::ByteArray<account_id_size> account_id{};
    crypto::ByteArray<ed25519_key_size> ik_sig{};
    crypto::ByteArray<x25519_key_size> ik_dh{};
    std::uint32_t generation = 0;
    std::uint64_t issued_at = 0;
    std::uint64_t expires_at = 0;
    crypto::ByteArray<signature_size> signature{};

    friend bool operator==(const UsernameCertificate&, const UsernameCertificate&) = default;
};

struct DirectoryKey {
    std::uint32_t key_id = 0;
    crypto::ByteArray<ed25519_key_size> public_key{};
    std::uint64_t not_before = 0;
    std::uint64_t not_after = 0;

    friend bool operator==(const DirectoryKey&, const DirectoryKey&) = default;
};

struct RevokedKey {
    std::uint32_t key_id = 0;
    std::uint64_t since = 0;

    friend bool operator==(const RevokedKey&, const RevokedKey&) = default;
};

struct DirectoryKeys {
    std::uint64_t sequence = 0;
    std::uint64_t issued_at = 0;
    std::uint64_t expires_at = 0;
    std::vector<DirectoryKey> keys;
    std::vector<RevokedKey> revoked;
    crypto::ByteArray<signature_size> signature{};

    friend bool operator==(const DirectoryKeys&, const DirectoryKeys&) = default;
};

struct InitialHeader {
    crypto::ByteArray<ed25519_key_size> ik_sig{};
    crypto::ByteArray<x25519_key_size> ik_dh{};
    crypto::ByteArray<signature_size> bind{};
    crypto::ByteArray<x25519_key_size> ephemeral_key{};
    crypto::ByteArray<kem_ciphertext_size> kem_ciphertext{};
    std::uint32_t spk_id = 0;
    PrekeyKind pq_kind = PrekeyKind::kem_last_resort;
    std::uint32_t pq_id = 0;
    std::optional<std::uint32_t> opk_id;

    friend bool operator==(const InitialHeader&, const InitialHeader&) = default;
};

struct Introduction {
    crypto::ByteArray<account_id_size> account_id{};
    std::uint32_t generation = 0;
    crypto::ByteArray<token_size> token{};
    PrekeyX seal_key{.kind = PrekeyKind::seal_key};
    std::optional<UsernameCertificate> certificate;

    friend bool operator==(const Introduction&, const Introduction&) = default;
};

struct Card {
    UsernameCertificate certificate;
    crypto::ByteArray<signature_size> bind{};
    std::uint32_t generation = 0;
    PrekeyX spk;
    PrekeyKem pqspk;
    PrekeyX ssk{.kind = PrekeyKind::seal_key};
    crypto::ByteArray<token_size> token{};
    crypto::ByteArray<group_id_size> group_id{};
    std::uint64_t expires_at = 0;
    crypto::ByteArray<signature_size> signature{};

    friend bool operator==(const Card&, const Card&) = default;
};

struct Content {
    crypto::ByteArray<content_id_size> id{};
    std::uint8_t kind = 0;
    std::optional<Introduction> introduction;
    crypto::Bytes body;

    friend bool operator==(const Content&, const Content&) = default;
};

struct RatchetHeader {
    crypto::ByteArray<x25519_key_size> ratchet_key{};
    std::uint32_t previous_chain_length = 0;
    std::uint32_t message_number = 0;

    friend bool operator==(const RatchetHeader&, const RatchetHeader&) = default;
};

struct RatchetMessage {
    crypto::ByteArray<encrypted_header_size> encrypted_header{};
    crypto::Bytes body;

    friend bool operator==(const RatchetMessage&, const RatchetMessage&) = default;
};

struct Inner {
    crypto::ByteArray<ed25519_key_size> sender{};
    std::optional<InitialHeader> initial;
    RatchetMessage message;

    friend bool operator==(const Inner&, const Inner&) = default;
};

struct Seal {
    std::uint32_t ssk_id = 0;
    crypto::ByteArray<x25519_key_size> ephemeral_key{};
    crypto::ByteArray<nonce_size> nonce{};
    crypto::Bytes box;

    friend bool operator==(const Seal&, const Seal&) = default;
};

struct VaultHeader {
    crypto::ByteArray<vault_salt_size> salt{};
    std::uint32_t ops = 0;
    std::uint32_t mem = 0;
    HardwareMode hw_mode = HardwareMode::software;
    std::optional<crypto::ByteArray<tpm_point_size>> tpm_point;
    crypto::ByteArray<wrapped_data_key_size> wrapped_data_key{};
    std::uint64_t epoch = 0;
    crypto::ByteArray<vault_check_size> check{};

    friend bool operator==(const VaultHeader&, const VaultHeader&) = default;
};

struct ManifestEntry {
    std::uint8_t type = 0;
    std::uint32_t count = 0;
    crypto::ByteArray<manifest_root_size> root{};

    friend bool operator==(const ManifestEntry&, const ManifestEntry&) = default;
};

struct Manifest {
    std::uint64_t epoch = 0;
    std::vector<ManifestEntry> types;

    friend bool operator==(const Manifest&, const Manifest&) = default;
};

void write(Writer& writer, const PrekeyX& value);
void write(Writer& writer, const PrekeyKem& value);
void write(Writer& writer, const UsernameCertificate& value);
void write(Writer& writer, const DirectoryKeys& value);
void write(Writer& writer, const InitialHeader& value);
void write(Writer& writer, const Introduction& value);
void write(Writer& writer, const Content& value);
void write(Writer& writer, const Card& value);
void write(Writer& writer, const RatchetHeader& value);
void write(Writer& writer, const RatchetMessage& value);
void write(Writer& writer, const Inner& value);
void write(Writer& writer, const Seal& value);
void write(Writer& writer, const VaultHeader& value);
void write(Writer& writer, const Manifest& value);

[[nodiscard]] Result<PrekeyX> read_prekey_x(Reader& reader);
[[nodiscard]] Result<PrekeyKem> read_prekey_kem(Reader& reader);
[[nodiscard]] Result<UsernameCertificate> read_username_certificate(Reader& reader);
[[nodiscard]] Result<DirectoryKeys> read_directory_keys(Reader& reader);
[[nodiscard]] Result<InitialHeader> read_initial_header(Reader& reader);
[[nodiscard]] Result<Introduction> read_introduction(Reader& reader);
[[nodiscard]] Result<Content> read_content(Reader& reader);
[[nodiscard]] Result<Card> read_card(Reader& reader);
[[nodiscard]] Result<RatchetHeader> read_ratchet_header(Reader& reader);
[[nodiscard]] Result<RatchetMessage> read_ratchet_message(Reader& reader);
[[nodiscard]] Result<Inner> read_inner(Reader& reader);
[[nodiscard]] Result<Seal> read_seal(Reader& reader);
[[nodiscard]] Result<VaultHeader> read_vault_header(Reader& reader);
[[nodiscard]] Result<Manifest> read_manifest(Reader& reader);

[[nodiscard]] crypto::Bytes encode_unsigned(const UsernameCertificate& value);
[[nodiscard]] crypto::Bytes encode_unsigned(const DirectoryKeys& value);
[[nodiscard]] crypto::Bytes encode_unsigned(const VaultHeader& value);

[[nodiscard]] bool is_canonical(const Manifest& value);

template <typename T>
[[nodiscard]] crypto::Bytes encode(const T& value)
{
    Writer writer;
    write(writer, value);
    return writer.take();
}

template <typename T>
[[nodiscard]] Result<T> decode(crypto::ByteView input, Result<T> (*read)(Reader&))
{
    Reader reader(input);
    return reader.read_all(read);
}

}
