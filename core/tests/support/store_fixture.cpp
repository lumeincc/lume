// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "support/store_fixture.hpp"

#include "lume/crypto/random.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/wire/codec.hpp"
#include "lume/wire/structures.hpp"
#include "support/hex.hpp"
#include "support/memory_vfs.hpp"
#include "vault/vault_internal.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <ios>
#include <iterator>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace lume::test {
namespace {

constexpr std::uint8_t record_kind = 1;
constexpr std::uint8_t address_kind = 2;
constexpr std::uint8_t manifest_kind = 3;
constexpr std::uint8_t header_kind = 4;
constexpr std::uint8_t data_key_fill = 0x33;
constexpr std::uint8_t output_fill = 0x11;
constexpr std::uint8_t point_fill = 0x22;
constexpr std::uint8_t salt_fill = 0x5a;
constexpr vault::RecordType row_type = 1;

const vault::PassphraseKey& passphrase_key()
{
    static const auto key = [] {
        vault::Salt salt{};
        salt.fill(salt_fill);
        return must(vault::derive_passphrase_key("store test passphrase", salt, vault::cost_floor, vault::Platform::desktop));
    }();
    return key;
}

crypto::SecretBytes data_key()
{
    crypto::Bytes key(vault::key_size, data_key_fill);
    return crypto::SecretBytes::copy_of(key);
}

vault::MasterKey master_for(const vault::KeyName& name)
{
    crypto::Bytes output(vault::hardware_secret_size, output_fill);
    return must(vault::derive_master_key(passphrase_key(), must(vault::hardware_key(name, output))));
}

vault::KeyName tpm_name()
{
    vault::TpmPoint point{};
    point.fill(point_fill);
    point.front() = wire::tpm_point_uncompressed;
    return vault::KeyName{.mode = wire::HardwareMode::tpm, .epoch = vault::first_epoch, .point = point};
}

crypto::Bytes read_all(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("a test file could not be read");
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

}

std::string backing_name(Backing backing)
{
    return backing == Backing::os ? "os" : "memory";
}

Place::Place(Backing backing)
    : backing_(backing)
{
    if (backing_ == Backing::memory) {
        memory_vfs::clear();
        path_ = "vault.db";
        return;
    }
    directory_ = std::filesystem::temp_directory_path() / ("lume-store-" + encode_hex(crypto::random_public_bytes<8>()));
    std::filesystem::create_directories(directory_);
    const auto name = (directory_ / "vault.db").u8string();
    std::ranges::transform(name, std::back_inserter(path_), [](char8_t letter) { return static_cast<char>(letter); });
}

Place::~Place()
{
    if (backing_ != Backing::os) {
        return;
    }
    try {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    } catch (...) {
        static_cast<void>(std::fputs("a temporary test directory could not be removed\n", stderr));
    }
}

Backing Place::backing() const noexcept
{
    return backing_;
}

const char* Place::vfs() const
{
    return backing_ == Backing::memory ? memory_vfs::name() : nullptr;
}

std::string Place::path(std::string_view suffix) const
{
    return path_ + std::string(suffix);
}

std::filesystem::path Place::file(std::string_view suffix) const
{
    return directory_ / ("vault.db" + std::string(suffix));
}

std::optional<crypto::Bytes> Place::read(std::string_view suffix) const
{
    if (backing_ == Backing::memory) {
        return memory_vfs::content(path(suffix));
    }
    if (!std::filesystem::exists(file(suffix))) {
        return std::nullopt;
    }
    return read_all(file(suffix));
}

void Place::write(std::string_view suffix, crypto::ByteView bytes) const
{
    if (backing_ == Backing::memory) {
        memory_vfs::put(path(suffix), bytes);
        return;
    }
    std::ofstream output(file(suffix), std::ios::binary | std::ios::trunc);
    std::ranges::copy(bytes, std::ostreambuf_iterator<char>(output));
    if (!output) {
        throw std::runtime_error("a test file could not be written");
    }
}

bool Place::exists(std::string_view suffix) const
{
    if (backing_ == Backing::memory) {
        return memory_vfs::exists(path(suffix));
    }
    return std::filesystem::exists(file(suffix));
}

void Place::remove(std::string_view suffix) const
{
    if (backing_ == Backing::memory) {
        memory_vfs::remove(path(suffix));
        return;
    }
    std::filesystem::remove(file(suffix));
}

Material::Material(vault::MasterKey master, vault::OpenedHeader opened)
    : master_(std::move(master))
    , opened_(std::move(opened))
{
}

const Material& Material::keystore()
{
    static const Material material = [] {
        auto master = master_for(vault::KeyName{.mode = wire::HardwareMode::keystore, .epoch = vault::first_epoch, .point = std::nullopt});
        auto opened = must(vault::detail::first_header(master, data_key(), nonce_from(header_kind, 0)));
        return Material(std::move(master), std::move(opened));
    }();
    return material;
}

const Material& Material::tpm()
{
    static const Material material = [] {
        auto master = master_for(tpm_name());
        auto opened = must(vault::detail::first_header(master, data_key(), nonce_from(header_kind, 0)));
        return Material(std::move(master), std::move(opened));
    }();
    return material;
}

const vault::OpenedHeader& Material::opened() const noexcept
{
    return opened_;
}

crypto::Bytes Material::header(std::uint8_t seed) const
{
    if (seed == 0) {
        return wire::encode(opened_.header());
    }
    return wire::encode(must(vault::detail::first_header(master_, data_key(), nonce_from(header_kind, seed))).header());
}

crypto::Bytes Material::manifest(std::uint8_t seed) const
{
    return must(vault::detail::seal_manifest(opened_, {}, nonce_from(manifest_kind, seed)));
}

SealedRow Material::row(std::uint64_t slot, std::uint8_t seed, crypto::ByteView payload, std::string_view id, std::uint64_t counter) const
{
    const vault::RecordAddress address{.type = row_type, .id = bytes_of(id), .counter = counter};
    const auto record_nonce = nonce_from(record_kind, seed);
    return SealedRow{.slot = slot,
        .address = must(vault::detail::seal_address(
            opened_.keys(), slot, vault::Located{.address = address, .nonce = record_nonce}, nonce_from(address_kind, seed))),
        .record = must(vault::detail::seal_record(opened_.keys(), address, payload, record_nonce))};
}

vault::Nonce nonce_from(std::uint8_t kind, std::uint8_t seed) noexcept
{
    vault::Nonce nonce{};
    nonce.fill(seed);
    nonce.front() = kind;
    return nonce;
}

vault::Nonce leading_nonce(crypto::ByteView box)
{
    vault::Nonce nonce{};
    std::ranges::copy(box.first(nonce.size()), nonce.begin());
    return nonce;
}

vault::RowChange inserted(const SealedRow& row)
{
    return vault::RowChange{.write = vault::RowWrite::insert, .slot = row.slot, .address = row.address, .record = row.record};
}

vault::RowChange replaced(const SealedRow& from, const SealedRow& to)
{
    return vault::RowChange{.write = vault::RowWrite::replace,
        .slot = to.slot,
        .address = to.address,
        .record = to.record,
        .old_address_nonce = leading_nonce(from.address),
        .old_record_nonce = leading_nonce(from.record)};
}

vault::RowChange erased(const SealedRow& row)
{
    return vault::RowChange{.write = vault::RowWrite::erase,
        .slot = row.slot,
        .address = {},
        .record = {},
        .old_address_nonce = leading_nonce(row.address),
        .old_record_nonce = leading_nonce(row.record)};
}

crypto::Bytes patterned(std::size_t size, std::uint8_t seed)
{
    crypto::Bytes bytes(size);
    std::uint8_t next = seed;
    for (auto& byte : bytes) {
        byte = next;
        next = static_cast<std::uint8_t>((next * 5U) + 1U);
    }
    return bytes;
}

crypto::Bytes bytes_of(std::string_view text)
{
    return {text.begin(), text.end()};
}

bool contains(crypto::ByteView haystack, crypto::ByteView needle)
{
    return !needle.empty() && !std::ranges::search(haystack, needle).empty();
}

vault::Store created(const Place& place, const Material& material, std::initializer_list<SealedRow> rows, std::uint8_t manifest_seed)
{
    auto store = must(vault::Store::open_new(place.path(), place.vfs()));
    std::vector<vault::RowChange> changes;
    std::ranges::transform(rows, std::back_inserter(changes), inserted);
    const auto result = store.initialise(material.header(), material.manifest(manifest_seed), changes);
    if (result.outcome != vault::Outcome::committed) {
        throw std::runtime_error("a test vault could not be created");
    }
    must(store.checkpoint());
    return store;
}

void CloseConnection::operator()(sqlite3* database) const noexcept
{
    static_cast<void>(sqlite3_close_v2(database));
}

Side::Side(const Place& place, std::string_view suffix)
{
    sqlite3* raw = nullptr;
    const auto name = place.path(suffix);
    const int code = sqlite3_open_v2(name.c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, place.vfs());
    database_.reset(raw);
    if (code != SQLITE_OK) {
        throw std::runtime_error("a side connection could not open the test file");
    }
    run("PRAGMA locking_mode = EXCLUSIVE");
}

void Side::run(std::string_view sql) const
{
    run(sql, {});
}

void Side::run(std::string_view sql, std::initializer_list<crypto::ByteView> blobs) const
{
    sqlite3_stmt* raw = nullptr;
    const int prepared = sqlite3_prepare_v2(database_.get(), sql.data(), static_cast<int>(sql.size()), &raw, nullptr);
    const std::unique_ptr<sqlite3_stmt, int (*)(sqlite3_stmt*)> statement(raw, sqlite3_finalize);
    if (prepared != SQLITE_OK || statement == nullptr) {
        throw std::runtime_error("a side connection could not prepare: " + std::string(sql));
    }
    int index = 0;
    for (const auto blob : blobs) {
        if (sqlite3_bind_blob64(statement.get(), ++index, blob.data(), blob.size(), nullptr) != SQLITE_OK) {
            throw std::runtime_error("a side connection could not bind a value");
        }
    }
    int code = SQLITE_ROW;
    while (code == SQLITE_ROW) {
        code = sqlite3_step(statement.get());
    }
    if (code != SQLITE_DONE) {
        throw std::runtime_error("a side connection could not run: " + std::string(sql));
    }
}

void Side::close() noexcept
{
    database_.reset();
}

}
