// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/store.hpp"

#include "lume/crypto/bytes.hpp"
#include "support/expected.hpp"
#include "support/store_fixture.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace lume::vault {
namespace {

using crypto::Bytes;
using test::Backing;
using test::Material;
using test::must;
using test::Place;

constexpr std::size_t page_size = 4096;
constexpr std::size_t sector_size = 512;
constexpr std::size_t checksum_stride = 200;
constexpr std::size_t application_id_offset = 68;
constexpr std::uint32_t checksum_seed = 0x01020304;
constexpr std::array<std::uint8_t, 8> journal_magic{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7};

struct Tables {
    std::string_view vault;
    std::string_view record;
    std::string_view body;
};

constexpr Tables exact{
    .vault = "CREATE TABLE vault (id INTEGER PRIMARY KEY CHECK (id = 1), header BLOB NOT NULL CHECK (length(header) IN (139, 204)), "
    "manifest BLOB NOT NULL CHECK (length(manifest) = 1235)) STRICT",
    .record = "CREATE TABLE record (slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 9223372036854775807), "
              "address BLOB NOT NULL CHECK (length(address) = 138)) STRICT",
    .body = "CREATE TABLE body (slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 9223372036854775807), "
    "record BLOB NOT NULL CHECK (length(record) BETWEEN 296 AND 131112)) STRICT",
};

class VaultStoreHostile : public ::testing::TestWithParam<Backing> {};

INSTANTIATE_TEST_SUITE_P(Backings, VaultStoreHostile, ::testing::Values(Backing::os, Backing::memory),
    [](const ::testing::TestParamInfo<Backing>& instance) { return test::backing_name(instance.param); });

Error opening(const Place& place)
{
    return test::error_of(Store::open_existing(place.path(), place.vfs()));
}

Error creating(const Place& place)
{
    return test::error_of(Store::open_new(place.path(), place.vfs()));
}

Bytes payload(std::uint8_t seed)
{
    return test::patterned(400, seed);
}

void forge(const Place& place, const Tables& tables, std::string_view page = "4096", std::string_view vacuum = "INCREMENTAL")
{
    const auto& material = Material::keystore();
    const test::Side side(place);
    side.run("PRAGMA page_size = " + std::string(page));
    side.run("PRAGMA auto_vacuum = " + std::string(vacuum));
    side.run("PRAGMA journal_mode = WAL");
    for (const auto table : {tables.vault, tables.record, tables.body}) {
        side.run(table);
    }
    side.run("INSERT INTO vault (id, header, manifest) VALUES (1, ?1, ?2)", {material.header(), material.manifest(1)});
    side.run("PRAGMA application_id = 1280658774");
    side.run("PRAGMA user_version = 1");
}

void altered(const Place& place, std::initializer_list<std::string_view> statements)
{
    const test::Side side(place);
    side.run("PRAGMA ignore_check_constraints = ON");
    for (const auto statement : statements) {
        side.run(statement);
    }
}

std::vector<std::size_t> positions(crypto::ByteView haystack, crypto::ByteView needle)
{
    std::vector<std::size_t> found;
    for (std::size_t at = 0; at + needle.size() <= haystack.size(); ++at) {
        if (std::ranges::equal(haystack.subspan(at, needle.size()), needle)) {
            found.push_back(at);
        }
    }
    return found;
}

void retype(const Place& place, crypto::ByteView record_header, std::size_t changed)
{
    auto file = place.read();
    if (!file) {
        throw std::runtime_error("the vault file is missing");
    }
    const auto found = positions(*file, record_header);
    if (found.size() != 1) {
        throw std::runtime_error("the record header is not unique in the vault file");
    }
    auto& serial_type = file->at(found.front() + changed);
    serial_type = static_cast<std::uint8_t>(serial_type + 1);
    place.write("", *file);
}

void put_u32(Bytes& bytes, std::size_t at, std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(at + index) = static_cast<std::uint8_t>(value >> (8U * (3U - index)));
    }
}

Bytes hot_journal(crypto::ByteView first_page, std::uint32_t pages, bool damaged)
{
    Bytes journal(sector_size + 4 + page_size + 4);
    std::ranges::copy(journal_magic, journal.begin());
    put_u32(journal, 8, 1);
    put_u32(journal, 12, checksum_seed);
    put_u32(journal, 16, pages);
    put_u32(journal, 20, static_cast<std::uint32_t>(sector_size));
    put_u32(journal, 24, static_cast<std::uint32_t>(page_size));
    put_u32(journal, sector_size, 1);
    std::ranges::copy(first_page, std::next(journal.begin(), static_cast<std::ptrdiff_t>(sector_size + 4)));
    std::uint32_t checksum = checksum_seed;
    for (std::size_t at = page_size % checksum_stride; at < first_page.size(); at += checksum_stride) {
        checksum += first_page.subspan(at, 1).front();
    }
    put_u32(journal, sector_size + 4 + page_size, damaged ? checksum + 1 : checksum);
    return journal;
}

TEST_P(VaultStoreHostile, RefusesAPlantedTriggerViewOrIndex)
{
    for (const std::string_view planted : {"CREATE TRIGGER planted AFTER INSERT ON record BEGIN DELETE FROM body; END",
             "CREATE VIEW planted AS SELECT slot FROM record", "CREATE INDEX planted ON body (record)"}) {
        const Place place(GetParam());
        static_cast<void>(test::created(place, Material::keystore(), {Material::keystore().row(5, 1, payload(1))}));
        altered(place, {planted});
        EXPECT_EQ(opening(place), Error::integrity) << planted;
        EXPECT_EQ(creating(place), Error::integrity) << planted;
    }
}

TEST_P(VaultStoreHostile, AcceptsOnlyTheExactTableDefinitions)
{
    {
        const Place place(GetParam());
        forge(place, exact);
        const auto store = Store::open_existing(place.path(), place.vfs());
        ASSERT_TRUE(store.has_value());
        EXPECT_EQ(store->opened().content, Content::vault);
        EXPECT_EQ(store->opened().manifest, Material::keystore().manifest(1));
    }
    const std::vector<Tables> changed{
        {.vault = exact.vault,
            .record = "CREATE TABLE record (slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 9223372036854775807), "
                      "address BLOB NOT NULL CHECK (length(address) = 138))",
            .body = exact.body},
        {.vault = exact.vault,
            .record = exact.record,
            .body = "CREATE TABLE body (slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 9223372036854775807), "
            "record BLOB NOT NULL CHECK (length(record) BETWEEN 296 AND 131113)) STRICT"},
        {.vault = "CREATE TABLE vault (id INTEGER PRIMARY KEY CHECK (id = 1), header BLOB NOT NULL CHECK (length(header) IN (139, 204)), "
                  "manifest BLOB NOT NULL CHECK (length(manifest) = 1235))  STRICT",
            .record = exact.record,
            .body = exact.body},
        {.vault = "CREATE TABLE vault (id INTEGER PRIMARY KEY, header BLOB NOT NULL, manifest BLOB NOT NULL) STRICT",
            .record = exact.record,
            .body = exact.body},
    };
    for (const auto& tables : changed) {
        const Place place(GetParam());
        forge(place, tables);
        EXPECT_EQ(opening(place), Error::integrity);
        EXPECT_EQ(creating(place), Error::integrity);
    }
}

TEST_P(VaultStoreHostile, RefusesAForeignLayoutAndANewerVersion)
{
    const auto check = [](std::initializer_list<std::string_view> statements, Error error) {
        const Place place(GetParam());
        static_cast<void>(test::created(place, Material::keystore(), {}));
        altered(place, statements);
        EXPECT_EQ(opening(place), error) << *statements.begin();
        EXPECT_EQ(creating(place), error) << *statements.begin();
    };
    check({"PRAGMA application_id = 0"}, Error::integrity);
    check({"PRAGMA application_id = 1280658775"}, Error::integrity);
    check({"PRAGMA user_version = 0"}, Error::integrity);
    check({"PRAGMA user_version = -1"}, Error::integrity);
    check({"PRAGMA user_version = 2"}, Error::unsupported_version);
    check({"PRAGMA application_id = 0", "PRAGMA user_version = 2"}, Error::integrity);
    check({"PRAGMA application_id = 1280658775", "PRAGMA user_version = 2"}, Error::integrity);
    check({"PRAGMA journal_mode = DELETE"}, Error::integrity);
    for (const auto& [page, vacuum] : {std::pair<std::string_view, std::string_view>{"1024", "INCREMENTAL"}, {"4096", "NONE"}, {"4096", "FULL"}}) {
        const Place place(GetParam());
        forge(place, exact, page, vacuum);
        EXPECT_EQ(opening(place), Error::integrity) << page << " " << vacuum;
        EXPECT_EQ(creating(place), Error::integrity) << page << " " << vacuum;
    }
}

TEST_P(VaultStoreHostile, RefusesAVaultRowOfAnotherShape)
{
    const auto check = [](std::initializer_list<std::string_view> statements, Error error) {
        const Place place(GetParam());
        static_cast<void>(test::created(place, Material::keystore(), {}));
        altered(place, statements);
        EXPECT_EQ(opening(place), error) << *statements.begin();
        EXPECT_EQ(creating(place), Error::vault_exists) << *statements.begin();
    };
    check({"DELETE FROM vault"}, Error::integrity);
    check({"UPDATE vault SET header = zeroblob(140)"}, Error::integrity);
    check({"UPDATE vault SET header = zeroblob(138)"}, Error::integrity);
    check({"UPDATE vault SET manifest = zeroblob(1234)"}, Error::integrity);
    check({"UPDATE vault SET header = zeroblob(300000)"}, Error::integrity);
    check({"UPDATE vault SET manifest = zeroblob(300000)"}, Error::integrity);
    check({"UPDATE vault SET header = zeroblob(139)"}, Error::wiped);
    check({"UPDATE vault SET header = zeroblob(204)"}, Error::wiped);

    const Place place(GetParam());
    static_cast<void>(test::created(place, Material::keystore(), {}));
    retype(place, std::array<std::uint8_t, 6>{0x06, 0x00, 0x82, 0x22, 0x93, 0x32}, 3);
    EXPECT_EQ(opening(place), Error::integrity);
}

TEST_P(VaultStoreHostile, CallsOnlyAHeaderOfZerosWiped)
{
    auto first_cleared = Material::keystore().header();
    first_cleared.front() = 0;
    Bytes last_set(Material::keystore().header().size());
    last_set.back() = 1;
    for (const auto& header : {first_cleared, last_set}) {
        const Place place(GetParam());
        static_cast<void>(test::created(place, Material::keystore(), {}));
        {
            const test::Side side(place);
            side.run("UPDATE vault SET header = ?1", {header});
        }
        const auto store = Store::open_existing(place.path(), place.vfs());
        ASSERT_TRUE(store.has_value());
        EXPECT_EQ(store->opened().header, header);
        EXPECT_EQ(store->opened().manifest, Material::keystore().manifest(1));
    }
}

TEST_P(VaultStoreHostile, CallsOnlyAFileWithNothingInItEmpty)
{
    for (const std::string_view statement :
        {"CREATE TABLE foreign_table (x BLOB)", "PRAGMA application_id = 1280658774", "PRAGMA user_version = 1"}) {
        const Place place(GetParam());
        {
            const test::Side side(place);
            side.run(statement);
        }
        ASSERT_TRUE(place.exists()) << statement;
        EXPECT_EQ(opening(place), Error::integrity) << statement;
        EXPECT_EQ(creating(place), Error::integrity) << statement;
    }
}

TEST_P(VaultStoreHostile, RefusesRowsOfAnotherTypeOrSize)
{
    const auto& material = Material::keystore();
    const auto row = material.row(5, 1, payload(1));
    const auto scan_error = [&material, &row](std::initializer_list<std::string_view> statements) {
        const Place place(GetParam());
        static_cast<void>(test::created(place, material, {row}));
        altered(place, statements);
        auto store = must(Store::open_existing(place.path(), place.vfs()));
        must(store.begin_scan());
        return test::error_of(store.next_row());
    };
    EXPECT_EQ(scan_error({"UPDATE record SET slot = 0"}), Error::integrity);
    EXPECT_EQ(scan_error({"UPDATE record SET slot = -5"}), Error::integrity);
    EXPECT_EQ(scan_error({"UPDATE record SET address = zeroblob(137)"}), Error::integrity);
    EXPECT_EQ(scan_error({"UPDATE record SET address = zeroblob(139)"}), Error::integrity);
    EXPECT_EQ(scan_error({"UPDATE record SET address = zeroblob(300000)"}), Error::integrity);

    const auto body_errors = [&material, &row](std::initializer_list<std::string_view> statements) {
        const Place place(GetParam());
        static_cast<void>(test::created(place, material, {row}));
        altered(place, statements);
        auto store = must(Store::open_existing(place.path(), place.vfs()));
        EXPECT_EQ(test::error_of(store.body(row.slot)), Error::integrity) << *statements.begin();
        EXPECT_EQ(must(store.salvage_body(row.slot)), std::nullopt) << *statements.begin();
    };
    body_errors({"UPDATE body SET record = zeroblob(295)"});
    body_errors({"UPDATE body SET record = zeroblob(131113)"});
    body_errors({"UPDATE body SET record = zeroblob(300000)"});

    const Place place(GetParam());
    static_cast<void>(test::created(place, material, {row}));
    retype(place, std::array<std::uint8_t, 4>{0x04, 0x00, 0x82, 0x20}, 3);
    auto store = must(Store::open_existing(place.path(), place.vfs()));
    must(store.begin_scan());
    EXPECT_EQ(test::error_of(store.next_row()), Error::integrity);
    EXPECT_EQ(must(store.body(row.slot)), std::optional<Bytes>(row.record));
}

TEST_P(VaultStoreHostile, ReplaysAHostileLogOnlyIntoARefusal)
{
    const auto& material = Material::keystore();
    {
        const Place place(GetParam());
        static_cast<void>(test::created(place, material, {}));
        place.write("-wal", test::patterned(8192, 3));
        auto store = must(Store::open_existing(place.path(), place.vfs()));
        EXPECT_EQ(store.opened().manifest, material.manifest(1));
        EXPECT_EQ(store.commit({}, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
        EXPECT_TRUE(store.checkpoint().has_value());
    }
    const Place place(GetParam());
    static_cast<void>(test::created(place, material, {}));
    const auto clean = place.read().value_or(Bytes{});
    ASSERT_FALSE(clean.empty());
    Bytes log;
    {
        test::Side side(place);
        side.run("CREATE TRIGGER planted AFTER INSERT ON record BEGIN DELETE FROM body; END");
        log = place.read("-wal").value_or(Bytes{});
        side.close();
    }
    ASSERT_GT(log.size(), 0U);
    place.write("", clean);
    place.write("-wal", log);
    EXPECT_EQ(opening(place), Error::integrity);
}

TEST_P(VaultStoreHostile, NeverTouchesAPlantedSharedMemoryFile)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    static_cast<void>(test::created(place, material, {}));
    const auto planted = test::patterned(32768, 7);
    place.write("-shm", planted);
    {
        auto store = must(Store::open_existing(place.path(), place.vfs()));
        ASSERT_EQ(store.commit({}, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
        ASSERT_TRUE(store.checkpoint().has_value());
    }
    EXPECT_EQ(place.read("-shm"), std::optional<Bytes>(planted));
    const auto store = must(Store::open_existing(place.path(), place.vfs()));
    EXPECT_EQ(store.opened().manifest, material.manifest(2));
}

TEST_P(VaultStoreHostile, RefusesWhatAPlantedHotJournalPutsBack)
{
    for (const bool damaged : {true, false}) {
        const Place place(GetParam());
        static_cast<void>(test::created(place, Material::keystore(), {Material::keystore().row(5, 1, payload(1))}));
        const auto file = place.read().value_or(Bytes{});
        ASSERT_GE(file.size(), page_size);
        ASSERT_EQ(file.size() % page_size, 0U);
        Bytes first_page(file.begin(), std::next(file.begin(), static_cast<std::ptrdiff_t>(page_size)));
        std::ranges::fill(std::span(first_page).subspan(application_id_offset, 4), std::uint8_t{0});
        place.write("-journal", hot_journal(first_page, static_cast<std::uint32_t>(file.size() / page_size), damaged));
        if (damaged) {
            const auto store = Store::open_existing(place.path(), place.vfs());
            ASSERT_TRUE(store.has_value());
            EXPECT_EQ(store->opened().content, Content::vault);
        } else {
            EXPECT_EQ(opening(place), Error::integrity);
        }
    }
}

TEST_P(VaultStoreHostile, TreatsAnEmptyFileAsNoVaultAndRandomBytesAsDamage)
{
    {
        const Place place(GetParam());
        place.write("", {});
        EXPECT_EQ(opening(place), Error::no_vault);
        auto store = must(Store::open_new(place.path(), place.vfs()));
        EXPECT_EQ(store.opened().content, Content::empty);
        EXPECT_EQ(store.initialise(Material::keystore().header(), Material::keystore().manifest(1), {}).outcome, Outcome::committed);
    }
    for (const std::size_t size : {std::size_t{100}, std::size_t{4096}, std::size_t{16384}}) {
        const Place place(GetParam());
        place.write("", test::patterned(size, 9));
        EXPECT_EQ(opening(place), Error::integrity) << size;
        EXPECT_EQ(creating(place), Error::integrity) << size;
    }
}

TEST(VaultStoreHostileFiles, RefusesADirectoryWhereTheVaultBelongs)
{
    const Place place(Backing::os);
    std::filesystem::create_directory(place.path());
    EXPECT_EQ(opening(place), Error::storage);
    EXPECT_EQ(creating(place), Error::storage);
    EXPECT_TRUE(std::filesystem::is_directory(place.path()));
}

#ifndef _WIN32
TEST(VaultStoreHostilePosix, RefusesASymbolicLink)
{
    const Place place(Backing::os);
    static_cast<void>(test::created(place, Material::keystore(), {}));
    std::filesystem::create_symlink(place.path(), place.path("-link"));
    EXPECT_EQ(test::error_of(Store::open_existing(place.path("-link"), place.vfs())), Error::storage);
    EXPECT_EQ(test::error_of(Store::open_new(place.path("-link"), place.vfs())), Error::storage);
    EXPECT_TRUE(Store::open_existing(place.path(), place.vfs()).has_value());
}

TEST(VaultStoreHostilePosix, RemovesNothingThroughASymbolicLink)
{
    const Place place(Backing::os);
    static_cast<void>(test::created(place, Material::keystore(), {}));
    const auto planted = test::patterned(64, 9);
    place.write("-shm", planted);
    place.write("-journal", planted);
    std::filesystem::create_symlink(place.path(), place.path("-link"));
    EXPECT_EQ(test::error_of(Store::remove_files(place.path("-link"), place.vfs())), Error::storage);
    for (const std::string_view suffix : {"", "-wal", "-shm", "-journal"}) {
        EXPECT_TRUE(place.exists(suffix)) << suffix;
    }
    EXPECT_TRUE(std::filesystem::is_symlink(place.path("-link")));
    EXPECT_EQ(place.read("-journal"), std::optional<Bytes>(planted));
    EXPECT_TRUE(Store::open_existing(place.path(), place.vfs()).has_value());
}

TEST(VaultStoreHostilePosix, RefusesALinkToNothing)
{
    const Place place(Backing::os);
    std::filesystem::create_symlink(place.path("-absent"), place.path("-link"));
    EXPECT_EQ(test::error_of(Store::open_existing(place.path("-link"), place.vfs())), Error::storage);
    EXPECT_EQ(test::error_of(Store::open_new(place.path("-link"), place.vfs())), Error::storage);
    EXPECT_EQ(test::error_of(Store::remove_files(place.path("-link"), place.vfs())), Error::storage);
    EXPECT_FALSE(place.exists("-absent"));
    EXPECT_TRUE(std::filesystem::is_symlink(place.path("-link")));
}

TEST(VaultStoreHostilePosix, RefusesAPathThroughALinkedDirectory)
{
    const Place place(Backing::os);
    const auto directory = std::filesystem::path(place.path()).parent_path();
    std::filesystem::create_directory(directory / "real");
    std::filesystem::create_directory_symlink(directory / "real", directory / "linked");
    const auto real = (directory / "real" / "vault.db").string();
    const auto linked = (directory / "linked" / "vault.db").string();
    {
        auto store = must(Store::open_new(real, place.vfs()));
        ASSERT_EQ(store.initialise(Material::keystore().header(), Material::keystore().manifest(1), {}).outcome, Outcome::committed);
    }
    EXPECT_EQ(test::error_of(Store::open_existing(linked, place.vfs())), Error::storage);
    EXPECT_EQ(test::error_of(Store::open_new(linked, place.vfs())), Error::storage);
    EXPECT_EQ(test::error_of(Store::remove_files(linked, place.vfs())), Error::storage);
    EXPECT_TRUE(std::filesystem::exists(directory / "real" / "vault.db"));
    EXPECT_TRUE(Store::open_existing(real, place.vfs()).has_value());
}
#endif

}
}
