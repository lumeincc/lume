// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/store.hpp"

#include "lume/crypto/bytes.hpp"
#include "lume/wire/codec.hpp"
#include "lume/wire/structures.hpp"
#include "support/expected.hpp"
#include "support/memory_vfs.hpp"
#include "support/store_fixture.hpp"
#include "vault/records.hpp"

#include <gtest/gtest.h>
#include <sqlite3.h>

#ifdef _WIN32
#include <process.h>
#else
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lume::vault {
namespace {

using crypto::Bytes;
using test::Backing;
using test::Material;
using test::must;
using test::Place;

constexpr std::array<std::string_view, 4> companion_files{"", "-wal", "-shm", "-journal"};
constexpr std::uint64_t busy_microseconds = 2000000;

constexpr std::array<std::pair<int, int>, 14> db_configs{{
    {SQLITE_DBCONFIG_DEFENSIVE, 1},
    {SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1},
    {SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0},
    {SQLITE_DBCONFIG_ENABLE_TRIGGER, 0},
    {SQLITE_DBCONFIG_ENABLE_VIEW, 0},
    {SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0},
    {SQLITE_DBCONFIG_DQS_DML, 0},
    {SQLITE_DBCONFIG_DQS_DDL, 0},
    {SQLITE_DBCONFIG_ENABLE_FKEY, 0},
    {SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, 0},
    {SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, 0},
    {SQLITE_DBCONFIG_WRITABLE_SCHEMA, 0},
    {SQLITE_DBCONFIG_LEGACY_ALTER_TABLE, 0},
    {SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, 0},
}};

constexpr std::array<std::pair<int, int>, 13> limits{{
    {SQLITE_LIMIT_LENGTH, 262144},
    {SQLITE_LIMIT_SQL_LENGTH, 4096},
    {SQLITE_LIMIT_COLUMN, 8},
    {SQLITE_LIMIT_EXPR_DEPTH, 32},
    {SQLITE_LIMIT_PARSER_DEPTH, 64},
    {SQLITE_LIMIT_COMPOUND_SELECT, 1},
    {SQLITE_LIMIT_FUNCTION_ARG, 3},
    {SQLITE_LIMIT_ATTACHED, 0},
    {SQLITE_LIMIT_VARIABLE_NUMBER, 8},
    {SQLITE_LIMIT_TRIGGER_DEPTH, 1},
    {SQLITE_LIMIT_TRIGGER_STEPS, 1},
    {SQLITE_LIMIT_WORKER_THREADS, 0},
    {SQLITE_LIMIT_SCHEMA, 4},
}};

class VaultStore : public ::testing::TestWithParam<Backing> {};

INSTANTIATE_TEST_SUITE_P(Backings, VaultStore, ::testing::Values(Backing::os, Backing::memory),
    [](const ::testing::TestParamInfo<Backing>& instance) { return test::backing_name(instance.param); });

std::vector<detail::Setting> expected_settings()
{
    const std::vector<std::pair<std::string_view, std::string_view>> pairs{
        {"pragma.busy_timeout", "2000"},
        {"pragma.locking_mode", "exclusive"},
        {"pragma.secure_delete", "1"},
        {"pragma.cell_size_check", "1"},
        {"pragma.mmap_size", "0"},
        {"pragma.temp_store", "2"},
        {"pragma.trusted_schema", "0"},
        {"pragma.foreign_keys", "0"},
        {"pragma.wal_autocheckpoint", "0"},
        {"pragma.journal_mode", "wal"},
        {"pragma.synchronous", "2"},
    };
    std::vector<detail::Setting> settings;
    settings.reserve(pairs.size());
    for (const auto& [name, value] : pairs) {
        settings.push_back(detail::Setting{.name = std::string(name), .value = std::string(value)});
    }
    return settings;
}

void expect_hardened(const Store& store)
{
    for (const auto& [option, value] : db_configs) {
        EXPECT_EQ(detail::db_config(store, option), value) << "db_config " << option;
    }
    for (const auto& [limit, value] : limits) {
        EXPECT_EQ(detail::limit(store, limit), value) << "limit " << limit;
    }
    EXPECT_EQ(detail::settings(store), expected_settings());
}

Bytes payload(std::uint8_t seed)
{
    return test::patterned(300, seed);
}

test::MemoryFaults faults(int read_fault, int write_fault, int open_fault = 0, std::uint64_t busy_locks = 0)
{
    return test::MemoryFaults{.read = read_fault, .write = write_fault, .open = open_fault, .busy_locks = busy_locks};
}

struct CloseRaw {
    void operator()(sqlite3* database) const noexcept
    {
        static_cast<void>(sqlite3_close_v2(database));
    }
};

bool loads_schema_within(const Place& place, int objects)
{
    sqlite3* raw = nullptr;
    const int opened = sqlite3_open_v2(place.path().c_str(), &raw, SQLITE_OPEN_READWRITE, place.vfs());
    const std::unique_ptr<sqlite3, CloseRaw> database(raw);
    if (opened != SQLITE_OK) {
        throw std::runtime_error("a raw connection could not open the test file");
    }
    static_cast<void>(sqlite3_limit(database.get(), SQLITE_LIMIT_SCHEMA, objects));
    for (const std::string_view sql : {"PRAGMA locking_mode = EXCLUSIVE", "SELECT count(*) FROM sqlite_schema"}) {
        sqlite3_stmt* statement = nullptr;
        const int prepared = sqlite3_prepare_v2(database.get(), sql.data(), static_cast<int>(sql.size()), &statement, nullptr);
        const int stepped = prepared == SQLITE_OK ? sqlite3_step(statement) : prepared;
        static_cast<void>(sqlite3_finalize(statement));
        if (stepped != SQLITE_ROW) {
            return false;
        }
    }
    return true;
}

std::map<std::uint64_t, Bytes> scanned(Store& store)
{
    std::map<std::uint64_t, Bytes> rows;
    must(store.begin_scan());
    for (;;) {
        auto row = must(store.next_row());
        if (!row) {
            return rows;
        }
        rows.emplace(row->slot, Bytes(row->address.begin(), row->address.end()));
    }
}

std::size_t size_of(const Place& place, std::string_view suffix)
{
    const auto bytes = place.read(suffix);
    return bytes ? bytes->size() : 0;
}

int probe(const std::string& path)
{
#ifdef _WIN32
    const std::string program = LUME_STORE_PROBE;
    const std::string quoted_program = '"' + program + '"';
    const std::string quoted_path = '"' + path + '"';
    const std::array<const char*, 3> arguments{quoted_program.c_str(), quoted_path.c_str(), nullptr};
    return static_cast<int>(_spawnv(_P_WAIT, program.c_str(), arguments.data()));
#else
    std::string program = LUME_STORE_PROBE;
    std::string argument = path;
    std::array<char*, 3> arguments{program.data(), argument.data(), nullptr};
    std::array<char*, 1> environment{nullptr};
    pid_t child = 0;
    if (posix_spawn(&child, program.c_str(), nullptr, nullptr, arguments.data(), environment.data()) != 0) {
        return -1;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
#endif
}

TEST(VaultStoreLibrary, IsTheBuildTheDesignRequires)
{
    EXPECT_EQ(sqlite3_libversion_number(), SQLITE_VERSION_NUMBER);
    EXPECT_GE(sqlite3_libversion_number(), 3054001);
    EXPECT_NE(sqlite3_threadsafe(), 0);
    EXPECT_EQ(sqlite3_compileoption_used("OMIT_LOAD_EXTENSION"), 1);
}

TEST(VaultStoreLibrary, StoresHeadersOfExactlyTheSizesTheWireEncodes)
{
    EXPECT_EQ(Material::keystore().header().size(), 139U);
    EXPECT_EQ(Material::tpm().header().size(), 204U);
    for (const auto* material : {&Material::keystore(), &Material::tpm()}) {
        const Place place(Backing::memory);
        static_cast<void>(test::created(place, *material, {}));
        const auto reopened = Store::open_existing(place.path(), place.vfs());
        ASSERT_TRUE(reopened.has_value());
        EXPECT_EQ(reopened->opened().header, material->header());
        const auto header = wire::decode(reopened->opened().header, wire::read_vault_header);
        ASSERT_TRUE(header.has_value());
        EXPECT_EQ(wire::encode(*header), material->header());
    }
}

TEST_P(VaultStore, ReadsBackEveryOptionLimitAndPragmaOnEveryOpen)
{
    const Place place(GetParam());
    {
        auto store = Store::open_new(place.path(), place.vfs());
        ASSERT_TRUE(store.has_value());
        expect_hardened(*store);
        EXPECT_FALSE(detail::sealed(*store));
        ASSERT_EQ(store->initialise(Material::keystore().header(), Material::keystore().manifest(1), {}).outcome, Outcome::committed);
        EXPECT_TRUE(detail::sealed(*store));
        expect_hardened(*store);
    }
    const auto reopened = Store::open_existing(place.path(), place.vfs());
    ASSERT_TRUE(reopened.has_value());
    EXPECT_TRUE(detail::sealed(*reopened));
    expect_hardened(*reopened);
}

TEST_P(VaultStore, CreatesOnlyWhereNoVaultIsAndReadsBackWhatItWrote)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::no_vault);

    const auto first = material.row(7, 1, payload(1), "first");
    const auto second = material.row(slot_bound, 2, test::patterned(5000, 2), "second");
    {
        auto store = Store::open_new(place.path(), place.vfs());
        ASSERT_TRUE(store.has_value());
        EXPECT_EQ(store->opened().content, Content::empty);
        EXPECT_TRUE(store->opened().header.empty());
        const std::vector<RowChange> rows{test::inserted(first), test::inserted(second)};
        const auto result = store->initialise(material.header(), material.manifest(1), rows);
        ASSERT_EQ(result.outcome, Outcome::committed);
        EXPECT_EQ(store->opened().content, Content::vault);
        EXPECT_EQ(store->opened().header, material.header());
        EXPECT_EQ(store->opened().manifest, material.manifest(1));
        EXPECT_TRUE(store->checkpoint().has_value());
    }
    EXPECT_EQ(test::error_of(Store::open_new(place.path(), place.vfs())), Error::vault_exists);

    auto store = Store::open_existing(place.path(), place.vfs());
    ASSERT_TRUE(store.has_value());
    EXPECT_EQ(store->opened().content, Content::vault);
    EXPECT_EQ(store->opened().header, material.header());
    EXPECT_EQ(store->opened().manifest, material.manifest(1));
    const std::map<std::uint64_t, Bytes> expected{{first.slot, first.address}, {second.slot, second.address}};
    EXPECT_EQ(scanned(*store), expected);
    EXPECT_EQ(must(store->body(first.slot)), std::optional<Bytes>(first.record));
    EXPECT_EQ(must(store->body(second.slot)), std::optional<Bytes>(second.record));
    EXPECT_EQ(must(store->salvage_body(second.slot)), std::optional<Bytes>(second.record));
    EXPECT_EQ(must(store->body(8)), std::nullopt);
    EXPECT_EQ(must(store->salvage_body(8)), std::nullopt);
}

TEST_P(VaultStore, NeverMakesASharedMemoryFileAndEmptiesTheLogAtEveryCheckpoint)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto row = material.row(11, 1, payload(1));
    const auto rewritten = material.row(11, 2, payload(2), "record", 1);
    const auto other = material.row(12, 3, payload(3), "other");
    {
        auto store = must(Store::open_new(place.path(), place.vfs()));
        EXPECT_FALSE(place.exists("-shm"));
        const std::vector<RowChange> initial{test::inserted(row)};
        ASSERT_EQ(store.initialise(material.header(), material.manifest(1), initial).outcome, Outcome::committed);
        EXPECT_GT(size_of(place, "-wal"), 0U);
        ASSERT_TRUE(store.checkpoint().has_value());
        EXPECT_TRUE(place.exists("-wal"));
        EXPECT_EQ(size_of(place, "-wal"), 0U);

        const std::vector<std::vector<RowChange>> writes{
            {test::replaced(row, rewritten)}, {test::inserted(other)}, {test::erased(other)}, {}};
        std::uint8_t manifest = 1;
        for (const auto& rows : writes) {
            const auto next = static_cast<std::uint8_t>(manifest + 1);
            ASSERT_EQ(store.commit(rows, std::nullopt, material.manifest(manifest), material.manifest(next)).outcome,
                Outcome::committed);
            manifest = next;
            EXPECT_GT(size_of(place, "-wal"), 0U);
            ASSERT_TRUE(store.checkpoint().has_value());
            EXPECT_EQ(size_of(place, "-wal"), 0U);
            EXPECT_FALSE(place.exists("-shm"));
        }
        const auto old_header = material.header();
        const auto new_header = material.header(1);
        const Swap swap{.old_header = old_header, .new_header = new_header};
        ASSERT_EQ(store.commit({}, swap, material.manifest(manifest), material.manifest(9)).outcome, Outcome::committed);
        EXPECT_EQ(store.opened().header, material.header(1));
        EXPECT_EQ(store.opened().manifest, material.manifest(9));
        ASSERT_TRUE(store.checkpoint().has_value());
        EXPECT_EQ(size_of(place, "-wal"), 0U);
        ASSERT_EQ(store.commit({}, std::nullopt, material.manifest(9), material.manifest(10)).outcome, Outcome::committed);
        EXPECT_GT(size_of(place, "-wal"), 0U);
    }
    const auto log = place.read("-wal").value_or(Bytes{});
    EXPECT_GT(log.size(), 0U);
    EXPECT_FALSE(place.exists("-shm"));

    auto store = must(Store::open_existing(place.path(), place.vfs()));
    EXPECT_EQ(store.opened().header, material.header(1));
    EXPECT_EQ(store.opened().manifest, material.manifest(10));
    EXPECT_EQ(place.read("-wal").value_or(Bytes{}), log);
    ASSERT_TRUE(store.checkpoint().has_value());
    EXPECT_EQ(size_of(place, "-wal"), 0U);
    EXPECT_FALSE(place.exists("-shm"));
}

TEST_P(VaultStore, RefusesASecondConnectionInTheSameProcess)
{
    const Place place(GetParam());
    {
        auto store = test::created(place, Material::keystore(), {});
        EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::busy);
        EXPECT_EQ(test::error_of(Store::open_new(place.path(), place.vfs())), Error::busy);
        EXPECT_EQ(store.commit({}, std::nullopt, Material::keystore().manifest(1), Material::keystore().manifest(2)).outcome,
            Outcome::committed);
    }
    const auto reopened = Store::open_existing(place.path(), place.vfs());
    ASSERT_TRUE(reopened.has_value());
    EXPECT_EQ(reopened->opened().manifest, Material::keystore().manifest(2));
}

TEST(VaultStoreProcess, RefusesASecondProcess)
{
    const Place place(Backing::os);
    {
        const auto store = test::created(place, Material::keystore(), {});
        EXPECT_EQ(probe(place.path()), static_cast<int>(Error::busy));
    }
    EXPECT_EQ(probe(place.path()), 0);
}

TEST_P(VaultStore, CatchesEveryOlderValueItIsAskedToWriteOver)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto older = material.row(21, 1, payload(1));
    const auto current = material.row(21, 2, payload(2), "record", 1);
    const auto newer = material.row(21, 3, payload(3), "record", 2);
    const auto extra = material.row(22, 4, payload(4), "extra");
    {
        auto store = test::created(place, material, {older});
        const std::vector<RowChange> rewrite{test::replaced(older, current)};
        ASSERT_EQ(store.commit(rewrite, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);

        const auto refused = [&](const std::vector<RowChange>& rows, std::optional<Swap> header, const Bytes& old_manifest) {
            const auto result = store.commit(rows, header, old_manifest, material.manifest(3));
            EXPECT_EQ(result.outcome, Outcome::mismatch);
            EXPECT_EQ(result.error, Error::integrity);
        };
        auto stale_address = test::replaced(current, newer);
        stale_address.old_address_nonce = test::leading_nonce(older.address);
        refused({stale_address}, std::nullopt, material.manifest(2));
        auto stale_record = test::replaced(current, newer);
        stale_record.old_record_nonce = test::leading_nonce(older.record);
        refused({stale_record}, std::nullopt, material.manifest(2));
        auto stale_address_erase = test::erased(current);
        stale_address_erase.old_address_nonce = test::leading_nonce(older.address);
        refused({stale_address_erase}, std::nullopt, material.manifest(2));
        auto stale_record_erase = test::erased(current);
        stale_record_erase.old_record_nonce = test::leading_nonce(older.record);
        refused({stale_record_erase}, std::nullopt, material.manifest(2));
        refused({}, std::nullopt, material.manifest(1));
        refused({test::inserted(extra), test::replaced(current, newer)}, std::nullopt, material.manifest(1));
        const auto stale_header = material.header(5);
        refused({}, Swap{.old_header = stale_header, .new_header = material.header(6)}, material.manifest(2));
        refused({}, Swap{.old_header = material.header(), .new_header = material.header(6)}, material.manifest(1));
        refused({test::inserted(extra), test::erased(older)}, std::nullopt, material.manifest(2));

        EXPECT_EQ(store.opened().manifest, material.manifest(2));
        EXPECT_EQ(store.opened().header, material.header());
    }
    auto store = must(Store::open_existing(place.path(), place.vfs()));
    EXPECT_EQ(store.opened().manifest, material.manifest(2));
    EXPECT_EQ(store.opened().header, material.header());
    const std::map<std::uint64_t, Bytes> expected{{current.slot, current.address}};
    EXPECT_EQ(scanned(store), expected);
    EXPECT_EQ(must(store.body(current.slot)), std::optional<Bytes>(current.record));
    EXPECT_EQ(must(store.body(extra.slot)), std::nullopt);
    const auto result = store.commit(std::vector<RowChange>{test::replaced(current, newer)},
        Swap{.old_header = material.header(), .new_header = material.header(6)}, material.manifest(2), material.manifest(3));
    EXPECT_EQ(result.outcome, Outcome::committed);
}

TEST_P(VaultStore, ChangesExactlyOneRowPerStatement)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto present = material.row(31, 1, payload(1));
    const auto absent = material.row(32, 2, payload(2));
    const auto absent_next = material.row(32, 3, payload(3), "record", 1);
    const auto taken = material.row(31, 4, payload(4), "taken");
    auto store = test::created(place, material, {present});
    for (const auto& rows : std::vector<std::vector<RowChange>>{
             {test::replaced(absent, absent_next)}, {test::erased(absent)}, {test::inserted(taken)}, {test::inserted(present)}}) {
        const auto result = store.commit(rows, std::nullopt, material.manifest(1), material.manifest(2));
        EXPECT_EQ(result.outcome, Outcome::mismatch);
        EXPECT_EQ(result.error, Error::integrity);
    }
    const std::map<std::uint64_t, Bytes> expected{{present.slot, present.address}};
    EXPECT_EQ(scanned(store), expected);
    EXPECT_EQ(must(store.body(present.slot)), std::optional<Bytes>(present.record));
}

TEST_P(VaultStore, UndoesTheWholeTransactionWhenOneTableRefusesAWrite)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto orphan = material.row(41, 1, payload(1));
    const auto incoming = material.row(41, 2, payload(2), "incoming");
    static_cast<void>(test::created(place, material, {orphan}));
    {
        const test::Side side(place);
        side.run("DELETE FROM record WHERE slot = 41");
    }
    auto store = must(Store::open_existing(place.path(), place.vfs()));
    const std::vector<RowChange> rows{test::inserted(incoming)};
    EXPECT_EQ(store.commit(rows, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::mismatch);
    EXPECT_TRUE(scanned(store).empty());
    EXPECT_EQ(must(store.body(orphan.slot)), std::optional<Bytes>(orphan.record));
    EXPECT_EQ(store.opened().manifest, material.manifest(1));
}

TEST_P(VaultStore, CompilesNoStatementOnceSealed)
{
    const Place place(GetParam());
    {
        auto store = must(Store::open_new(place.path(), place.vfs()));
        store.seal_statements();
        const auto result = store.initialise(Material::keystore().header(), Material::keystore().manifest(1), {});
        EXPECT_EQ(result.outcome, Outcome::mismatch);
        EXPECT_EQ(result.error, Error::integrity);
        EXPECT_EQ(store.opened().content, Content::empty);
    }
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::no_vault);
}

TEST_P(VaultStore, MarksTheVaultWiped)
{
    const Place place(GetParam());
    {
        auto store = test::created(place, Material::keystore(), {Material::keystore().row(51, 1, payload(1))});
        const auto result = store.mark_wiped();
        ASSERT_EQ(result.outcome, Outcome::committed);
        EXPECT_TRUE(std::ranges::all_of(store.opened().header, [](std::uint8_t byte) { return byte == 0; }));
        EXPECT_EQ(store.opened().header.size(), 139U);
        EXPECT_TRUE(std::ranges::all_of(store.opened().manifest, [](std::uint8_t byte) { return byte == 0; }));
        EXPECT_TRUE(store.checkpoint().has_value());
    }
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::wiped);
    EXPECT_EQ(test::error_of(Store::open_new(place.path(), place.vfs())), Error::vault_exists);
}

TEST_P(VaultStore, RemovesEveryFileItMayHaveLeft)
{
    const Place place(GetParam());
    static_cast<void>(test::created(place, Material::keystore(), {}));
    const auto planted = test::patterned(64, 9);
    place.write("-shm", planted);
    place.write("-journal", planted);
    for (const auto suffix : companion_files) {
        EXPECT_TRUE(place.exists(suffix)) << suffix;
    }
    const auto earlier = test::memory_vfs::deletions().size();
    EXPECT_TRUE(Store::remove_files(place.path(), place.vfs()).has_value());
    for (const auto suffix : companion_files) {
        EXPECT_FALSE(place.exists(suffix)) << suffix;
    }
    if (GetParam() == Backing::memory) {
        const auto deletions = test::memory_vfs::deletions();
        ASSERT_EQ(deletions.size(), earlier + companion_files.size());
        for (std::size_t index = 0; index < companion_files.size(); ++index) {
            EXPECT_EQ(deletions.at(earlier + index),
                (test::MemoryDeletion{.name = place.path(companion_files.at(index)), .synced = true}));
        }
    }
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::no_vault);
    EXPECT_TRUE(Store::remove_files(place.path(), place.vfs()).has_value());
}

TEST_P(VaultStore, RefusesWhatItWasNotMadeFor)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    for (const std::string_view path : {std::string_view(), std::string_view("vault\0db", 8), std::string_view(":memory:")}) {
        EXPECT_EQ(test::error_of(Store::open_existing(path, place.vfs())), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(Store::open_new(path, place.vfs())), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(Store::remove_files(path, place.vfs())), Error::invalid_parameters);
    }
    EXPECT_EQ(test::error_of(Store::open_new(place.path(), "lume-no-such-vfs")), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(Store::remove_files(place.path(), "lume-no-such-vfs")), Error::invalid_parameters);

    const auto row = material.row(61, 1, payload(1));
    const auto refused = [](const CommitResult& result) {
        EXPECT_EQ(result.outcome, Outcome::rolled_back);
        EXPECT_EQ(result.error, Error::invalid_parameters);
    };
    {
        auto empty = must(Store::open_new(place.path(), place.vfs()));
        EXPECT_EQ(test::error_of(empty.begin_scan()), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(empty.next_row()), Error::invalid_parameters);
        EXPECT_EQ(test::error_of(empty.body(row.slot)), Error::invalid_parameters);
        refused(empty.commit({}, std::nullopt, material.manifest(1), material.manifest(2)));
        refused(empty.mark_wiped());
        refused(empty.initialise(Bytes(140), material.manifest(1), {}));
        refused(empty.initialise(material.header(), Bytes(sealed_manifest_size - 1), {}));
        refused(empty.initialise(material.header(), material.manifest(1), std::vector<RowChange>{test::erased(row)}));
        auto bad_slot = test::inserted(row);
        bad_slot.slot = 0;
        refused(empty.initialise(material.header(), material.manifest(1), std::vector<RowChange>{bad_slot}));
        auto bad_record = test::inserted(row);
        bad_record.record.resize(record_minimum - 1);
        refused(empty.initialise(material.header(), material.manifest(1), std::vector<RowChange>{bad_record}));
        EXPECT_FALSE(detail::sealed(empty));
        EXPECT_TRUE(empty.checkpoint().has_value());
    }
    auto store = test::created(place, material, {row});
    refused(store.initialise(material.header(), material.manifest(1), {}));
    EXPECT_EQ(test::error_of(store.next_row()), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(store.body(0)), Error::invalid_parameters);
    EXPECT_EQ(test::error_of(store.body(slot_bound + 1)), Error::invalid_parameters);
    refused(store.commit({}, std::nullopt, material.manifest(1), Bytes(sealed_manifest_size + 1)));
    refused(store.commit({}, Swap{.old_header = material.header(), .new_header = Bytes(140)}, material.manifest(1), material.manifest(2)));
    auto bad_address = test::replaced(row, material.row(61, 2, payload(2), "record", 1));
    bad_address.address.pop_back();
    refused(store.commit(std::vector<RowChange>{bad_address}, std::nullopt, material.manifest(1), material.manifest(2)));
    auto bad_large = test::inserted(material.row(62, 3, payload(3)));
    bad_large.record.resize(record_maximum + 1);
    refused(store.commit(std::vector<RowChange>{bad_large}, std::nullopt, material.manifest(1), material.manifest(2)));
    auto bad_write = test::inserted(material.row(63, 4, payload(4)));
    bad_write.write = std::bit_cast<RowWrite>(std::uint8_t{0});
    refused(store.commit(std::vector<RowChange>{bad_write}, std::nullopt, material.manifest(1), material.manifest(2)));
    auto beyond = test::inserted(material.row(64, 5, payload(5)));
    beyond.slot = slot_bound + 1;
    refused(store.commit(std::vector<RowChange>{beyond}, std::nullopt, material.manifest(1), material.manifest(2)));
    refused(store.commit({}, std::nullopt, Bytes(sealed_manifest_size - 1), material.manifest(2)));
    refused(store.commit({}, Swap{.old_header = Bytes(140), .new_header = material.header(1)}, material.manifest(1), material.manifest(2)));
    EXPECT_EQ(store.opened().manifest, material.manifest(1));
    EXPECT_EQ(store.opened().header, material.header());

    Store moved = std::move(store);
    EXPECT_EQ(moved.opened().content, Content::vault);
    EXPECT_EQ(must(moved.body(row.slot)), std::optional<Bytes>(row.record));
}

TEST_P(VaultStore, ScansOnlyBetweenBeginAndTheLastRow)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto first = material.row(71, 1, payload(1));
    const auto second = material.row(72, 2, payload(2), "second");
    auto store = test::created(place, material, {first, second});
    must(store.begin_scan());
    ASSERT_TRUE(must(store.next_row()).has_value());
    EXPECT_EQ(must(store.body(second.slot)), std::optional<Bytes>(second.record));
    ASSERT_TRUE(must(store.next_row()).has_value());
    EXPECT_FALSE(must(store.next_row()).has_value());
    EXPECT_EQ(test::error_of(store.next_row()), Error::invalid_parameters);

    must(store.begin_scan());
    ASSERT_TRUE(must(store.next_row()).has_value());
    ASSERT_EQ(store.commit({}, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
    EXPECT_EQ(test::error_of(store.next_row()), Error::invalid_parameters);
    EXPECT_EQ(scanned(store).size(), 2U);
}

TEST_P(VaultStore, CallsANewerLayoutUnsupportedBeforeItLoadsTheSchema)
{
    const Place place(GetParam());
    static_cast<void>(test::created(place, Material::keystore(), {}));
    {
        const test::Side side(place);
        side.run("CREATE TABLE extra (x BLOB) STRICT");
        side.run("PRAGMA user_version = 2");
    }
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::unsupported_version);
    EXPECT_EQ(test::error_of(Store::open_new(place.path(), place.vfs())), Error::unsupported_version);
    {
        const test::Side side(place);
        side.run("PRAGMA user_version = 1");
    }
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::integrity);
    EXPECT_EQ(test::error_of(Store::open_new(place.path(), place.vfs())), Error::integrity);
}

TEST(VaultStoreLibrary, LoadsNoSchemaWithOneMoreObjectThanTheVaultHas)
{
    const Place place(Backing::memory);
    static_cast<void>(test::created(place, Material::keystore(), {}));
    EXPECT_TRUE(loads_schema_within(place, 4));
    EXPECT_FALSE(loads_schema_within(place, 3));
    {
        const test::Side side(place);
        side.run("CREATE TABLE extra (x BLOB) STRICT");
    }
    EXPECT_FALSE(loads_schema_within(place, 4));
    EXPECT_TRUE(loads_schema_within(place, 5));
}

TEST(VaultStoreMemory, KeepsEveryCommitThroughAPowerLoss)
{
    const Place place(Backing::memory);
    const auto& material = Material::keystore();
    const auto row = material.row(81, 1, payload(1));
    {
        auto store = must(Store::open_new(place.path(), place.vfs()));
        const std::vector<RowChange> rows{test::inserted(row)};
        ASSERT_EQ(store.initialise(material.header(), material.manifest(1), rows).outcome, Outcome::committed);
    }
    test::memory_vfs::lose_power();
    {
        auto store = must(Store::open_existing(place.path(), place.vfs()));
        EXPECT_EQ(store.opened().manifest, material.manifest(1));
        ASSERT_EQ(store.commit(std::vector<RowChange>{test::erased(row)}, std::nullopt, material.manifest(1), material.manifest(2))
                      .outcome,
            Outcome::committed);
    }
    test::memory_vfs::lose_power();
    {
        auto store = must(Store::open_existing(place.path(), place.vfs()));
        EXPECT_EQ(store.opened().manifest, material.manifest(2));
        EXPECT_TRUE(scanned(store).empty());
        ASSERT_EQ(store.commit({}, std::nullopt, material.manifest(2), material.manifest(3)).outcome, Outcome::committed);
        ASSERT_TRUE(store.checkpoint().has_value());
    }
    test::memory_vfs::lose_power();
    const auto store = must(Store::open_existing(place.path(), place.vfs()));
    EXPECT_EQ(store.opened().manifest, material.manifest(3));
}

TEST(VaultStoreMemory, ReportsAnUnknownOutcomeWhenTheCommitItselfFails)
{
    const auto& material = Material::keystore();
    for (const auto& [fault, error] : {std::pair{SQLITE_FULL, Error::storage_full}, std::pair{SQLITE_IOERR_WRITE, Error::storage}}) {
        const Place place(Backing::memory);
        {
            auto store = test::created(place, material, {});
            test::memory_vfs::inject(faults(0, fault));
            const auto result = store.commit({}, std::nullopt, material.manifest(1), material.manifest(2));
            EXPECT_EQ(result.outcome, Outcome::unknown);
            EXPECT_EQ(result.error, error);
            test::memory_vfs::inject(faults(0, 0));
        }
        const auto reopened = Store::open_existing(place.path(), place.vfs());
        ASSERT_TRUE(reopened.has_value());
        const auto& manifest = reopened->opened().manifest;
        EXPECT_TRUE(manifest == material.manifest(1) || manifest == material.manifest(2));
    }
    const Place place(Backing::memory);
    {
        auto store = must(Store::open_new(place.path(), place.vfs()));
        test::memory_vfs::inject(faults(0, SQLITE_FULL));
        const auto result = store.initialise(material.header(), material.manifest(1), {});
        EXPECT_EQ(result.outcome, Outcome::unknown);
        EXPECT_EQ(result.error, Error::storage_full);
        EXPECT_FALSE(detail::sealed(store));
        test::memory_vfs::inject(faults(0, 0));
    }
    const auto reopened = Store::open_existing(place.path(), place.vfs());
    EXPECT_TRUE(reopened.has_value() || reopened.error() == Error::no_vault);
}

TEST(VaultStoreMemory, RollsBackWhenAStatementCannotRead)
{
    const Place place(Backing::memory);
    const auto& material = Material::keystore();
    const auto row = material.row(91, 1, payload(1));
    const auto rewritten = material.row(91, 2, payload(2), "record", 1);
    static_cast<void>(test::created(place, material, {row}));
    {
        auto store = must(Store::open_existing(place.path(), place.vfs()));
        test::memory_vfs::inject(faults(SQLITE_IOERR_READ, 0));
        const std::vector<RowChange> rows{test::replaced(row, rewritten)};
        const auto result = store.commit(rows, std::nullopt, material.manifest(1), material.manifest(2));
        test::memory_vfs::inject(faults(0, 0));
        EXPECT_EQ(result.outcome, Outcome::rolled_back);
        EXPECT_EQ(result.error, Error::storage);
        EXPECT_EQ(store.opened().manifest, material.manifest(1));
        EXPECT_EQ(store.commit(rows, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
    }
    auto store = must(Store::open_existing(place.path(), place.vfs()));
    EXPECT_EQ(store.opened().manifest, material.manifest(2));
    EXPECT_EQ(must(store.body(row.slot)), std::optional<Bytes>(rewritten.record));
}

TEST(VaultStoreMemory, WritesNothingWhileOpeningAndCountsEveryChange)
{
    const Place place(Backing::memory);
    const auto before = test::memory_vfs::operations();
    static_cast<void>(test::created(place, Material::keystore(), {}));
    const auto created = test::memory_vfs::operations();
    EXPECT_GT(created, before);
    const auto files = test::memory_vfs::files();
    {
        const auto store = must(Store::open_existing(place.path(), place.vfs()));
        EXPECT_EQ(store.opened().content, Content::vault);
        EXPECT_EQ(test::memory_vfs::operations(), created);
    }
    EXPECT_EQ(test::memory_vfs::operations(), created);
    EXPECT_EQ(test::memory_vfs::files(), files);
    EXPECT_EQ(test::memory_vfs::open_files(), 0U);
    test::memory_vfs::count_operation();
    EXPECT_EQ(test::memory_vfs::operations(), created + 1);
}

TEST_P(VaultStore, RefusesTheNoncesOfAnotherLiveRow)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto first = material.row(101, 1, payload(1), "first");
    const auto second = material.row(102, 2, payload(2), "second");
    const auto second_next = material.row(102, 3, payload(3), "second", 1);
    auto store = test::created(place, material, {first, second});
    const auto refused = [&](const RowChange& row) {
        const auto result = store.commit(std::vector<RowChange>{row}, std::nullopt, material.manifest(1), material.manifest(2));
        EXPECT_EQ(result.outcome, Outcome::mismatch);
        EXPECT_EQ(result.error, Error::integrity);
    };
    auto address_rewrite = test::replaced(second, second_next);
    address_rewrite.old_address_nonce = test::leading_nonce(first.address);
    refused(address_rewrite);
    auto record_rewrite = test::replaced(second, second_next);
    record_rewrite.old_record_nonce = test::leading_nonce(first.record);
    refused(record_rewrite);
    auto address_erase = test::erased(second);
    address_erase.old_address_nonce = test::leading_nonce(first.address);
    refused(address_erase);
    auto record_erase = test::erased(second);
    record_erase.old_record_nonce = test::leading_nonce(first.record);
    refused(record_erase);

    EXPECT_EQ(store.opened().manifest, material.manifest(1));
    const std::map<std::uint64_t, Bytes> expected{{first.slot, first.address}, {second.slot, second.address}};
    EXPECT_EQ(scanned(store), expected);
    EXPECT_EQ(must(store.body(first.slot)), std::optional<Bytes>(first.record));
    EXPECT_EQ(must(store.body(second.slot)), std::optional<Bytes>(second.record));
}

TEST_P(VaultStore, RestartsAScanThatWasLeftOpen)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    auto store = test::created(place, material, {material.row(111, 1, payload(1)), material.row(112, 2, payload(2), "second")});
    must(store.begin_scan());
    ASSERT_TRUE(must(store.next_row()).has_value());
    EXPECT_EQ(scanned(store).size(), 2U);
}

TEST_P(VaultStore, CheckpointsDuringAScanAndEndsIt)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    auto store = test::created(place, material, {material.row(121, 1, payload(1)), material.row(122, 2, payload(2), "second")});
    ASSERT_EQ(store.commit({}, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
    ASSERT_GT(size_of(place, "-wal"), 0U);
    must(store.begin_scan());
    ASSERT_TRUE(must(store.next_row()).has_value());
    EXPECT_TRUE(store.checkpoint().has_value());
    EXPECT_EQ(size_of(place, "-wal"), 0U);
    EXPECT_EQ(test::error_of(store.next_row()), Error::invalid_parameters);
}

TEST_P(VaultStore, EndsTheScanAtAMalformedRow)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    static_cast<void>(test::created(place, material, {material.row(131, 1, payload(1)), material.row(132, 2, payload(2), "second")}));
    {
        const test::Side side(place);
        side.run("PRAGMA ignore_check_constraints = ON");
        side.run("UPDATE record SET address = zeroblob(137) WHERE slot = 131");
    }
    auto store = must(Store::open_existing(place.path(), place.vfs()));
    must(store.begin_scan());
    EXPECT_EQ(test::error_of(store.next_row()), Error::integrity);
    EXPECT_EQ(test::error_of(store.next_row()), Error::invalid_parameters);
}

TEST(VaultStoreMemory, WritesNothingWhileOpeningAVaultWithACommittedLog)
{
    const Place place(Backing::memory);
    const auto& material = Material::keystore();
    {
        auto store = test::created(place, material, {material.row(141, 1, payload(1))});
        ASSERT_EQ(store.commit({}, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
    }
    ASSERT_GT(size_of(place, "-wal"), 0U);
    const auto operations = test::memory_vfs::operations();
    const auto files = test::memory_vfs::files();
    {
        const auto store = must(Store::open_existing(place.path(), place.vfs()));
        EXPECT_EQ(store.opened().manifest, material.manifest(2));
        EXPECT_EQ(test::memory_vfs::operations(), operations);
        EXPECT_EQ(test::memory_vfs::files(), files);
    }
    EXPECT_EQ(test::memory_vfs::operations(), operations);
    EXPECT_EQ(test::memory_vfs::files(), files);
}

TEST(VaultStoreMemory, WaitsTwoSecondsForAConnectionThatHoldsTheFile)
{
    const Place place(Backing::memory);
    const auto store = test::created(place, Material::keystore(), {});
    const auto before = test::memory_vfs::slept();
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::busy);
    EXPECT_EQ(test::memory_vfs::slept() - before, busy_microseconds);
}

TEST(VaultStoreMemory, OpensOnceAConnectionThatWasClosingLetsGo)
{
    const Place place(Backing::memory);
    static_cast<void>(test::created(place, Material::keystore(), {}));
    const auto before = test::memory_vfs::slept();
    test::memory_vfs::inject(faults(0, 0, 0, 3));
    const auto store = Store::open_existing(place.path(), place.vfs());
    test::memory_vfs::inject(faults(0, 0));
    ASSERT_TRUE(store.has_value());
    EXPECT_EQ(store->opened().content, Content::vault);
    EXPECT_GT(test::memory_vfs::slept(), before);
    EXPECT_LT(test::memory_vfs::slept() - before, busy_microseconds);
}

TEST(VaultStoreMemory, KeepsReadErrorsWhenItSalvages)
{
    const Place place(Backing::memory);
    const auto& material = Material::keystore();
    const auto row = material.row(151, 1, payload(1));
    static_cast<void>(test::created(place, material, {row}));
    auto store = must(Store::open_existing(place.path(), place.vfs()));
    test::memory_vfs::inject(faults(SQLITE_IOERR_READ, 0));
    const auto salvaged = store.salvage_body(row.slot);
    test::memory_vfs::inject(faults(0, 0));
    EXPECT_EQ(test::error_of(salvaged), Error::storage);
    EXPECT_EQ(must(store.salvage_body(row.slot)), std::optional<Bytes>(row.record));
}

TEST(VaultStoreMemory, ReportsAFileItCannotOpenAsStorage)
{
    const Place place(Backing::memory);
    test::memory_vfs::inject(faults(0, 0, SQLITE_CANTOPEN));
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::no_vault);
    test::memory_vfs::inject(faults(0, 0));
    static_cast<void>(test::created(place, Material::keystore(), {}));
    test::memory_vfs::inject(faults(0, 0, SQLITE_CANTOPEN));
    EXPECT_EQ(test::error_of(Store::open_existing(place.path(), place.vfs())), Error::storage);
    EXPECT_EQ(test::error_of(Store::open_new(place.path(), place.vfs())), Error::storage);
    test::memory_vfs::inject(faults(0, 0));
    EXPECT_TRUE(Store::open_existing(place.path(), place.vfs()).has_value());
}

}
}
