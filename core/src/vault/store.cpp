// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/store.hpp"

#include "lume/wire/structures.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace lume::vault {
namespace {

constexpr int minimum_library = 3054001;
constexpr std::int64_t application_id = 0x4C554D56;
constexpr std::int64_t layout_version = 1;
constexpr int busy_milliseconds = 2000;
constexpr int primary_code = 0xff;
constexpr std::size_t header_size = 139;
constexpr std::size_t tpm_header_size = header_size + wire::tpm_point_size;

static_assert(SQLITE_VERSION_NUMBER >= minimum_library);
static_assert(tpm_header_size == 204);
static_assert(sealed_manifest_size == 1235);
static_assert(sealed_address_size == 138);
static_assert(record_minimum == 296);
static_assert(record_maximum == 131112);
static_assert(slot_bound == 9223372036854775807ULL);
static_assert(crypto::aead_nonce_size == 24);

constexpr std::string_view vault_table = "CREATE TABLE vault (id INTEGER PRIMARY KEY CHECK (id = 1), "
                                         "header BLOB NOT NULL CHECK (length(header) IN (139, 204)), "
                                         "manifest BLOB NOT NULL CHECK (length(manifest) = 1235)) STRICT";
constexpr std::string_view record_table = "CREATE TABLE record (slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 9223372036854775807), "
                                          "address BLOB NOT NULL CHECK (length(address) = 138)) STRICT";
constexpr std::string_view body_table = "CREATE TABLE body (slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 9223372036854775807), "
                                        "record BLOB NOT NULL CHECK (length(record) BETWEEN 296 AND 131112)) STRICT";
constexpr std::string_view insert_vault = "INSERT INTO vault (id, header, manifest) VALUES (1, ?1, ?2)";
constexpr std::string_view read_schema = "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name";

struct SchemaRow {
    std::string_view name;
    std::string_view sql;
};

constexpr std::array<SchemaRow, 3> schema{{
    {.name = "body", .sql = body_table},
    {.name = "record", .sql = record_table},
    {.name = "vault", .sql = vault_table},
}};
constexpr std::array<std::string_view, 3> tables{vault_table, record_table, body_table};

enum class Sql : std::uint8_t {
    vault_row,
    scan,
    body,
    insert_address,
    insert_body,
    replace_address,
    replace_body,
    erase_address,
    erase_body,
    swap_manifest,
    swap_header,
    wipe,
    begin,
    commit,
    rollback,
};

constexpr std::size_t statement_count = 15;
constexpr std::size_t read_statements = 3;

constexpr std::array<std::string_view, statement_count> statement_text{
    "SELECT header, manifest FROM vault WHERE id = 1",
    "SELECT slot, address FROM record",
    "SELECT record FROM body WHERE slot = ?1",
    "INSERT INTO record (slot, address) VALUES (?1, ?2)",
    "INSERT INTO body (slot, record) VALUES (?1, ?2)",
    "UPDATE record SET address = ?2 WHERE slot = ?1 AND substr(address, 1, 24) = ?3",
    "UPDATE body SET record = ?2 WHERE slot = ?1 AND substr(record, 1, 24) = ?3",
    "DELETE FROM record WHERE slot = ?1 AND substr(address, 1, 24) = ?2",
    "DELETE FROM body WHERE slot = ?1 AND substr(record, 1, 24) = ?2",
    "UPDATE vault SET manifest = ?1 WHERE id = 1 AND manifest = ?2",
    "UPDATE vault SET header = ?1, manifest = ?2 WHERE id = 1 AND header = ?3 AND manifest = ?4",
    "UPDATE vault SET header = zeroblob(length(header)), manifest = zeroblob(length(manifest)) WHERE id = 1",
    "BEGIN IMMEDIATE",
    "COMMIT",
    "ROLLBACK",
};

constexpr std::size_t index_of(Sql sql) noexcept
{
    return static_cast<std::size_t>(sql);
}

static_assert(index_of(Sql::rollback) + 1 == statement_count);
static_assert(index_of(Sql::body) + 1 == read_statements);

struct Option {
    int code = 0;
    int value = 0;
};

constexpr std::array<Option, 14> options{{
    {.code = SQLITE_DBCONFIG_DEFENSIVE, .value = 1},
    {.code = SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, .value = 1},
    {.code = SQLITE_DBCONFIG_TRUSTED_SCHEMA, .value = 0},
    {.code = SQLITE_DBCONFIG_ENABLE_TRIGGER, .value = 0},
    {.code = SQLITE_DBCONFIG_ENABLE_VIEW, .value = 0},
    {.code = SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, .value = 0},
    {.code = SQLITE_DBCONFIG_DQS_DML, .value = 0},
    {.code = SQLITE_DBCONFIG_DQS_DDL, .value = 0},
    {.code = SQLITE_DBCONFIG_ENABLE_FKEY, .value = 0},
    {.code = SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, .value = 0},
    {.code = SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, .value = 0},
    {.code = SQLITE_DBCONFIG_WRITABLE_SCHEMA, .value = 0},
    {.code = SQLITE_DBCONFIG_LEGACY_ALTER_TABLE, .value = 0},
    {.code = SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, .value = 0},
}};

constexpr std::array<Option, 13> limits{{
    {.code = SQLITE_LIMIT_LENGTH, .value = 262144},
    {.code = SQLITE_LIMIT_SQL_LENGTH, .value = 4096},
    {.code = SQLITE_LIMIT_COLUMN, .value = 8},
    {.code = SQLITE_LIMIT_EXPR_DEPTH, .value = 32},
    {.code = SQLITE_LIMIT_PARSER_DEPTH, .value = 64},
    {.code = SQLITE_LIMIT_COMPOUND_SELECT, .value = 1},
    {.code = SQLITE_LIMIT_FUNCTION_ARG, .value = 3},
    {.code = SQLITE_LIMIT_ATTACHED, .value = 0},
    {.code = SQLITE_LIMIT_VARIABLE_NUMBER, .value = 8},
    {.code = SQLITE_LIMIT_TRIGGER_DEPTH, .value = 1},
    {.code = SQLITE_LIMIT_TRIGGER_STEPS, .value = 1},
    {.code = SQLITE_LIMIT_WORKER_THREADS, .value = 0},
    {.code = SQLITE_LIMIT_SCHEMA, .value = 4},
}};

struct Pragma {
    std::string_view name;
    std::string_view set;
    std::string_view query;
    std::string_view expected;
};

constexpr std::array<Pragma, 7> reading_pragmas{{
    {.name = "pragma.secure_delete", .set = "PRAGMA secure_delete = ON", .query = "PRAGMA secure_delete", .expected = "1"},
    {.name = "pragma.cell_size_check",
        .set = "PRAGMA cell_size_check = ON",
        .query = "PRAGMA cell_size_check",
        .expected = "1"},
    {.name = "pragma.mmap_size", .set = "PRAGMA mmap_size = 0", .query = "PRAGMA mmap_size", .expected = "0"},
    {.name = "pragma.temp_store", .set = "PRAGMA temp_store = MEMORY", .query = "PRAGMA temp_store", .expected = "2"},
    {.name = "pragma.trusted_schema",
        .set = "PRAGMA trusted_schema = OFF",
        .query = "PRAGMA trusted_schema",
        .expected = "0"},
    {.name = "pragma.foreign_keys", .set = "PRAGMA foreign_keys = OFF", .query = "PRAGMA foreign_keys", .expected = "0"},
    {.name = "pragma.wal_autocheckpoint",
        .set = "PRAGMA wal_autocheckpoint = 0",
        .query = "PRAGMA wal_autocheckpoint",
        .expected = "0"},
}};

constexpr Pragma synchronous{
    .name = "pragma.synchronous", .set = "PRAGMA synchronous = FULL", .query = "PRAGMA synchronous", .expected = "2"};

constexpr std::string_view exclusive = "exclusive";
constexpr std::string_view wal = "wal";
constexpr std::string_view page_size = "4096";
constexpr std::string_view incremental = "2";
constexpr std::string_view busy_wait = "2000";

struct CloseDatabase {
    void operator()(sqlite3* database) const noexcept
    {
        static_cast<void>(sqlite3_close_v2(database));
    }
};

struct FinalizeStatement {
    void operator()(sqlite3_stmt* statement) const noexcept
    {
        static_cast<void>(sqlite3_finalize(statement));
    }
};

using Database = std::unique_ptr<sqlite3, CloseDatabase>;
using Statement = std::unique_ptr<sqlite3_stmt, FinalizeStatement>;

enum class Fault : std::uint8_t {
    full,
    io,
    busy,
    data,
};

Fault fault_of(int code) noexcept
{
    switch (code & primary_code) {
    case SQLITE_FULL:
        return Fault::full;
    case SQLITE_BUSY:
    case SQLITE_LOCKED:
        return Fault::busy;
    case SQLITE_IOERR:
    case SQLITE_CANTOPEN:
    case SQLITE_NOMEM:
    case SQLITE_READONLY:
    case SQLITE_PERM:
    case SQLITE_PROTOCOL:
    case SQLITE_NOLFS:
        return Fault::io;
    default:
        return Fault::data;
    }
}

Error error_of(int code) noexcept
{
    switch (fault_of(code)) {
    case Fault::full:
        return Error::storage_full;
    case Fault::io:
        return Error::storage;
    case Fault::busy:
        return Error::busy;
    case Fault::data:
        break;
    }
    return Error::integrity;
}

Error write_error_of(int code) noexcept
{
    return fault_of(code) == Fault::full ? Error::storage_full : Error::storage;
}

CommitResult refused() noexcept
{
    return CommitResult{.outcome = Outcome::rolled_back, .error = Error::invalid_parameters};
}

bool library_matches() noexcept
{
    const int version = sqlite3_libversion_number();
    return version == SQLITE_VERSION_NUMBER && version >= minimum_library && sqlite3_threadsafe() != 0
        && sqlite3_compileoption_used("OMIT_LOAD_EXTENSION") == 1;
}

bool valid_path(std::string_view path) noexcept
{
    return !path.empty() && !path.contains('\0') && path != ":memory:";
}

bool valid_header(crypto::ByteView header) noexcept
{
    return header.size() == header_size || header.size() == tpm_header_size;
}

bool valid_row(const RowChange& row) noexcept
{
    if (row.slot == 0 || row.slot > slot_bound) {
        return false;
    }
    switch (row.write) {
    case RowWrite::insert:
    case RowWrite::replace:
        return row.address.size() == sealed_address_size && row.record.size() >= record_minimum
            && row.record.size() <= record_maximum;
    case RowWrite::erase:
        return true;
    }
    return false;
}

int authorise(void* sealed, [[maybe_unused]] int action, [[maybe_unused]] const char* first,
    [[maybe_unused]] const char* second, [[maybe_unused]] const char* database, [[maybe_unused]] const char* trigger) noexcept
{
    return static_cast<const std::atomic<bool>*>(sealed)->load() ? SQLITE_DENY : SQLITE_OK;
}

int prepare_into(sqlite3* database, std::string_view sql, unsigned int flags, Statement& statement)
{
    sqlite3_stmt* raw = nullptr;
    const char* tail = nullptr;
    const int code = sqlite3_prepare_v3(database, sql.data(), static_cast<int>(sql.size()), flags, &raw, &tail);
    statement.reset(raw);
    if (code != SQLITE_OK) {
        return code;
    }
    if (statement == nullptr || tail != std::to_address(sql.end())) {
        statement.reset();
        return SQLITE_MISUSE;
    }
    return SQLITE_OK;
}

Result<Statement> prepare(sqlite3* database, std::string_view sql, unsigned int flags)
{
    Statement statement;
    const int code = prepare_into(database, sql, flags, statement);
    if (code == SQLITE_MISUSE) {
        return std::unexpected(Error::library_failure);
    }
    if (code != SQLITE_OK) {
        return std::unexpected(error_of(code));
    }
    return statement;
}

class Use {
public:
    explicit Use(sqlite3_stmt* statement) noexcept
        : statement_(statement)
    {
    }

    Use(const Use&) = delete;
    Use& operator=(const Use&) = delete;
    Use(Use&&) = delete;
    Use& operator=(Use&&) = delete;

    ~Use()
    {
        static_cast<void>(sqlite3_reset(statement_));
        static_cast<void>(sqlite3_clear_bindings(statement_));
    }

private:
    sqlite3_stmt* statement_;
};

int bind_at(sqlite3_stmt* statement, int index, crypto::ByteView bytes) noexcept
{
    return sqlite3_bind_blob64(statement, index, bytes.data(), bytes.size(), nullptr);
}

int bind_at(sqlite3_stmt* statement, int index, std::uint64_t slot) noexcept
{
    return sqlite3_bind_int64(statement, index, static_cast<sqlite3_int64>(slot));
}

int bind_all([[maybe_unused]] sqlite3_stmt* statement) noexcept
{
    return SQLITE_OK;
}

template <typename... Values>
int bind_all(sqlite3_stmt* statement, const Values&... values) noexcept
{
    int index = 0;
    int code = SQLITE_OK;
    const auto next = [&](const auto& value) noexcept {
        if (code == SQLITE_OK) {
            code = bind_at(statement, ++index, value);
        }
    };
    (next(values), ...);
    return code;
}

std::optional<crypto::ByteView> blob_at(sqlite3_stmt* statement, int column, std::size_t minimum, std::size_t maximum) noexcept
{
    if (sqlite3_column_type(statement, column) != SQLITE_BLOB) {
        return std::nullopt;
    }
    const void* data = sqlite3_column_blob(statement, column);
    const int size = sqlite3_column_bytes(statement, column);
    if (data == nullptr || size < 0) {
        return std::nullopt;
    }
    const auto length = static_cast<std::size_t>(size);
    if (length < minimum || length > maximum) {
        return std::nullopt;
    }
    return crypto::ByteView(static_cast<const std::uint8_t*>(data), length);
}

std::optional<std::span<const unsigned char>> text_at(sqlite3_stmt* statement, int column) noexcept
{
    if (sqlite3_column_type(statement, column) != SQLITE_TEXT) {
        return std::nullopt;
    }
    const unsigned char* text = sqlite3_column_text(statement, column);
    const int size = sqlite3_column_bytes(statement, column);
    if (text == nullptr || size < 0) {
        return std::nullopt;
    }
    return std::span(text, static_cast<std::size_t>(size));
}

bool text_is(sqlite3_stmt* statement, int column, std::string_view expected) noexcept
{
    const auto text = text_at(statement, column);
    return text.has_value() && std::ranges::equal(*text, expected, [](unsigned char letter, char wanted) {
        return letter == static_cast<unsigned char>(wanted);
    });
}

std::optional<std::string> value_at(sqlite3_stmt* statement, int column)
{
    if (sqlite3_column_type(statement, column) == SQLITE_INTEGER) {
        return std::to_string(sqlite3_column_int64(statement, column));
    }
    const auto text = text_at(statement, column);
    if (!text) {
        return std::nullopt;
    }
    std::string value;
    value.reserve(text->size());
    std::ranges::transform(*text, std::back_inserter(value), [](unsigned char letter) { return static_cast<char>(letter); });
    return value;
}

Result<std::string> query(sqlite3* database, std::string_view sql)
{
    const auto statement = prepare(database, sql, 0);
    if (!statement) {
        return std::unexpected(statement.error());
    }
    const int first = sqlite3_step(statement->get());
    if (first != SQLITE_ROW) {
        return std::unexpected(first == SQLITE_DONE ? Error::library_failure : error_of(first));
    }
    auto value = value_at(statement->get(), 0);
    if (!value) {
        return std::unexpected(Error::library_failure);
    }
    const int last = sqlite3_step(statement->get());
    if (last != SQLITE_DONE) {
        return std::unexpected(last == SQLITE_ROW ? Error::library_failure : error_of(last));
    }
    return std::move(*value);
}

Result<void> execute(sqlite3* database, std::string_view sql)
{
    const auto statement = prepare(database, sql, 0);
    if (!statement) {
        return std::unexpected(statement.error());
    }
    for (;;) {
        const int code = sqlite3_step(statement->get());
        if (code == SQLITE_DONE) {
            return {};
        }
        if (code != SQLITE_ROW) {
            return std::unexpected(error_of(code));
        }
    }
}

std::optional<std::int64_t> number_of(std::string_view text) noexcept
{
    std::int64_t number = 0;
    const auto* const first = std::to_address(text.begin());
    const auto* const last = std::to_address(text.end());
    const auto [end, problem] = std::from_chars(first, last, number);
    if (problem != std::errc{} || end != last) {
        return std::nullopt;
    }
    return number;
}

std::optional<std::string> full_path(sqlite3_vfs* system, std::string_view path)
{
    if (system->mxPathname <= 0) {
        return std::nullopt;
    }
    const std::string name(path);
    std::string full(static_cast<std::size_t>(system->mxPathname) + 1, '\0');
    if (system->xFullPathname(system, name.c_str(), system->mxPathname + 1, full.data()) != SQLITE_OK) {
        return std::nullopt;
    }
    if (const auto end = full.find('\0'); end != std::string::npos) {
        full.resize(end);
    }
    return full;
}

bool present(sqlite3_vfs* system, const std::string& full, int flags)
{
    int found = 0;
    return system->xAccess(system, full.c_str(), flags, &found) != SQLITE_OK || found != 0;
}

bool exists(sqlite3_vfs* system, std::string_view path)
{
    const auto full = full_path(system, path);
    return !full || present(system, *full, SQLITE_ACCESS_EXISTS) || present(system, *full, SQLITE_ACCESS_READWRITE);
}

Result<void> configure(sqlite3* database)
{
    for (const auto& option : options) {
        int value = -1;
        if (std::invoke(sqlite3_db_config, database, option.code, option.value, &value) != SQLITE_OK || value != option.value) {
            return std::unexpected(Error::library_failure);
        }
    }
    for (const auto& limit : limits) {
        static_cast<void>(sqlite3_limit(database, limit.code, limit.value));
        if (sqlite3_limit(database, limit.code, -1) != limit.value) {
            return std::unexpected(Error::library_failure);
        }
    }
    if (sqlite3_busy_timeout(database, busy_milliseconds) != SQLITE_OK) {
        return std::unexpected(Error::library_failure);
    }
    return {};
}

int db_config_of(sqlite3* database, int option)
{
    int value = -1;
    static_cast<void>(std::invoke(sqlite3_db_config, database, option, -1, &value));
    return value;
}

struct Schema {
    std::size_t rows = 0;
    bool matches = true;
};

Result<Schema> schema_of(sqlite3* database)
{
    const auto statement = prepare(database, read_schema, 0);
    if (!statement) {
        return std::unexpected(statement.error());
    }
    Schema found;
    for (;;) {
        const int code = sqlite3_step(statement->get());
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW) {
            return std::unexpected(error_of(code));
        }
        if (found.rows < schema.size()) {
            const auto& expected = schema.at(found.rows);
            found.matches = found.matches && text_is(statement->get(), 0, "table") && text_is(statement->get(), 1, expected.name)
                && text_is(statement->get(), 2, expected.name) && text_is(statement->get(), 3, expected.sql);
        }
        ++found.rows;
    }
    found.matches = found.matches && found.rows == schema.size();
    return found;
}

struct Identity {
    std::string application;
    std::string version;
    std::string page;
    std::string vacuum;
    Schema tables;
};

Result<void> read_into(sqlite3* database, std::initializer_list<std::pair<std::string*, std::string_view>> fields)
{
    for (const auto& [field, sql] : fields) {
        auto value = query(database, sql);
        if (!value) {
            return std::unexpected(value.error());
        }
        *field = std::move(*value);
    }
    return {};
}

Result<Identity> stamp_of(sqlite3* database)
{
    Identity identity;
    if (const auto read = read_into(database,
            {std::pair{&identity.application, "PRAGMA application_id"}, std::pair{&identity.version, "PRAGMA user_version"}});
        !read) {
        return std::unexpected(read.error());
    }
    const auto version = number_of(identity.version);
    if (identity.application == std::to_string(application_id) && version && *version > layout_version) {
        return std::unexpected(Error::unsupported_version);
    }
    return identity;
}

Result<void> complete(sqlite3* database, Identity& identity)
{
    if (const auto read = read_into(
            database, {std::pair{&identity.page, "PRAGMA page_size"}, std::pair{&identity.vacuum, "PRAGMA auto_vacuum"}});
        !read) {
        return read;
    }
    const auto found = schema_of(database);
    if (!found) {
        return std::unexpected(found.error());
    }
    identity.tables = *found;
    return {};
}

Result<Content> content_of(const Identity& identity, std::string_view journal)
{
    if (identity.tables.rows == 0 && identity.application == "0" && identity.version == "0") {
        return Content::empty;
    }
    if (identity.application == std::to_string(application_id) && number_of(identity.version) == layout_version
        && journal == wal && identity.page == page_size && identity.vacuum == incremental && identity.tables.matches) {
        return Content::vault;
    }
    return std::unexpected(Error::integrity);
}

Result<Opened> vault_row(sqlite3_stmt* statement)
{
    const Use use(statement);
    const int code = sqlite3_step(statement);
    if (code != SQLITE_ROW) {
        return std::unexpected(code == SQLITE_DONE ? Error::integrity : error_of(code));
    }
    const auto header = blob_at(statement, 0, header_size, tpm_header_size);
    const auto manifest = blob_at(statement, 1, sealed_manifest_size, sealed_manifest_size);
    if (!header || !valid_header(*header) || !manifest) {
        return std::unexpected(Error::integrity);
    }
    Opened opened{.content = Content::vault,
        .header = crypto::Bytes(header->begin(), header->end()),
        .manifest = crypto::Bytes(manifest->begin(), manifest->end())};
    const int last = sqlite3_step(statement);
    if (last != SQLITE_DONE) {
        return std::unexpected(last == SQLITE_ROW ? Error::integrity : error_of(last));
    }
    if (std::ranges::all_of(opened.header, [](std::uint8_t byte) { return byte == 0; })) {
        return std::unexpected(Error::wiped);
    }
    return opened;
}

class Batch {
public:
    explicit Batch(sqlite3* database) noexcept
        : database_(database)
    {
    }

    [[nodiscard]] bool failed() const noexcept
    {
        return mismatch_ || code_ != SQLITE_OK;
    }

    [[nodiscard]] bool mismatched() const noexcept
    {
        return mismatch_;
    }

    [[nodiscard]] int code() const noexcept
    {
        return code_;
    }

    void fail(int code) noexcept
    {
        if (fault_of(code) == Fault::data) {
            mismatch_ = true;
        } else if (code_ == SQLITE_OK) {
            code_ = code;
        }
    }

    void run(sqlite3_stmt* statement) noexcept
    {
        if (failed()) {
            return;
        }
        const Use use(statement);
        if (const int code = sqlite3_step(statement); code != SQLITE_DONE) {
            fail(code);
        }
    }

    void execute(std::string_view sql)
    {
        if (failed()) {
            return;
        }
        Statement statement;
        if (const int code = prepare_into(database_, sql, 0, statement); code != SQLITE_OK) {
            fail(code);
            return;
        }
        run(statement.get());
    }

    template <typename... Values>
    void write(sqlite3_stmt* statement, const Values&... values) noexcept
    {
        if (failed()) {
            return;
        }
        const Use use(statement);
        if (const int bound = bind_all(statement, values...); bound != SQLITE_OK) {
            fail(bound);
            return;
        }
        if (const int code = sqlite3_step(statement); code != SQLITE_DONE) {
            fail(code);
            return;
        }
        if (sqlite3_changes64(database_) != 1) {
            mismatch_ = true;
        }
    }

private:
    sqlite3* database_;
    int code_ = SQLITE_OK;
    bool mismatch_ = false;
};

}

struct Store::Connection {
    [[nodiscard]] Result<void> open(std::string_view path, const char* vfs, bool create)
    {
        if (const auto opened_file = open_file(path, vfs, create); !opened_file) {
            return opened_file;
        }
        if (const auto hardened = harden(); !hardened) {
            return hardened;
        }
        auto identity = stamp_of(db());
        if (!identity) {
            return std::unexpected(identity.error());
        }
        const auto journal = query(db(), "PRAGMA journal_mode");
        if (!journal) {
            return std::unexpected(journal.error());
        }
        return create ? continue_new(*journal, *identity) : continue_existing(*journal, *identity);
    }

    [[nodiscard]] const Opened& opened() const noexcept
    {
        return opened_;
    }

    [[nodiscard]] Result<void> begin_scan()
    {
        if (!holds_vault()) {
            return std::unexpected(Error::invalid_parameters);
        }
        stop_reading();
        scanning_ = true;
        return {};
    }

    [[nodiscard]] Result<std::optional<ScannedRow>> next_row()
    {
        if (!holds_vault() || !scanning_) {
            return std::unexpected(Error::invalid_parameters);
        }
        sqlite3_stmt* scan = statement(Sql::scan);
        const auto stop = [this](Error error) -> Result<std::optional<ScannedRow>> {
            stop_reading();
            return std::unexpected(error);
        };
        const int code = sqlite3_step(scan);
        if (code == SQLITE_DONE) {
            stop_reading();
            return std::optional<ScannedRow>{};
        }
        if (code != SQLITE_ROW) {
            return stop(error_of(code));
        }
        if (sqlite3_column_type(scan, 0) != SQLITE_INTEGER) {
            return stop(Error::integrity);
        }
        const sqlite3_int64 slot = sqlite3_column_int64(scan, 0);
        const auto address = blob_at(scan, 1, sealed_address_size, sealed_address_size);
        if (slot < 1 || !address) {
            return stop(Error::integrity);
        }
        return std::optional<ScannedRow>(ScannedRow{.slot = static_cast<std::uint64_t>(slot), .address = *address});
    }

    [[nodiscard]] Result<std::optional<crypto::Bytes>> read_body(std::uint64_t slot, bool salvage) const
    {
        if (!holds_vault() || slot == 0 || slot > slot_bound) {
            return std::unexpected(Error::invalid_parameters);
        }
        sqlite3_stmt* read = statement(Sql::body);
        const Use use(read);
        const auto refuse = [salvage](int code) -> Result<std::optional<crypto::Bytes>> {
            if (salvage && fault_of(code) == Fault::data) {
                return std::optional<crypto::Bytes>{};
            }
            return std::unexpected(error_of(code));
        };
        if (const int bound = bind_at(read, 1, slot); bound != SQLITE_OK) {
            return refuse(bound);
        }
        const int code = sqlite3_step(read);
        if (code == SQLITE_DONE) {
            return std::optional<crypto::Bytes>{};
        }
        if (code != SQLITE_ROW) {
            return refuse(code);
        }
        const auto record = blob_at(read, 0, record_minimum, record_maximum);
        if (!record) {
            return refuse(SQLITE_CORRUPT);
        }
        crypto::Bytes copy(record->begin(), record->end());
        if (const int last = sqlite3_step(read); last != SQLITE_DONE) {
            return refuse(last == SQLITE_ROW ? SQLITE_CORRUPT : last);
        }
        return std::optional<crypto::Bytes>(std::move(copy));
    }

    [[nodiscard]] CommitResult initialise(crypto::ByteView header, crypto::ByteView manifest, std::span<const RowChange> rows)
    {
        const auto inserts = [](const RowChange& row) { return row.write == RowWrite::insert && valid_row(row); };
        if (opened_.content != Content::empty || !valid_header(header) || manifest.size() != sealed_manifest_size
            || !std::ranges::all_of(rows, inserts)) {
            return refused();
        }
        Opened next{.content = Content::vault,
            .header = crypto::Bytes(header.begin(), header.end()),
            .manifest = crypto::Bytes(manifest.begin(), manifest.end())};
        const auto set_application = "PRAGMA application_id = " + std::to_string(application_id);
        const auto set_version = "PRAGMA user_version = " + std::to_string(layout_version);
        const auto result = transact([&](Batch& batch) {
            for (const auto table : tables) {
                batch.execute(table);
            }
            prepare_in(batch, 0, index_of(Sql::begin));
            Statement vault;
            if (const int code = prepare_into(db(), insert_vault, 0, vault); code != SQLITE_OK) {
                batch.fail(code);
                return;
            }
            batch.write(vault.get(), header, manifest);
            for (const auto& row : rows) {
                write_row(batch, row);
            }
            batch.execute(set_application);
            batch.execute(set_version);
        });
        if (result.outcome == Outcome::committed) {
            opened_ = std::move(next);
            seal();
        } else {
            for (auto& table_statement : statements_ | std::views::take(index_of(Sql::begin))) {
                table_statement.reset();
            }
        }
        return result;
    }

    [[nodiscard]] CommitResult commit(
        std::span<const RowChange> rows, std::optional<Swap> header, crypto::ByteView old_manifest, crypto::ByteView new_manifest)
    {
        const auto valid_swap = !header || (valid_header(header->old_header) && valid_header(header->new_header));
        if (!holds_vault() || !std::ranges::all_of(rows, valid_row) || !valid_swap || old_manifest.size() != sealed_manifest_size
            || new_manifest.size() != sealed_manifest_size) {
            return refused();
        }
        crypto::Bytes next_header = header ? crypto::Bytes(header->new_header.begin(), header->new_header.end()) : opened_.header;
        crypto::Bytes next_manifest(new_manifest.begin(), new_manifest.end());
        const auto result = transact([&](Batch& batch) {
            for (const auto& row : rows) {
                write_row(batch, row);
            }
            if (header) {
                batch.write(statement(Sql::swap_header), header->new_header, new_manifest, header->old_header, old_manifest);
            } else {
                batch.write(statement(Sql::swap_manifest), new_manifest, old_manifest);
            }
        });
        if (result.outcome == Outcome::committed) {
            opened_.header.swap(next_header);
            opened_.manifest.swap(next_manifest);
        }
        return result;
    }

    [[nodiscard]] CommitResult mark_wiped()
    {
        if (!holds_vault()) {
            return refused();
        }
        const auto result = transact([this](Batch& batch) { batch.write(statement(Sql::wipe)); });
        if (result.outcome == Outcome::committed) {
            std::ranges::fill(opened_.header, std::uint8_t{0});
            std::ranges::fill(opened_.manifest, std::uint8_t{0});
        }
        return result;
    }

    [[nodiscard]] Result<void> checkpoint() noexcept
    {
        stop_reading();
        int log = -1;
        int done = -1;
        const int code = sqlite3_wal_checkpoint_v2(db(), "main", SQLITE_CHECKPOINT_TRUNCATE, &log, &done);
        if (code != SQLITE_OK) {
            return std::unexpected(error_of(code));
        }
        if (log != 0) {
            return std::unexpected(Error::storage);
        }
        return {};
    }

    void seal() noexcept
    {
        sealed_.store(true);
    }

    [[nodiscard]] bool sealed() const noexcept
    {
        return sealed_.load();
    }

    [[nodiscard]] const std::vector<detail::Setting>& settings() const noexcept
    {
        return pragmas_;
    }

    [[nodiscard]] int db_config(int option) const
    {
        return db_config_of(db(), option);
    }

    [[nodiscard]] int limit(int code) const
    {
        return sqlite3_limit(db(), code, -1);
    }

private:
    [[nodiscard]] sqlite3* db() const noexcept
    {
        return database_.get();
    }

    [[nodiscard]] sqlite3_stmt* statement(Sql sql) const
    {
        return statements_.at(index_of(sql)).get();
    }

    [[nodiscard]] bool holds_vault() const noexcept
    {
        return opened_.content == Content::vault;
    }

    void stop_reading() noexcept
    {
        for (const auto& read : std::span(statements_).first(read_statements)) {
            if (read != nullptr) {
                static_cast<void>(sqlite3_reset(read.get()));
            }
        }
        scanning_ = false;
    }

    [[nodiscard]] Result<void> open_file(std::string_view path, const char* vfs, bool create)
    {
        if (!library_matches()) {
            return std::unexpected(Error::library_failure);
        }
        sqlite3_vfs* system = sqlite3_vfs_find(vfs);
        if (!valid_path(path) || system == nullptr) {
            return std::unexpected(Error::invalid_parameters);
        }
        const std::string name(path);
        const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE | SQLITE_OPEN_PRIVATECACHE
            | SQLITE_OPEN_FULLMUTEX | (create ? SQLITE_OPEN_CREATE : 0);
        sqlite3* raw = nullptr;
        const int code = sqlite3_open_v2(name.c_str(), &raw, flags, vfs);
        database_.reset(raw);
        if (code == SQLITE_OK) {
            return {};
        }
        if (!create && (code & primary_code) == SQLITE_CANTOPEN && !exists(system, name)) {
            return std::unexpected(Error::no_vault);
        }
        return std::unexpected(Error::storage);
    }

    [[nodiscard]] Result<void> harden()
    {
        if (const auto configured = configure(db()); !configured) {
            return configured;
        }
        if (sqlite3_set_authorizer(db(), authorise, &sealed_) != SQLITE_OK) {
            return std::unexpected(Error::library_failure);
        }
        if (const auto waits = record("pragma.busy_timeout", "PRAGMA busy_timeout", busy_wait); !waits) {
            return waits;
        }
        if (const auto locked = record("pragma.locking_mode", "PRAGMA locking_mode = EXCLUSIVE", exclusive); !locked) {
            return locked;
        }
        for (const auto& pragma : reading_pragmas) {
            if (const auto set = apply(pragma); !set) {
                return set;
            }
        }
        return {};
    }

    [[nodiscard]] Result<void> continue_existing(const std::string& journal, Identity& identity)
    {
        pragmas_.push_back(detail::Setting{.name = "pragma.journal_mode", .value = journal});
        if (const auto set = apply(synchronous); !set) {
            return set;
        }
        if (const auto read = complete(db(), identity); !read) {
            return read;
        }
        const auto content = content_of(identity, journal);
        if (!content) {
            return std::unexpected(content.error());
        }
        if (*content == Content::empty) {
            return std::unexpected(Error::no_vault);
        }
        const auto row = prepare(db(), statement_text.at(index_of(Sql::vault_row)), 0);
        if (!row) {
            return std::unexpected(row.error());
        }
        auto found = vault_row(row->get());
        if (!found) {
            return std::unexpected(found.error());
        }
        opened_ = std::move(*found);
        if (const auto prepared = prepare_statements(0, statement_count); !prepared) {
            return prepared;
        }
        seal();
        return {};
    }

    [[nodiscard]] Result<void> continue_new(const std::string& journal, Identity& identity)
    {
        if (const auto read = complete(db(), identity); !read) {
            return read;
        }
        const auto content = content_of(identity, journal);
        if (!content) {
            return std::unexpected(content.error());
        }
        if (*content == Content::vault) {
            return std::unexpected(Error::vault_exists);
        }
        if (const auto laid_out = lay_out_new_file(); !laid_out) {
            return laid_out;
        }
        if (const auto set = apply(synchronous); !set) {
            return set;
        }
        return prepare_statements(index_of(Sql::begin), statement_count);
    }

    [[nodiscard]] Result<void> lay_out_new_file()
    {
        for (const std::string_view sql : {"PRAGMA page_size = 4096", "PRAGMA auto_vacuum = INCREMENTAL"}) {
            if (const auto set = execute(db(), sql); !set) {
                return set;
            }
        }
        const auto journal = query(db(), "PRAGMA journal_mode = WAL");
        if (!journal) {
            return std::unexpected(journal.error());
        }
        const auto page = query(db(), "PRAGMA page_size");
        if (!page) {
            return std::unexpected(page.error());
        }
        const auto vacuum = query(db(), "PRAGMA auto_vacuum");
        if (!vacuum) {
            return std::unexpected(vacuum.error());
        }
        if (*journal != wal || *page != page_size || *vacuum != incremental) {
            return std::unexpected(Error::integrity);
        }
        pragmas_.push_back(detail::Setting{.name = "pragma.journal_mode", .value = *journal});
        return {};
    }

    [[nodiscard]] Result<void> record(std::string_view name, std::string_view sql, std::string_view expected)
    {
        const auto value = query(db(), sql);
        if (!value) {
            return std::unexpected(value.error());
        }
        if (*value != expected) {
            return std::unexpected(Error::library_failure);
        }
        pragmas_.push_back(detail::Setting{.name = std::string(name), .value = *value});
        return {};
    }

    [[nodiscard]] Result<void> apply(const Pragma& pragma)
    {
        if (const auto set = execute(db(), pragma.set); !set) {
            return set;
        }
        return record(pragma.name, pragma.query, pragma.expected);
    }

    [[nodiscard]] Result<void> prepare_statements(std::size_t from, std::size_t to)
    {
        for (std::size_t index = from; index < to; ++index) {
            auto prepared = prepare(db(), statement_text.at(index), SQLITE_PREPARE_PERSISTENT);
            if (!prepared) {
                return std::unexpected(prepared.error());
            }
            statements_.at(index) = std::move(*prepared);
        }
        return {};
    }

    void prepare_in(Batch& batch, std::size_t from, std::size_t to)
    {
        for (std::size_t index = from; index < to && !batch.failed(); ++index) {
            if (const int code = prepare_into(db(), statement_text.at(index), SQLITE_PREPARE_PERSISTENT, statements_.at(index));
                code != SQLITE_OK) {
                batch.fail(code);
            }
        }
    }

    [[nodiscard]] int finish(Sql sql) const
    {
        const Use use(statement(sql));
        return sqlite3_step(statement(sql));
    }

    template <typename Writes>
    [[nodiscard]] CommitResult transact(Writes&& writes)
    {
        stop_reading();
        Batch batch(db());
        batch.run(statement(Sql::begin));
        if (!batch.failed()) {
            std::forward<Writes>(writes)(batch);
        }
        if (batch.failed()) {
            if (sqlite3_get_autocommit(db()) == 0) {
                if (const int code = finish(Sql::rollback); code != SQLITE_DONE) {
                    return CommitResult{.outcome = Outcome::unknown, .error = write_error_of(code)};
                }
            }
            if (batch.mismatched()) {
                return CommitResult{.outcome = Outcome::mismatch, .error = Error::integrity};
            }
            return CommitResult{.outcome = Outcome::rolled_back, .error = write_error_of(batch.code())};
        }
        if (const int code = finish(Sql::commit); code != SQLITE_DONE) {
            if (sqlite3_get_autocommit(db()) == 0) {
                static_cast<void>(finish(Sql::rollback));
            }
            return CommitResult{.outcome = Outcome::unknown, .error = write_error_of(code)};
        }
        return CommitResult{.outcome = Outcome::committed, .error = Error::storage};
    }

    void write_row(Batch& batch, const RowChange& row) const
    {
        switch (row.write) {
        case RowWrite::insert:
            batch.write(statement(Sql::insert_address), row.slot, row.address);
            batch.write(statement(Sql::insert_body), row.slot, row.record);
            return;
        case RowWrite::replace:
            batch.write(statement(Sql::replace_address), row.slot, row.address, row.old_address_nonce);
            batch.write(statement(Sql::replace_body), row.slot, row.record, row.old_record_nonce);
            return;
        case RowWrite::erase:
            batch.write(statement(Sql::erase_address), row.slot, row.old_address_nonce);
            batch.write(statement(Sql::erase_body), row.slot, row.old_record_nonce);
            return;
        }
        batch.fail(SQLITE_MISUSE);
    }

    std::atomic<bool> sealed_{false};
    Database database_;
    std::array<Statement, statement_count> statements_{};
    Opened opened_;
    bool scanning_ = false;
    std::vector<detail::Setting> pragmas_;
};

Store::Store(std::unique_ptr<Connection> connection) noexcept
    : connection_(std::move(connection))
{
}

Store::Store(Store&& other) noexcept = default;
Store& Store::operator=(Store&& other) noexcept = default;
Store::~Store() = default;

Result<Store> Store::open_existing(std::string_view path, const char* vfs)
{
    auto connection = std::make_unique<Connection>();
    if (const auto opened = connection->open(path, vfs, false); !opened) {
        return std::unexpected(opened.error());
    }
    return Store(std::move(connection));
}

Result<Store> Store::open_new(std::string_view path, const char* vfs)
{
    auto connection = std::make_unique<Connection>();
    if (const auto opened = connection->open(path, vfs, true); !opened) {
        return std::unexpected(opened.error());
    }
    return Store(std::move(connection));
}

Result<void> Store::remove_files(std::string_view path, const char* vfs)
{
    sqlite3_vfs* system = sqlite3_vfs_find(vfs);
    if (!valid_path(path) || system == nullptr) {
        return std::unexpected(Error::invalid_parameters);
    }
    const auto full = full_path(system, path);
    if (!full) {
        return std::unexpected(Error::storage);
    }
    for (const std::string_view suffix : {"", "-wal", "-shm", "-journal"}) {
        const auto name = *full + std::string(suffix);
        const int code = system->xDelete(system, name.c_str(), 1);
        if (code != SQLITE_OK && code != SQLITE_IOERR_DELETE_NOENT) {
            return std::unexpected(Error::storage);
        }
    }
    return {};
}

const Opened& Store::opened() const noexcept
{
    static const Opened none{};
    return connection_ ? connection_->opened() : none;
}

Result<void> Store::begin_scan()
{
    if (!connection_) {
        return std::unexpected(Error::invalid_parameters);
    }
    return connection_->begin_scan();
}

Result<std::optional<ScannedRow>> Store::next_row()
{
    if (!connection_) {
        return std::unexpected(Error::invalid_parameters);
    }
    return connection_->next_row();
}

Result<std::optional<crypto::Bytes>> Store::body(std::uint64_t slot)
{
    if (!connection_) {
        return std::unexpected(Error::invalid_parameters);
    }
    return connection_->read_body(slot, false);
}

Result<std::optional<crypto::Bytes>> Store::salvage_body(std::uint64_t slot)
{
    if (!connection_) {
        return std::unexpected(Error::invalid_parameters);
    }
    return connection_->read_body(slot, true);
}

CommitResult Store::initialise(crypto::ByteView header, crypto::ByteView manifest, std::span<const RowChange> rows)
{
    return connection_ ? connection_->initialise(header, manifest, rows) : refused();
}

CommitResult Store::commit(std::span<const RowChange> rows, std::optional<Swap> header, crypto::ByteView old_manifest,
    crypto::ByteView new_manifest)
{
    return connection_ ? connection_->commit(rows, header, old_manifest, new_manifest) : refused();
}

CommitResult Store::mark_wiped()
{
    return connection_ ? connection_->mark_wiped() : refused();
}

Result<void> Store::checkpoint()
{
    if (!connection_) {
        return std::unexpected(Error::invalid_parameters);
    }
    return connection_->checkpoint();
}

void Store::seal_statements() noexcept
{
    if (connection_) {
        connection_->seal();
    }
}

namespace detail {

std::vector<Setting> settings(const Store& store)
{
    return store.connection_ ? store.connection_->settings() : std::vector<Setting>{};
}

int db_config(const Store& store, int option)
{
    return store.connection_ ? store.connection_->db_config(option) : -1;
}

int limit(const Store& store, int code)
{
    return store.connection_ ? store.connection_->limit(code) : -1;
}

bool sealed(const Store& store) noexcept
{
    return store.connection_ && store.connection_->sealed();
}

}

}
