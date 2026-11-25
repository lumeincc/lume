// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/vault/vault.hpp"
#include "vault/records.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace lume::vault {

enum class Content : std::uint8_t {
    empty = 1,
    vault = 2,
};

struct Opened {
    Content content = Content::empty;
    crypto::Bytes header;
    crypto::Bytes manifest;
};

struct ScannedRow {
    std::uint64_t slot = 0;
    crypto::ByteView address;
};

enum class RowWrite : std::uint8_t {
    insert = 1,
    replace = 2,
    erase = 3,
};

struct RowChange {
    RowWrite write = RowWrite::insert;
    std::uint64_t slot = 0;
    crypto::Bytes address;
    crypto::Bytes record;
    Nonce old_address_nonce{};
    Nonce old_record_nonce{};
};

struct Swap {
    crypto::ByteView old_header;
    crypto::ByteView new_header;
};

enum class Outcome : std::uint8_t {
    committed = 1,
    rolled_back = 2,
    mismatch = 3,
    unknown = 4,
};

struct CommitResult {
    Outcome outcome = Outcome::committed;
    Error error = Error::storage;
};

class Store;

namespace detail {

struct Setting {
    std::string name;
    std::string value;

    friend bool operator==(const Setting&, const Setting&) = default;
};

[[nodiscard]] std::vector<Setting> settings(const Store& store);
[[nodiscard]] int db_config(const Store& store, int option);
[[nodiscard]] int limit(const Store& store, int code);
[[nodiscard]] bool sealed(const Store& store) noexcept;

}

class Store {
public:
    [[nodiscard]] static Result<Store> open_existing(std::string_view path, const char* vfs);
    [[nodiscard]] static Result<Store> open_new(std::string_view path, const char* vfs);
    [[nodiscard]] static Result<void> remove_files(std::string_view path, const char* vfs);

    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
    Store(Store&& other) noexcept;
    Store& operator=(Store&& other) noexcept;
    ~Store();

    [[nodiscard]] const Opened& opened() const noexcept;
    [[nodiscard]] Result<void> begin_scan();
    [[nodiscard]] Result<std::optional<ScannedRow>> next_row();
    [[nodiscard]] Result<std::optional<crypto::Bytes>> body(std::uint64_t slot);
    [[nodiscard]] Result<std::optional<crypto::Bytes>> salvage_body(std::uint64_t slot);
    [[nodiscard]] CommitResult initialise(crypto::ByteView header, crypto::ByteView manifest, std::span<const RowChange> rows);
    [[nodiscard]] CommitResult commit(std::span<const RowChange> rows, std::optional<Swap> header,
        crypto::ByteView old_manifest, crypto::ByteView new_manifest);
    [[nodiscard]] CommitResult mark_wiped();
    [[nodiscard]] Result<void> checkpoint();
    void seal_statements() noexcept;

private:
    struct Connection;
    friend std::vector<detail::Setting> detail::settings(const Store& store);
    friend int detail::db_config(const Store& store, int option);
    friend int detail::limit(const Store& store, int code);
    friend bool detail::sealed(const Store& store) noexcept;
    explicit Store(std::unique_ptr<Connection> connection) noexcept;
    std::unique_ptr<Connection> connection_;
};

}
