// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/vault/vault.hpp"
#include "vault/keys.hpp"
#include "vault/records.hpp"
#include "vault/store.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <initializer_list>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

struct sqlite3;

namespace lume::test {

template <typename T, typename E>
T must(std::expected<T, E> result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
    return std::move(*result);
}

template <typename E>
void must(const std::expected<void, E>& result)
{
    if (!result) {
        throw std::runtime_error("a setup step of the test failed");
    }
}

enum class Backing : std::uint8_t {
    os = 1,
    memory = 2,
};

[[nodiscard]] std::string backing_name(Backing backing);

class Place {
public:
    explicit Place(Backing backing);
    Place(const Place&) = delete;
    Place& operator=(const Place&) = delete;
    Place(Place&&) = delete;
    Place& operator=(Place&&) = delete;
    ~Place();

    [[nodiscard]] Backing backing() const noexcept;
    [[nodiscard]] const char* vfs() const;
    [[nodiscard]] std::string path(std::string_view suffix = {}) const;
    [[nodiscard]] std::optional<crypto::Bytes> read(std::string_view suffix = {}) const;
    void write(std::string_view suffix, crypto::ByteView bytes) const;
    [[nodiscard]] bool exists(std::string_view suffix = {}) const;
    void remove(std::string_view suffix = {}) const;

private:
    [[nodiscard]] std::filesystem::path file(std::string_view suffix) const;

    Backing backing_;
    std::filesystem::path directory_;
    std::string path_;
};

struct SealedRow {
    std::uint64_t slot = 0;
    crypto::Bytes address;
    crypto::Bytes record;
};

class Material {
public:
    [[nodiscard]] static const Material& keystore();
    [[nodiscard]] static const Material& tpm();

    [[nodiscard]] const vault::OpenedHeader& opened() const noexcept;
    [[nodiscard]] crypto::Bytes header(std::uint8_t seed = 0) const;
    [[nodiscard]] crypto::Bytes manifest(std::uint8_t seed) const;
    [[nodiscard]] SealedRow row(std::uint64_t slot, std::uint8_t seed, crypto::ByteView payload, std::string_view id = "record",
        std::uint64_t counter = 0) const;

private:
    Material(vault::MasterKey master, vault::OpenedHeader opened);

    vault::MasterKey master_;
    vault::OpenedHeader opened_;
};

[[nodiscard]] vault::Nonce nonce_from(std::uint8_t kind, std::uint8_t seed) noexcept;
[[nodiscard]] vault::Nonce leading_nonce(crypto::ByteView box);
[[nodiscard]] vault::RowChange inserted(const SealedRow& row);
[[nodiscard]] vault::RowChange replaced(const SealedRow& from, const SealedRow& to);
[[nodiscard]] vault::RowChange erased(const SealedRow& row);
[[nodiscard]] crypto::Bytes patterned(std::size_t size, std::uint8_t seed);
[[nodiscard]] crypto::Bytes bytes_of(std::string_view text);
[[nodiscard]] bool contains(crypto::ByteView haystack, crypto::ByteView needle);

[[nodiscard]] vault::Store created(const Place& place, const Material& material, std::initializer_list<SealedRow> rows,
    std::uint8_t manifest_seed = 1);

struct CloseConnection {
    void operator()(sqlite3* database) const noexcept;
};

class Side {
public:
    explicit Side(const Place& place, std::string_view suffix = {});

    void run(std::string_view sql) const;
    void run(std::string_view sql, std::initializer_list<crypto::ByteView> blobs) const;
    void close() noexcept;

private:
    std::unique_ptr<sqlite3, CloseConnection> database_;
};

}
