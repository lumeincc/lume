// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lume::test {

struct MemoryFile {
    crypto::Bytes current;
    crypto::Bytes durable;

    friend bool operator==(const MemoryFile&, const MemoryFile&) = default;
};

using MemoryFiles = std::map<std::string, MemoryFile, std::less<>>;

struct MemoryFaults {
    int read = 0;
    int write = 0;
    int open = 0;
    std::uint64_t busy_locks = 0;
};

struct MemoryDeletion {
    std::string name;
    bool synced = false;

    friend bool operator==(const MemoryDeletion&, const MemoryDeletion&) = default;
};

namespace memory_vfs {

[[nodiscard]] const char* name();
void clear();
[[nodiscard]] std::uint64_t operations();
void count_operation();
[[nodiscard]] MemoryFiles files();
void restore(const MemoryFiles& files);
void lose_power();
[[nodiscard]] bool exists(std::string_view path);
[[nodiscard]] std::optional<crypto::Bytes> content(std::string_view path);
void put(std::string_view path, crypto::ByteView content);
void remove(std::string_view path);
void inject(const MemoryFaults& faults);
[[nodiscard]] std::size_t open_files();
[[nodiscard]] std::uint64_t slept();
[[nodiscard]] std::vector<MemoryDeletion> deletions();

}

}
