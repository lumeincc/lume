// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "support/memory_vfs.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lume::test {
namespace {

constexpr const char* vfs_name = "lume-memory";
constexpr int path_bound = 512;
constexpr int sector_size = 512;

struct File {
    crypto::Bytes current;
    crypto::Bytes durable;
};

struct Handle {
    std::string name;
    std::shared_ptr<File> file;
    int lock = SQLITE_LOCK_NONE;
    bool delete_on_close = false;
};

struct State {
    std::atomic_flag busy;
    std::map<std::string, std::shared_ptr<File>, std::less<>> files;
    std::map<const sqlite3_file*, Handle> handles;
    std::uint64_t operations = 0;
    std::uint64_t temporaries = 0;
    std::uint64_t slept = 0;
    std::vector<MemoryDeletion> deletions;
    MemoryFaults faults;
};

State& state()
{
    static State shared;
    return shared;
}

class Guard {
public:
    explicit Guard(State& shared) noexcept
        : busy_(shared.busy)
    {
        while (busy_.test_and_set(std::memory_order_acquire)) {
            busy_.wait(true, std::memory_order_relaxed);
        }
    }

    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
    Guard(Guard&&) = delete;
    Guard& operator=(Guard&&) = delete;

    ~Guard()
    {
        busy_.clear(std::memory_order_release);
        busy_.notify_one();
    }

private:
    std::atomic_flag& busy_;
};

template <typename Body>
int shielded(int failure, const Body& body) noexcept
{
    try {
        return body();
    } catch (...) {
        return failure;
    }
}

Handle* handle_of(State& shared, const sqlite3_file* file) noexcept
{
    const auto found = shared.handles.find(file);
    return found == shared.handles.end() ? nullptr : &found->second;
}

int highest_lock(const State& shared, const sqlite3_file* except, const std::shared_ptr<File>& file) noexcept
{
    int highest = SQLITE_LOCK_NONE;
    for (const auto& [key, handle] : shared.handles) {
        if (key != except && handle.file == file) {
            highest = std::max(highest, handle.lock);
        }
    }
    return highest;
}

bool blocked(int level, int others) noexcept
{
    if (level == SQLITE_LOCK_SHARED) {
        return others >= SQLITE_LOCK_PENDING;
    }
    if (level == SQLITE_LOCK_RESERVED) {
        return others >= SQLITE_LOCK_RESERVED;
    }
    return others >= SQLITE_LOCK_SHARED;
}

int close_file(sqlite3_file* file) noexcept
{
    return shielded(SQLITE_IOERR_CLOSE, [file] {
        auto& shared = state();
        const Guard guard(shared);
        const auto found = shared.handles.find(file);
        if (found == shared.handles.end()) {
            return SQLITE_OK;
        }
        if (found->second.delete_on_close) {
            const auto named = shared.files.find(found->second.name);
            if (named != shared.files.end() && named->second == found->second.file) {
                shared.files.erase(named);
            }
        }
        shared.handles.erase(found);
        return SQLITE_OK;
    });
}

int read_file(sqlite3_file* file, void* buffer, int amount, sqlite3_int64 offset) noexcept
{
    return shielded(SQLITE_IOERR_READ, [=] {
        auto& shared = state();
        const Guard guard(shared);
        const auto* handle = handle_of(shared, file);
        if (handle == nullptr || amount < 0 || offset < 0) {
            return SQLITE_IOERR_READ;
        }
        if (shared.faults.read != 0) {
            return shared.faults.read;
        }
        const std::span target(static_cast<std::uint8_t*>(buffer), static_cast<std::size_t>(amount));
        const auto& bytes = handle->file->current;
        const auto start = static_cast<std::size_t>(offset);
        const std::size_t available = start < bytes.size() ? std::min(target.size(), bytes.size() - start) : 0;
        if (available > 0) {
            std::ranges::copy(std::span(bytes).subspan(start, available), target.begin());
        }
        std::ranges::fill(target.subspan(available), std::uint8_t{0});
        return available == target.size() ? SQLITE_OK : SQLITE_IOERR_SHORT_READ;
    });
}

int write_file(sqlite3_file* file, const void* buffer, int amount, sqlite3_int64 offset) noexcept
{
    return shielded(SQLITE_IOERR_WRITE, [=] {
        auto& shared = state();
        const Guard guard(shared);
        const auto* handle = handle_of(shared, file);
        if (handle == nullptr || amount < 0 || offset < 0) {
            return SQLITE_IOERR_WRITE;
        }
        ++shared.operations;
        if (shared.faults.write != 0) {
            return shared.faults.write;
        }
        const std::span source(static_cast<const std::uint8_t*>(buffer), static_cast<std::size_t>(amount));
        auto& bytes = handle->file->current;
        const auto start = static_cast<std::size_t>(offset);
        if (bytes.size() < start + source.size()) {
            bytes.resize(start + source.size());
        }
        std::ranges::copy(source, std::span(bytes).subspan(start).begin());
        return SQLITE_OK;
    });
}

int truncate_file(sqlite3_file* file, sqlite3_int64 size) noexcept
{
    return shielded(SQLITE_IOERR_TRUNCATE, [=] {
        auto& shared = state();
        const Guard guard(shared);
        const auto* handle = handle_of(shared, file);
        if (handle == nullptr || size < 0) {
            return SQLITE_IOERR_TRUNCATE;
        }
        ++shared.operations;
        if (shared.faults.write != 0) {
            return shared.faults.write;
        }
        handle->file->current.resize(static_cast<std::size_t>(size));
        return SQLITE_OK;
    });
}

int sync_file(sqlite3_file* file, [[maybe_unused]] int flags) noexcept
{
    return shielded(SQLITE_IOERR_FSYNC, [file] {
        auto& shared = state();
        const Guard guard(shared);
        const auto* handle = handle_of(shared, file);
        if (handle == nullptr) {
            return SQLITE_IOERR_FSYNC;
        }
        ++shared.operations;
        if (shared.faults.write != 0) {
            return shared.faults.write;
        }
        handle->file->durable = handle->file->current;
        return SQLITE_OK;
    });
}

int file_size(sqlite3_file* file, sqlite3_int64* size) noexcept
{
    return shielded(SQLITE_IOERR_FSTAT, [file, size] {
        auto& shared = state();
        const Guard guard(shared);
        const auto* handle = handle_of(shared, file);
        if (handle == nullptr) {
            return SQLITE_IOERR_FSTAT;
        }
        *size = static_cast<sqlite3_int64>(handle->file->current.size());
        return SQLITE_OK;
    });
}

int lock_file(sqlite3_file* file, int level) noexcept
{
    return shielded(SQLITE_IOERR_LOCK, [file, level] {
        auto& shared = state();
        const Guard guard(shared);
        auto* handle = handle_of(shared, file);
        if (handle == nullptr) {
            return SQLITE_IOERR_LOCK;
        }
        if (handle->lock >= level) {
            return SQLITE_OK;
        }
        if (shared.faults.busy_locks > 0) {
            --shared.faults.busy_locks;
            return SQLITE_BUSY;
        }
        if (blocked(level, highest_lock(shared, file, handle->file))) {
            return SQLITE_BUSY;
        }
        handle->lock = level;
        return SQLITE_OK;
    });
}

int unlock_file(sqlite3_file* file, int level) noexcept
{
    return shielded(SQLITE_IOERR_UNLOCK, [file, level] {
        auto& shared = state();
        const Guard guard(shared);
        auto* handle = handle_of(shared, file);
        if (handle == nullptr) {
            return SQLITE_IOERR_UNLOCK;
        }
        handle->lock = std::min(handle->lock, level);
        return SQLITE_OK;
    });
}

int check_reserved(sqlite3_file* file, int* reserved) noexcept
{
    return shielded(SQLITE_IOERR_CHECKRESERVEDLOCK, [file, reserved] {
        auto& shared = state();
        const Guard guard(shared);
        const auto* handle = handle_of(shared, file);
        if (handle == nullptr) {
            return SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        *reserved = highest_lock(shared, nullptr, handle->file) >= SQLITE_LOCK_RESERVED ? 1 : 0;
        return SQLITE_OK;
    });
}

int control_file([[maybe_unused]] sqlite3_file* file, int operation, void* argument) noexcept
{
    if (operation == SQLITE_FCNTL_MMAP_SIZE) {
        *static_cast<sqlite3_int64*>(argument) = 0;
        return SQLITE_OK;
    }
    return SQLITE_NOTFOUND;
}

int sector_size_of([[maybe_unused]] sqlite3_file* file) noexcept
{
    return sector_size;
}

int characteristics([[maybe_unused]] sqlite3_file* file) noexcept
{
    return 0;
}

const sqlite3_io_methods& methods()
{
    static const sqlite3_io_methods table{
        .iVersion = 1,
        .xClose = close_file,
        .xRead = read_file,
        .xWrite = write_file,
        .xTruncate = truncate_file,
        .xSync = sync_file,
        .xFileSize = file_size,
        .xLock = lock_file,
        .xUnlock = unlock_file,
        .xCheckReservedLock = check_reserved,
        .xFileControl = control_file,
        .xSectorSize = sector_size_of,
        .xDeviceCharacteristics = characteristics,
        .xShmMap = nullptr,
        .xShmLock = nullptr,
        .xShmBarrier = nullptr,
        .xShmUnmap = nullptr,
        .xFetch = nullptr,
        .xUnfetch = nullptr,
    };
    return table;
}

int open_file([[maybe_unused]] sqlite3_vfs* vfs, sqlite3_filename name, sqlite3_file* file, int flags, int* opened_flags) noexcept
{
    file->pMethods = nullptr;
    return shielded(SQLITE_CANTOPEN, [=] {
        auto& shared = state();
        const Guard guard(shared);
        const std::string path = name != nullptr ? std::string(name) : "temporary-" + std::to_string(++shared.temporaries);
        auto found = shared.files.find(path);
        const bool create = (flags & SQLITE_OPEN_CREATE) != 0;
        if (shared.faults.open != 0) {
            return shared.faults.open;
        }
        if (found == shared.files.end()) {
            if (!create) {
                return SQLITE_CANTOPEN;
            }
            found = shared.files.emplace(path, std::make_shared<File>()).first;
        } else if (create && (flags & SQLITE_OPEN_EXCLUSIVE) != 0) {
            return SQLITE_CANTOPEN;
        }
        shared.handles.insert_or_assign(file,
            Handle{.name = path,
                .file = found->second,
                .lock = SQLITE_LOCK_NONE,
                .delete_on_close = (flags & SQLITE_OPEN_DELETEONCLOSE) != 0});
        if (opened_flags != nullptr) {
            *opened_flags = flags;
        }
        file->pMethods = &methods();
        return SQLITE_OK;
    });
}

int delete_file([[maybe_unused]] sqlite3_vfs* vfs, const char* name, int sync_directory) noexcept
{
    return shielded(SQLITE_IOERR_DELETE, [name, sync_directory] {
        auto& shared = state();
        const Guard guard(shared);
        ++shared.operations;
        shared.deletions.push_back(MemoryDeletion{.name = name, .synced = sync_directory != 0});
        if (shared.faults.write != 0) {
            return shared.faults.write;
        }
        const auto found = shared.files.find(std::string_view(name));
        if (found == shared.files.end()) {
            return SQLITE_IOERR_DELETE_NOENT;
        }
        shared.files.erase(found);
        return SQLITE_OK;
    });
}

int access_file([[maybe_unused]] sqlite3_vfs* vfs, const char* name, int flags, int* result) noexcept
{
    return shielded(SQLITE_IOERR_ACCESS, [name, flags, result] {
        auto& shared = state();
        const Guard guard(shared);
        const auto found = shared.files.find(std::string_view(name));
        const bool present =
            found != shared.files.end() && (flags != SQLITE_ACCESS_EXISTS || !found->second->current.empty());
        *result = present ? 1 : 0;
        return SQLITE_OK;
    });
}

int full_pathname([[maybe_unused]] sqlite3_vfs* vfs, const char* name, int size, char* output) noexcept
{
    const std::string_view path(name);
    if (size <= 0 || path.size() >= static_cast<std::size_t>(size)) {
        return SQLITE_CANTOPEN;
    }
    const std::span target(output, static_cast<std::size_t>(size));
    *std::ranges::copy(path, target.begin()).out = '\0';
    return SQLITE_OK;
}

sqlite3_vfs* system_vfs() noexcept
{
    return sqlite3_vfs_find(nullptr);
}

int randomness([[maybe_unused]] sqlite3_vfs* vfs, int size, char* output) noexcept
{
    auto* system = system_vfs();
    return system->xRandomness(system, size, output);
}

int sleep_for([[maybe_unused]] sqlite3_vfs* vfs, int microseconds) noexcept
{
    return shielded(microseconds, [microseconds] {
        auto& shared = state();
        const Guard guard(shared);
        if (microseconds > 0) {
            shared.slept += static_cast<std::uint64_t>(microseconds);
        }
        return microseconds;
    });
}

int current_time([[maybe_unused]] sqlite3_vfs* vfs, double* now) noexcept
{
    auto* system = system_vfs();
    return system->xCurrentTime(system, now);
}

int last_error([[maybe_unused]] sqlite3_vfs* vfs, [[maybe_unused]] int size, [[maybe_unused]] char* message) noexcept
{
    return 0;
}

int current_time_int64([[maybe_unused]] sqlite3_vfs* vfs, sqlite3_int64* now) noexcept
{
    auto* system = system_vfs();
    return system->xCurrentTimeInt64(system, now);
}

sqlite3_vfs& memory()
{
    static sqlite3_vfs system{
        .iVersion = 2,
        .szOsFile = static_cast<int>(sizeof(sqlite3_file)),
        .mxPathname = path_bound,
        .pNext = nullptr,
        .zName = vfs_name,
        .pAppData = nullptr,
        .xOpen = open_file,
        .xDelete = delete_file,
        .xAccess = access_file,
        .xFullPathname = full_pathname,
        .xDlOpen = nullptr,
        .xDlError = nullptr,
        .xDlSym = nullptr,
        .xDlClose = nullptr,
        .xRandomness = randomness,
        .xSleep = sleep_for,
        .xCurrentTime = current_time,
        .xGetLastError = last_error,
        .xCurrentTimeInt64 = current_time_int64,
        .xSetSystemCall = nullptr,
        .xGetSystemCall = nullptr,
        .xNextSystemCall = nullptr,
    };
    return system;
}

}

namespace memory_vfs {

const char* name()
{
    static const char* const registered = [] {
        if (sqlite3_vfs_register(&memory(), 0) != SQLITE_OK) {
            throw std::runtime_error("the memory VFS could not be registered");
        }
        return vfs_name;
    }();
    return registered;
}

void clear()
{
    auto& shared = state();
    const Guard guard(shared);
    shared.files.clear();
    shared.handles.clear();
    shared.operations = 0;
    shared.slept = 0;
    shared.deletions.clear();
    shared.faults = MemoryFaults{};
}

std::uint64_t operations()
{
    auto& shared = state();
    const Guard guard(shared);
    return shared.operations;
}

void count_operation()
{
    auto& shared = state();
    const Guard guard(shared);
    ++shared.operations;
}

MemoryFiles files()
{
    auto& shared = state();
    const Guard guard(shared);
    MemoryFiles snapshot;
    for (const auto& [path, file] : shared.files) {
        snapshot.emplace(path, MemoryFile{.current = file->current, .durable = file->durable});
    }
    return snapshot;
}

void restore(const MemoryFiles& files)
{
    auto& shared = state();
    const Guard guard(shared);
    shared.files.clear();
    for (const auto& [path, file] : files) {
        shared.files.emplace(path, std::make_shared<File>(File{.current = file.current, .durable = file.durable}));
    }
}

void lose_power()
{
    auto& shared = state();
    const Guard guard(shared);
    for (auto& [path, file] : shared.files) {
        file->current = file->durable;
    }
}

bool exists(std::string_view path)
{
    auto& shared = state();
    const Guard guard(shared);
    return shared.files.contains(path);
}

std::optional<crypto::Bytes> content(std::string_view path)
{
    auto& shared = state();
    const Guard guard(shared);
    const auto found = shared.files.find(path);
    if (found == shared.files.end()) {
        return std::nullopt;
    }
    return found->second->current;
}

void put(std::string_view path, crypto::ByteView content)
{
    auto& shared = state();
    const Guard guard(shared);
    auto found = shared.files.find(path);
    if (found == shared.files.end()) {
        found = shared.files.emplace(std::string(path), std::make_shared<File>()).first;
    }
    found->second->current.assign(content.begin(), content.end());
    found->second->durable = found->second->current;
}

void remove(std::string_view path)
{
    auto& shared = state();
    const Guard guard(shared);
    if (const auto found = shared.files.find(path); found != shared.files.end()) {
        shared.files.erase(found);
    }
}

void inject(const MemoryFaults& faults)
{
    auto& shared = state();
    const Guard guard(shared);
    shared.faults = faults;
}

std::size_t open_files()
{
    auto& shared = state();
    const Guard guard(shared);
    return shared.handles.size();
}

std::uint64_t slept()
{
    auto& shared = state();
    const Guard guard(shared);
    return shared.slept;
}

std::vector<MemoryDeletion> deletions()
{
    auto& shared = state();
    const Guard guard(shared);
    return shared.deletions;
}

}

}
