// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/vault/hardware.hpp"
#include "lume/vault/vault.hpp"
#include "lume/wire/structures.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace lume::vault {

inline constexpr std::uint32_t kib_per_mib = 1024;
inline constexpr std::size_t key_size = 32;
inline constexpr std::uint64_t first_epoch = 1;

struct Cost {
    std::uint32_t ops = 0;
    std::uint32_t mem = 0;

    friend bool operator==(const Cost&, const Cost&) = default;
};

struct Limits {
    Cost cost;
    Cost ceiling;
};

inline constexpr Cost cost_floor{.ops = 2, .mem = 64 * kib_per_mib};
inline constexpr Cost cost_ceiling{.ops = 10, .mem = 1024 * kib_per_mib};
inline constexpr Limits android_limits{
    .cost = {.ops = 3, .mem = 64 * kib_per_mib}, .ceiling = {.ops = 4, .mem = 256 * kib_per_mib}};
inline constexpr Limits desktop_limits{.cost = {.ops = 3, .mem = 256 * kib_per_mib}, .ceiling = cost_ceiling};

using Salt = crypto::ByteArray<wire::vault_salt_size>;
using Check = crypto::ByteArray<wire::vault_check_size>;

namespace detail {
struct KeyAccess;
}

[[nodiscard]] std::optional<Limits> limits_of(Platform platform) noexcept;
[[nodiscard]] bool within_bounds(Cost cost, Cost ceiling) noexcept;
[[nodiscard]] bool rotates(wire::HardwareMode mode) noexcept;
[[nodiscard]] bool well_formed(const wire::VaultHeader& header) noexcept;
[[nodiscard]] bool names(const wire::VaultHeader& header, const KeyName& key) noexcept;
[[nodiscard]] Result<void> check_new_passphrase(std::string_view passphrase, wire::HardwareMode mode);
[[nodiscard]] Salt fresh_salt();

class PassphraseKey {
public:
    PassphraseKey(PassphraseKey&&) noexcept = default;
    PassphraseKey& operator=(PassphraseKey&&) noexcept = default;
    PassphraseKey(const PassphraseKey&) = delete;
    PassphraseKey& operator=(const PassphraseKey&) = delete;
    ~PassphraseKey() = default;

    [[nodiscard]] const Salt& salt() const noexcept;
    [[nodiscard]] Cost cost() const noexcept;

private:
    friend struct detail::KeyAccess;
    PassphraseKey(crypto::SecretBytes key, const Salt& salt, Cost cost) noexcept;

    crypto::SecretBytes key_;
    Salt salt_{};
    Cost cost_{};
};

class HardwareKey {
public:
    HardwareKey(HardwareKey&&) noexcept = default;
    HardwareKey& operator=(HardwareKey&&) noexcept = default;
    HardwareKey(const HardwareKey&) = delete;
    HardwareKey& operator=(const HardwareKey&) = delete;
    ~HardwareKey() = default;

    [[nodiscard]] const KeyName& name() const noexcept;

private:
    friend struct detail::KeyAccess;
    HardwareKey(crypto::SecretBytes key, const KeyName& name) noexcept;

    crypto::SecretBytes key_;
    KeyName name_;
};

class MasterKey {
public:
    MasterKey(MasterKey&&) noexcept = default;
    MasterKey& operator=(MasterKey&&) noexcept = default;
    MasterKey(const MasterKey&) = delete;
    MasterKey& operator=(const MasterKey&) = delete;
    ~MasterKey() = default;

    [[nodiscard]] const Salt& salt() const noexcept;
    [[nodiscard]] Cost cost() const noexcept;
    [[nodiscard]] const KeyName& hardware() const noexcept;

private:
    friend struct detail::KeyAccess;
    MasterKey(crypto::SecretBytes key, crypto::SecretBytes passphrase, const Salt& salt, Cost cost, const KeyName& hardware) noexcept;

    crypto::SecretBytes key_;
    crypto::SecretBytes passphrase_;
    Salt salt_{};
    Cost cost_{};
    KeyName hardware_;
};

class Keys {
public:
    Keys(Keys&&) noexcept = default;
    Keys& operator=(Keys&&) noexcept = default;
    Keys(const Keys&) = delete;
    Keys& operator=(const Keys&) = delete;
    ~Keys() = default;

private:
    friend struct detail::KeyAccess;
    Keys(crypto::SecretBytes data, crypto::SecretBytes record, crypto::SecretBytes address, crypto::SecretBytes manifest,
        crypto::SecretBytes root) noexcept;

    crypto::SecretBytes data_;
    crypto::SecretBytes record_;
    crypto::SecretBytes address_;
    crypto::SecretBytes manifest_;
    crypto::SecretBytes root_;
};

class OpenedHeader {
public:
    OpenedHeader(OpenedHeader&&) noexcept = default;
    OpenedHeader& operator=(OpenedHeader&&) noexcept = default;
    OpenedHeader(const OpenedHeader&) = delete;
    OpenedHeader& operator=(const OpenedHeader&) = delete;
    ~OpenedHeader() = default;

    [[nodiscard]] const wire::VaultHeader& header() const noexcept;
    [[nodiscard]] const Keys& keys() const noexcept;
    [[nodiscard]] const KeyName& hardware() const noexcept;
    void forget_passphrase() noexcept;

private:
    friend struct detail::KeyAccess;
    OpenedHeader(const wire::VaultHeader& header, Keys keys, crypto::SecretBytes passphrase, const KeyName& hardware) noexcept;

    wire::VaultHeader header_;
    Keys keys_;
    crypto::SecretBytes passphrase_;
    KeyName hardware_;
};

class Confirmed {
public:
    [[nodiscard]] const Check& check() const noexcept;

private:
    friend struct detail::KeyAccess;
    explicit Confirmed(const Check& check) noexcept;

    Check check_{};
};

[[nodiscard]] Result<PassphraseKey> derive_passphrase_key(
    std::string_view passphrase, const Salt& salt, Cost cost, Platform platform);
[[nodiscard]] Result<crypto::SecretBytes> hardware_input(const PassphraseKey& passphrase_key, wire::HardwareMode mode);
[[nodiscard]] Result<crypto::SecretBytes> hardware_input(const OpenedHeader& opened);
[[nodiscard]] Result<HardwareKey> hardware_key(const KeyName& name, crypto::ByteView output);
[[nodiscard]] Result<MasterKey> derive_master_key(const PassphraseKey& passphrase_key, const HardwareKey& hardware_key);
[[nodiscard]] Result<OpenedHeader> first_header(const MasterKey& master_key);
[[nodiscard]] Result<OpenedHeader> open_header(const MasterKey& master_key, const wire::VaultHeader& header);
[[nodiscard]] Result<Keys> salvage_keys(const MasterKey& master_key, const wire::VaultHeader& header);
[[nodiscard]] Result<Confirmed> confirm(const MasterKey& master_key, const OpenedHeader& current);
[[nodiscard]] Result<OpenedHeader> next_header(const HardwareKey& hardware_key, const OpenedHeader& current);
[[nodiscard]] Result<OpenedHeader> rekeyed_header(
    const MasterKey& master_key, const OpenedHeader& current, const Confirmed& confirmed);

}
