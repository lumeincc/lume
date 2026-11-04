// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/secret_bytes.hpp"
#include "vault/keys.hpp"

#include <utility>

namespace lume::vault::detail {

struct KeyAccess {
    [[nodiscard]] static PassphraseKey passphrase_key(crypto::SecretBytes key, const Salt& salt, Cost cost) noexcept
    {
        return {std::move(key), salt, cost};
    }

    [[nodiscard]] static HardwareKey hardware_key(crypto::SecretBytes key, const KeyName& name) noexcept
    {
        return {std::move(key), name};
    }

    [[nodiscard]] static MasterKey master_key(crypto::SecretBytes key, crypto::SecretBytes passphrase, const Salt& salt,
        Cost cost, const KeyName& hardware) noexcept
    {
        return {std::move(key), std::move(passphrase), salt, cost, hardware};
    }

    [[nodiscard]] static Keys keys(crypto::SecretBytes data, crypto::SecretBytes record, crypto::SecretBytes address,
        crypto::SecretBytes manifest, crypto::SecretBytes root) noexcept
    {
        return {std::move(data), std::move(record), std::move(address), std::move(manifest), std::move(root)};
    }

    [[nodiscard]] static OpenedHeader opened_header(
        const wire::VaultHeader& header, Keys keys, crypto::SecretBytes passphrase, const KeyName& hardware) noexcept
    {
        return {header, std::move(keys), std::move(passphrase), hardware};
    }

    [[nodiscard]] static Confirmed confirmed(const Check& check) noexcept
    {
        return Confirmed(check);
    }

    [[nodiscard]] static const crypto::SecretBytes& secret(const PassphraseKey& key) noexcept
    {
        return key.key_;
    }

    [[nodiscard]] static const crypto::SecretBytes& secret(const HardwareKey& key) noexcept
    {
        return key.key_;
    }

    [[nodiscard]] static const crypto::SecretBytes& secret(const MasterKey& key) noexcept
    {
        return key.key_;
    }

    [[nodiscard]] static const crypto::SecretBytes& passphrase(const MasterKey& key) noexcept
    {
        return key.passphrase_;
    }

    [[nodiscard]] static const crypto::SecretBytes& passphrase(const OpenedHeader& opened) noexcept
    {
        return opened.passphrase_;
    }

    [[nodiscard]] static const crypto::SecretBytes& data(const Keys& keys) noexcept
    {
        return keys.data_;
    }

    [[nodiscard]] static const crypto::SecretBytes& record(const Keys& keys) noexcept
    {
        return keys.record_;
    }

    [[nodiscard]] static const crypto::SecretBytes& address(const Keys& keys) noexcept
    {
        return keys.address_;
    }

    [[nodiscard]] static const crypto::SecretBytes& manifest(const Keys& keys) noexcept
    {
        return keys.manifest_;
    }

    [[nodiscard]] static const crypto::SecretBytes& root(const Keys& keys) noexcept
    {
        return keys.root_;
    }
};

}
