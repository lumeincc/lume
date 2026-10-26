// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace lume::crypto {

class SecretBytes {
public:
    SecretBytes() noexcept = default;
    explicit SecretBytes(std::size_t size);

    static SecretBytes copy_of(ByteView bytes);
    static SecretBytes joined(std::span<const ByteView> parts);

    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept;
    SecretBytes& operator=(SecretBytes&& other) noexcept;
    ~SecretBytes();

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::span<std::uint8_t> writable() noexcept;
    [[nodiscard]] ByteView view() const noexcept;
    [[nodiscard]] bool equals(ByteView other) const noexcept;
    [[nodiscard]] SecretBytes clone() const;

private:
    void release() noexcept;

    std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

}
