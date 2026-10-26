// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/secret_bytes.hpp"

#include "backend.hpp"

#include <sodium.h>

#include <algorithm>
#include <new>
#include <utility>

namespace lume::crypto {

SecretBytes::SecretBytes(std::size_t size)
{
    if (size == 0) {
        return;
    }
    detail::require_operational();
    data_ = static_cast<std::uint8_t*>(sodium_malloc(size));
    if (data_ == nullptr) {
        throw std::bad_alloc();
    }
    size_ = size;
    sodium_memzero(data_, size_);
}

SecretBytes SecretBytes::copy_of(ByteView bytes)
{
    SecretBytes secret(bytes.size());
    std::ranges::copy(bytes, secret.writable().begin());
    return secret;
}

SecretBytes::SecretBytes(SecretBytes&& other) noexcept
    : data_(std::exchange(other.data_, nullptr))
    , size_(std::exchange(other.size_, 0))
{
}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept
{
    if (this != &other) {
        release();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

SecretBytes::~SecretBytes()
{
    release();
}

std::size_t SecretBytes::size() const noexcept
{
    return size_;
}

bool SecretBytes::empty() const noexcept
{
    return size_ == 0;
}

std::span<std::uint8_t> SecretBytes::writable() noexcept
{
    return {data_, size_};
}

ByteView SecretBytes::view() const noexcept
{
    return {data_, size_};
}

bool SecretBytes::equals(ByteView other) const noexcept
{
    if (other.size() != size_) {
        return false;
    }
    if (size_ == 0) {
        return true;
    }
    return sodium_memcmp(data_, other.data(), size_) == 0;
}

SecretBytes SecretBytes::clone() const
{
    return copy_of(view());
}

void SecretBytes::release() noexcept
{
    if (data_ != nullptr) {
        sodium_free(data_);
        data_ = nullptr;
        size_ = 0;
    }
}

}
