// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "support/curve.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace lume::test {
namespace {

constexpr std::size_t limb_count = 8;
constexpr std::size_t limb_bits = 32;
constexpr std::size_t bytes_per_limb = 4;
constexpr std::size_t bits_per_byte = 8;
constexpr std::uint64_t limb_mask = 0xffffffffU;
constexpr std::uint64_t top_bit = 63;
constexpr std::uint64_t wrap = 38;

using Field = std::array<std::uint32_t, limb_count>;

constexpr Field prime{
    0xffffffedU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x7fffffffU};
constexpr Field prime_minus_two{
    0xffffffebU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x7fffffffU};

bool below_prime(const Field& value)
{
    for (std::size_t index = limb_count; index-- > 0;) {
        if (value.at(index) != prime.at(index)) {
            return value.at(index) < prime.at(index);
        }
    }
    return false;
}

void subtract_prime(Field& value)
{
    std::uint64_t borrow = 0;
    for (std::size_t index = 0; index < limb_count; ++index) {
        const std::uint64_t difference = std::uint64_t{value.at(index)} - prime.at(index) - borrow;
        value.at(index) = static_cast<std::uint32_t>(difference & limb_mask);
        borrow = difference >> top_bit;
    }
}

void fold_carry(Field& value, std::uint64_t carry)
{
    while (carry != 0) {
        std::uint64_t pending = carry * wrap;
        for (std::size_t index = 0; index < limb_count; ++index) {
            const std::uint64_t sum = std::uint64_t{value.at(index)} + pending;
            value.at(index) = static_cast<std::uint32_t>(sum & limb_mask);
            pending = sum >> limb_bits;
        }
        carry = pending;
    }
}

Field multiply(const Field& left, const Field& right)
{
    std::array<std::uint64_t, 2 * limb_count> wide{};
    for (std::size_t row = 0; row < limb_count; ++row) {
        std::uint64_t carry = 0;
        for (std::size_t column = 0; column < limb_count; ++column) {
            const std::uint64_t sum =
                wide.at(row + column) + (std::uint64_t{left.at(row)} * right.at(column)) + carry;
            wide.at(row + column) = sum & limb_mask;
            carry = sum >> limb_bits;
        }
        wide.at(row + limb_count) = carry;
    }
    Field result{};
    std::uint64_t carry = 0;
    for (std::size_t index = 0; index < limb_count; ++index) {
        const std::uint64_t sum = wide.at(index) + (wrap * wide.at(index + limb_count)) + carry;
        result.at(index) = static_cast<std::uint32_t>(sum & limb_mask);
        carry = sum >> limb_bits;
    }
    fold_carry(result, carry);
    while (!below_prime(result)) {
        subtract_prime(result);
    }
    return result;
}

Field power(const Field& base, const Field& exponent)
{
    Field result{1};
    for (std::size_t bit = limb_count * limb_bits; bit-- > 0;) {
        result = multiply(result, result);
        if (((exponent.at(bit / limb_bits) >> (bit % limb_bits)) & 1U) != 0) {
            result = multiply(result, base);
        }
    }
    return result;
}

Field load(crypto::ByteView bytes)
{
    Field value{};
    std::size_t index = 0;
    for (const std::uint8_t byte : bytes) {
        value.at(index / bytes_per_limb) |= std::uint32_t{byte} << (bits_per_byte * (index % bytes_per_limb));
        ++index;
    }
    return value;
}

crypto::ByteArray<crypto::x25519_key_size> store(const Field& value)
{
    crypto::ByteArray<crypto::x25519_key_size> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes.at(index) =
            static_cast<std::uint8_t>(value.at(index / bytes_per_limb) >> (bits_per_byte * (index % bytes_per_limb)));
    }
    return bytes;
}

}

crypto::ByteArray<crypto::x25519_key_size> x25519_twin(crypto::ByteView public_key)
{
    return store(power(load(public_key), prime_minus_two));
}

}
