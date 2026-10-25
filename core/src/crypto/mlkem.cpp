// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/mlkem.hpp"

#include "backend.hpp"
#include "lume/crypto/random.hpp"
#include "mlkem_internal.hpp"

#include <oqs/oqs.h>

#include <cstddef>
#include <expected>
#include <stdexcept>
#include <utility>

namespace lume::crypto {

namespace {

constexpr std::size_t expanded_secret_key_size = 2400;

static_assert(OQS_KEM_ml_kem_768_length_public_key == mlkem768_public_key_size);
static_assert(OQS_KEM_ml_kem_768_length_secret_key == expanded_secret_key_size);
static_assert(OQS_KEM_ml_kem_768_length_ciphertext == mlkem768_ciphertext_size);
static_assert(OQS_KEM_ml_kem_768_length_shared_secret == mlkem768_shared_secret_size);
static_assert(OQS_KEM_ml_kem_768_length_keypair_seed == mlkem768_seed_size);
static_assert(OQS_KEM_ml_kem_768_length_encaps_seed == detail::mlkem768_encapsulation_randomness_size);

struct Expanded {
    Bytes public_key = Bytes(mlkem768_public_key_size);
    SecretBytes secret_key{expanded_secret_key_size};
};

Result<Expanded> expand(const SecretBytes& seed)
{
    if (seed.size() != mlkem768_seed_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::require_operational();
    Expanded expanded;
    if (OQS_KEM_ml_kem_768_keypair_derand(
            expanded.public_key.data(), expanded.secret_key.writable().data(), seed.view().data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::library_failure);
    }
    return expanded;
}

MlKemEncapsulation empty_encapsulation()
{
    return MlKemEncapsulation{
        .ciphertext = Bytes(mlkem768_ciphertext_size), .shared_secret = SecretBytes(mlkem768_shared_secret_size)};
}

}

MlKemKeyPair mlkem768_generate()
{
    auto key_pair = mlkem768_from_seed(random_secret(mlkem768_seed_size));
    if (!key_pair) {
        throw std::runtime_error("ML-KEM-768 key generation failed");
    }
    return std::move(*key_pair);
}

Result<MlKemKeyPair> mlkem768_from_seed(SecretBytes seed)
{
    auto expanded = expand(seed);
    if (!expanded) {
        return std::unexpected(expanded.error());
    }
    return MlKemKeyPair{.public_key = std::move(expanded->public_key), .seed = std::move(seed)};
}

Result<MlKemEncapsulation> mlkem768_encapsulate(ByteView public_key)
{
    if (public_key.size() != mlkem768_public_key_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::require_operational();
    auto encapsulation = empty_encapsulation();
    if (OQS_KEM_ml_kem_768_encaps(
            encapsulation.ciphertext.data(), encapsulation.shared_secret.writable().data(), public_key.data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::invalid_key);
    }
    return encapsulation;
}

Result<SecretBytes> mlkem768_decapsulate(const SecretBytes& seed, ByteView ciphertext)
{
    if (ciphertext.size() != mlkem768_ciphertext_size) {
        return std::unexpected(Error::invalid_size);
    }
    const auto expanded = expand(seed);
    if (!expanded) {
        return std::unexpected(expanded.error());
    }
    SecretBytes shared_secret(mlkem768_shared_secret_size);
    if (OQS_KEM_ml_kem_768_decaps(
            shared_secret.writable().data(), ciphertext.data(), expanded->secret_key.view().data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::library_failure);
    }
    return shared_secret;
}

namespace detail {

Result<MlKemEncapsulation> mlkem768_encapsulate_deterministic(ByteView public_key, const SecretBytes& randomness)
{
    if (public_key.size() != mlkem768_public_key_size
        || randomness.size() != mlkem768_encapsulation_randomness_size) {
        return std::unexpected(Error::invalid_size);
    }
    require_operational();
    auto encapsulation = empty_encapsulation();
    if (OQS_KEM_ml_kem_768_encaps_derand(
            encapsulation.ciphertext.data(), encapsulation.shared_secret.writable().data(), public_key.data(),
            randomness.view().data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::invalid_key);
    }
    return encapsulation;
}

}

}
