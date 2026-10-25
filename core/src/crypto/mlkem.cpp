// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/crypto/mlkem.hpp"

#include "backend.hpp"

#include <oqs/oqs.h>

#include <expected>

namespace lume::crypto {

static_assert(OQS_KEM_ml_kem_768_length_public_key == mlkem768_public_key_size);
static_assert(OQS_KEM_ml_kem_768_length_secret_key == mlkem768_secret_key_size);
static_assert(OQS_KEM_ml_kem_768_length_ciphertext == mlkem768_ciphertext_size);
static_assert(OQS_KEM_ml_kem_768_length_shared_secret == mlkem768_shared_secret_size);
static_assert(OQS_KEM_ml_kem_768_length_keypair_seed == mlkem768_key_seed_size);
static_assert(OQS_KEM_ml_kem_768_length_encaps_seed == mlkem768_encapsulation_seed_size);

namespace {

MlKemKeyPair empty_key_pair()
{
    return MlKemKeyPair{
        .public_key = Bytes(mlkem768_public_key_size), .secret_key = SecretBytes(mlkem768_secret_key_size)};
}

MlKemEncapsulation empty_encapsulation()
{
    return MlKemEncapsulation{
        .ciphertext = Bytes(mlkem768_ciphertext_size), .shared_secret = SecretBytes(mlkem768_shared_secret_size)};
}

}

Result<MlKemKeyPair> mlkem768_generate()
{
    detail::ensure_backends_ready();
    auto key_pair = empty_key_pair();
    if (OQS_KEM_ml_kem_768_keypair(key_pair.public_key.data(), key_pair.secret_key.writable().data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::library_failure);
    }
    return key_pair;
}

Result<MlKemKeyPair> mlkem768_from_seed(const SecretBytes& seed)
{
    if (seed.size() != mlkem768_key_seed_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::ensure_backends_ready();
    auto key_pair = empty_key_pair();
    if (OQS_KEM_ml_kem_768_keypair_derand(
            key_pair.public_key.data(), key_pair.secret_key.writable().data(), seed.view().data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::library_failure);
    }
    return key_pair;
}

Result<MlKemEncapsulation> mlkem768_encapsulate(ByteView public_key)
{
    if (public_key.size() != mlkem768_public_key_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::ensure_backends_ready();
    auto encapsulation = empty_encapsulation();
    if (OQS_KEM_ml_kem_768_encaps(
            encapsulation.ciphertext.data(), encapsulation.shared_secret.writable().data(), public_key.data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::invalid_key);
    }
    return encapsulation;
}

Result<MlKemEncapsulation> mlkem768_encapsulate_deterministic(ByteView public_key, const SecretBytes& seed)
{
    if (public_key.size() != mlkem768_public_key_size || seed.size() != mlkem768_encapsulation_seed_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::ensure_backends_ready();
    auto encapsulation = empty_encapsulation();
    if (OQS_KEM_ml_kem_768_encaps_derand(
            encapsulation.ciphertext.data(), encapsulation.shared_secret.writable().data(), public_key.data(),
            seed.view().data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::invalid_key);
    }
    return encapsulation;
}

Result<SecretBytes> mlkem768_decapsulate(const SecretBytes& secret_key, ByteView ciphertext)
{
    if (secret_key.size() != mlkem768_secret_key_size || ciphertext.size() != mlkem768_ciphertext_size) {
        return std::unexpected(Error::invalid_size);
    }
    detail::ensure_backends_ready();
    SecretBytes shared_secret(mlkem768_shared_secret_size);
    if (OQS_KEM_ml_kem_768_decaps(shared_secret.writable().data(), ciphertext.data(), secret_key.view().data())
        != OQS_SUCCESS) {
        return std::unexpected(Error::invalid_key);
    }
    return shared_secret;
}

}
