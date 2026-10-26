// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "self_test.hpp"

#include "aead_internal.hpp"
#include "known_answers.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/mlkem.hpp"
#include "lume/crypto/random.hpp"
#include "lume/crypto/x25519.hpp"
#include "mlkem_internal.hpp"

#include <oqs/rand.h>

#include <algorithm>
#include <cstdint>
#include <expected>
#include <stdexcept>

namespace lume::crypto::detail {

namespace {

namespace ka = known_answers;

constexpr std::size_t random_sample_size = 32;

bool same(ByteView left, ByteView right)
{
    return std::ranges::equal(left, right);
}

Bytes with_first_bit_flipped(ByteView bytes)
{
    if (bytes.empty()) {
        throw std::logic_error("cannot flip a bit of nothing");
    }
    Bytes copy(bytes.begin(), bytes.end());
    copy.at(0) = static_cast<std::uint8_t>(copy.at(0) ^ 0x01U);
    return copy;
}

bool random_is_live()
{
    const auto first = random_public_bytes<random_sample_size>();
    const auto second = random_public_bytes<random_sample_size>();
    ByteArray<random_sample_size> first_from_oqs{};
    ByteArray<random_sample_size> second_from_oqs{};
    OQS_randombytes(first_from_oqs.data(), first_from_oqs.size());
    OQS_randombytes(second_from_oqs.data(), second_from_oqs.size());
    return !same(first, second) && !same(first_from_oqs, second_from_oqs);
}

bool sha2_matches()
{
    return same(sha256(ka::sha2_input), ka::sha256_digest) && same(sha512(ka::sha2_input), ka::sha512_digest)
        && sha256_secret({ka::sha2_input}).equals(ka::sha256_digest);
}

bool hmac_matches()
{
    return hmac_sha256(ka::hmac_key, ka::hmac_message).equals(ka::hmac_tag);
}

bool hkdf_matches()
{
    const auto output = hkdf_sha256(ka::hkdf_salt, ka::hkdf_input_key, ka::hkdf_info, ka::hkdf_output.size());
    return output && output->equals(ka::hkdf_output);
}

bool x25519_matches()
{
    const auto secret_key = SecretBytes::copy_of(ka::x25519_secret_key);
    const auto shared = x25519_shared_secret(secret_key, ka::x25519_peer_public_key);
    return shared && shared->equals(ka::x25519_shared_secret);
}

bool x25519_rejects_low_order_points()
{
    const auto secret_key = SecretBytes::copy_of(ka::x25519_secret_key);
    const auto rejected = [&secret_key](ByteView point) {
        const auto shared = x25519_shared_secret(secret_key, point);
        return !shared && shared.error() == Error::weak_public_key;
    };
    const Bytes zero_point(x25519_key_size, 0);
    return rejected(zero_point) && rejected(ka::x25519_low_order_point);
}

bool ed25519_matches()
{
    const auto key_pair = ed25519_from_seed(SecretBytes::copy_of(ka::ed25519_seed));
    if (!key_pair || !same(key_pair->public_key, ka::ed25519_public_key)) {
        return false;
    }
    const auto signature = ed25519_sign(key_pair->seed, ka::ed25519_message);
    return signature && same(*signature, ka::ed25519_signature)
        && ed25519_verify(key_pair->public_key, ka::ed25519_message, ka::ed25519_signature)
        && !ed25519_verify(key_pair->public_key, ka::ed25519_message, with_first_bit_flipped(ka::ed25519_signature));
}

bool ed25519_rejects_keys_outside_the_prime_order_subgroup()
{
    return !ed25519_verify(
               ka::ed25519_small_order_public_key, ka::ed25519_forgery_message, ka::ed25519_forgery_signature)
        && !ed25519_verify(
            ka::ed25519_mixed_order_public_key, ka::ed25519_mixed_order_message, ka::ed25519_mixed_order_signature);
}

bool aead_matches()
{
    const auto key = SecretBytes::copy_of(ka::aead_key);
    const auto ciphertext = aead_encrypt(key, ka::aead_nonce, ka::aead_associated_data, ka::aead_plaintext);
    if (!ciphertext || !same(*ciphertext, ka::aead_ciphertext)) {
        return false;
    }
    const auto opened = aead_decrypt(key, ka::aead_nonce, ka::aead_associated_data, ka::aead_ciphertext);
    const auto forged =
        aead_decrypt(key, ka::aead_nonce, ka::aead_associated_data, with_first_bit_flipped(ka::aead_ciphertext));
    return opened && opened->equals(ka::aead_plaintext) && !forged;
}

bool aead_round_trips()
{
    const auto key = random_secret(aead_key_size);
    const auto first = aead_seal(key, ka::aead_associated_data, ka::aead_plaintext);
    const auto second = aead_seal(key, ka::aead_associated_data, ka::aead_plaintext);
    if (!first || !second || same(*first, *second)) {
        return false;
    }
    const auto opened = aead_open(key, ka::aead_associated_data, *first);
    return opened && opened->equals(ka::aead_plaintext);
}

bool mlkem_matches()
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(ka::mlkem_key_seed));
    if (!key_pair || !same(sha256(key_pair->public_key), ka::mlkem_public_key_sha256)) {
        return false;
    }
    const auto shared = mlkem768_decapsulate(key_pair->seed, ka::mlkem_ciphertext);
    return shared && shared->equals(ka::mlkem_shared_secret);
}

bool mlkem_rejects_implicitly()
{
    const auto shared = mlkem768_decapsulate(
        SecretBytes::copy_of(ka::mlkem_rejection_key_seed), ka::mlkem_rejection_ciphertext);
    return shared && shared->equals(ka::mlkem_rejection_shared_secret);
}

bool mlkem_encapsulation_matches()
{
    const auto encapsulation = mlkem768_encapsulate_deterministic(
        ka::mlkem_encapsulation_public_key, SecretBytes::copy_of(ka::mlkem_encapsulation_randomness));
    return encapsulation && same(sha256(encapsulation->ciphertext), ka::mlkem_encapsulation_ciphertext_sha256)
        && encapsulation->shared_secret.equals(ka::mlkem_encapsulation_shared_secret);
}

bool mlkem_round_trips()
{
    const auto key_pair = mlkem768_from_seed(random_secret(mlkem768_seed_size));
    if (!key_pair) {
        return false;
    }
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    if (!encapsulation) {
        return false;
    }
    const auto shared = mlkem768_decapsulate(key_pair->seed, encapsulation->ciphertext);
    return shared && shared->equals(encapsulation->shared_secret.view());
}

}

Result<void> run_self_test()
{
    const bool passed = random_is_live() && sha2_matches() && hmac_matches() && hkdf_matches() && x25519_matches()
        && x25519_rejects_low_order_points() && ed25519_matches() && ed25519_rejects_keys_outside_the_prime_order_subgroup()
        && aead_matches() && aead_round_trips() && mlkem_matches() && mlkem_rejects_implicitly()
        && mlkem_encapsulation_matches() && mlkem_round_trips();
    if (!passed) {
        return std::unexpected(Error::self_test_failed);
    }
    return {};
}

}
