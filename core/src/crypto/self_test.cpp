// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "self_test.hpp"

#include "hex.hpp"
#include "known_answers.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/ed25519.hpp"
#include "lume/crypto/hash.hpp"
#include "lume/crypto/kdf.hpp"
#include "lume/crypto/mlkem.hpp"
#include "lume/crypto/x25519.hpp"

#include <algorithm>
#include <expected>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace lume::crypto::detail {

namespace {

namespace ka = known_answers;

Bytes hex(std::string_view text)
{
    auto bytes = decode_hex(text);
    if (!bytes) {
        throw std::logic_error("malformed known answer");
    }
    return std::move(*bytes);
}

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

bool sha2_matches()
{
    const auto input = hex(ka::sha2_input);
    return same(sha256(input), hex(ka::sha256_digest)) && same(sha512(input), hex(ka::sha512_digest));
}

bool hmac_matches()
{
    return hmac_sha256(hex(ka::hmac_key), hex(ka::hmac_message)).equals(hex(ka::hmac_tag));
}

bool hkdf_matches()
{
    const auto expected = hex(ka::hkdf_output);
    const auto output = hkdf_sha256(hex(ka::hkdf_salt), hex(ka::hkdf_input_key), hex(ka::hkdf_info), expected.size());
    return output && output->equals(expected);
}

bool x25519_matches()
{
    const auto secret_key = SecretBytes::copy_of(hex(ka::x25519_secret_key));
    const auto shared = x25519_shared_secret(secret_key, hex(ka::x25519_peer_public_key));
    return shared && shared->equals(hex(ka::x25519_shared_secret));
}

bool x25519_rejects_low_order_point()
{
    const auto secret_key = SecretBytes::copy_of(hex(ka::x25519_secret_key));
    const Bytes identity_point(x25519_key_size, 0);
    const auto shared = x25519_shared_secret(secret_key, identity_point);
    return !shared && shared.error() == Error::weak_public_key;
}

bool ed25519_matches()
{
    const auto key_pair = ed25519_from_seed(SecretBytes::copy_of(hex(ka::ed25519_seed)));
    if (!key_pair || !same(key_pair->public_key, hex(ka::ed25519_public_key))) {
        return false;
    }
    const auto message = hex(ka::ed25519_message);
    const auto expected = hex(ka::ed25519_signature);
    const auto signature = ed25519_sign(key_pair->secret_key, message);
    return signature && same(*signature, expected) && ed25519_verify(key_pair->public_key, message, expected)
        && !ed25519_verify(key_pair->public_key, message, with_first_bit_flipped(expected));
}

bool aead_matches()
{
    const auto key = SecretBytes::copy_of(hex(ka::aead_key));
    const auto nonce = hex(ka::aead_nonce);
    const auto associated_data = hex(ka::aead_associated_data);
    const auto plaintext = hex(ka::aead_plaintext);
    const auto expected = hex(ka::aead_ciphertext);

    const auto sealed = aead_seal(key, nonce, associated_data, plaintext);
    if (!sealed || !same(*sealed, expected)) {
        return false;
    }
    const auto opened = aead_open(key, nonce, associated_data, expected);
    const auto forged = aead_open(key, nonce, associated_data, with_first_bit_flipped(expected));
    return opened && opened->equals(plaintext) && !forged;
}

bool mlkem_matches()
{
    const auto key_pair = mlkem768_from_seed(SecretBytes::copy_of(hex(ka::mlkem_key_seed)));
    if (!key_pair || !same(sha256(key_pair->public_key), hex(ka::mlkem_public_key_sha256))) {
        return false;
    }
    const auto shared = mlkem768_decapsulate(key_pair->secret_key, hex(ka::mlkem_ciphertext));
    return shared && shared->equals(hex(ka::mlkem_shared_secret));
}

bool mlkem_round_trips()
{
    const auto key_pair = mlkem768_generate();
    if (!key_pair) {
        return false;
    }
    const auto encapsulation = mlkem768_encapsulate(key_pair->public_key);
    if (!encapsulation) {
        return false;
    }
    const auto shared = mlkem768_decapsulate(key_pair->secret_key, encapsulation->ciphertext);
    return shared && shared->equals(encapsulation->shared_secret.view());
}

}

Result<void> run_self_test()
{
    const bool passed = sha2_matches() && hmac_matches() && hkdf_matches() && x25519_matches()
        && x25519_rejects_low_order_point() && ed25519_matches() && aead_matches() && mlkem_matches()
        && mlkem_round_trips();
    if (!passed) {
        return std::unexpected(Error::self_test_failed);
    }
    return {};
}

}
