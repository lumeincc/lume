# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

find_package(GTest CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(rapidcheck CONFIG REQUIRED)

add_executable(lume_core_tests
    support/curve.cpp
    support/hex.cpp
    support/hex_test.cpp
    support/vectors.cpp
    crypto/aead_test.cpp
    crypto/ed25519_test.cpp
    crypto/encoding_test.cpp
    crypto/hash_test.cpp
    crypto/kdf_test.cpp
    crypto/library_test.cpp
    crypto/mlkem_test.cpp
    crypto/random_test.cpp
    crypto/secret_bytes_test.cpp
    crypto/x25519_test.cpp
    handshake/handshake_test.cpp
    handshake/prekey_test.cpp
    identity/identity_test.cpp
    identity/phrase_test.cpp
    ratchet/ratchet_test.cpp
    safety/safety_number_test.cpp
    seal/padding_test.cpp
    seal/seal_test.cpp
    wire/codec_test.cpp
    wire/structures_test.cpp
)

target_include_directories(lume_core_tests PRIVATE . ../src)
target_link_libraries(lume_core_tests PRIVATE
    lume::core
    unofficial-sodium::sodium
    GTest::gtest_main
    rapidcheck
    rapidcheck_gtest
    nlohmann_json::nlohmann_json
)
target_compile_definitions(lume_core_tests PRIVATE
    LUME_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors"
    LUME_THIRD_PARTY_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../third_party"
    _SILENCE_CXX23_ALIGNED_STORAGE_DEPRECATION_WARNING
)
lume_configure_target(lume_core_tests)

include(GoogleTest)
set(LUME_PROPERTY_RUNS 500 CACHE STRING "Cases each property test checks")
set(LUME_FINGERPRINT_PROPERTY_RUNS 100 CACHE STRING "Cases each property over the 5200-round fingerprint checks")
gtest_discover_tests(lume_core_tests
    DISCOVERY_TIMEOUT 120
    DISCOVERY_EXTRA_ARGS --gtest_filter=-SafetyNumberProperties.*
    PROPERTIES ENVIRONMENT "RC_PARAMS=max_success=${LUME_PROPERTY_RUNS}"
)
gtest_discover_tests(lume_core_tests
    DISCOVERY_TIMEOUT 120
    DISCOVERY_EXTRA_ARGS --gtest_filter=SafetyNumberProperties.*
    PROPERTIES ENVIRONMENT "RC_PARAMS=max_success=${LUME_FINGERPRINT_PROPERTY_RUNS}"
)
