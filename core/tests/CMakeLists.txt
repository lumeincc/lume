# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

find_package(GTest CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(rapidcheck CONFIG REQUIRED)

add_executable(lume_core_tests
    support/curve.cpp
    support/hex.cpp
    support/hex_test.cpp
    support/memory_vfs.cpp
    support/store_fixture.cpp
    support/vectors.cpp
    card/card_test.cpp
    crypto/aead_test.cpp
    crypto/ed25519_test.cpp
    crypto/encoding_test.cpp
    crypto/hash_test.cpp
    crypto/kdf_test.cpp
    crypto/library_test.cpp
    crypto/mlkem_test.cpp
    crypto/padding_test.cpp
    crypto/pwhash_test.cpp
    crypto/random_test.cpp
    crypto/secret_bytes_test.cpp
    crypto/wiping_allocator_test.cpp
    crypto/x25519_test.cpp
    directory/directory_test.cpp
    handshake/handshake_test.cpp
    handshake/prekey_test.cpp
    identity/identity_test.cpp
    identity/phrase_test.cpp
    ratchet/ratchet_test.cpp
    safety/safety_number_test.cpp
    seal/padding_test.cpp
    seal/seal_test.cpp
    vault/index_test.cpp
    vault/store_test.cpp
    vault/vault_secure_delete_test.cpp
    vault/vault_store_hostile_test.cpp
    vault/vault_test.cpp
    wire/codec_test.cpp
    wire/structures_test.cpp
)

add_executable(lume_store_probe vault/store_probe.cpp)
target_include_directories(lume_store_probe PRIVATE ../src)
target_link_libraries(lume_store_probe PRIVATE lume::core)
lume_configure_target(lume_store_probe)

target_include_directories(lume_core_tests PRIVATE . ../src)
target_link_libraries(lume_core_tests PRIVATE
    lume::core
    unofficial-sodium::sodium
    unofficial::sqlite3::sqlite3
    GTest::gtest_main
    rapidcheck
    rapidcheck_gtest
    nlohmann_json::nlohmann_json
)
target_compile_definitions(lume_core_tests PRIVATE
    LUME_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors"
    LUME_THIRD_PARTY_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../third_party"
    LUME_STORE_PROBE="$<TARGET_FILE:lume_store_probe>"
    _SILENCE_CXX23_ALIGNED_STORAGE_DEPRECATION_WARNING
)
lume_configure_target(lume_core_tests)
add_dependencies(lume_core_tests lume_store_probe)

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
