# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(liboqs CONFIG REQUIRED)

add_library(lume_core STATIC
    src/crypto/aead.cpp
    src/crypto/backend.cpp
    src/crypto/ed25519.cpp
    src/crypto/encoding.cpp
    src/crypto/hash.cpp
    src/crypto/kdf.cpp
    src/crypto/library.cpp
    src/crypto/memory_lock.cpp
    src/crypto/mlkem.cpp
    src/crypto/random.cpp
    src/crypto/secret_bytes.cpp
    src/crypto/self_test.cpp
    src/crypto/x25519.cpp
    src/handshake/handshake.cpp
    src/handshake/prekey.cpp
    src/identity/identity.cpp
    src/identity/phrase.cpp
    src/ratchet/ratchet.cpp
    src/ratchet/skipped_keys.cpp
    src/safety/safety_number.cpp
    src/seal/padding.cpp
    src/seal/seal.cpp
    src/wire/codec.cpp
    src/wire/structures.cpp
)
add_library(lume::core ALIAS lume_core)

target_include_directories(lume_core
    PUBLIC include
    PRIVATE src
)
target_link_libraries(lume_core PRIVATE unofficial-sodium::sodium OQS::oqs)
target_compile_features(lume_core PUBLIC cxx_std_23)
lume_configure_target(lume_core)

if(LUME_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(LUME_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
