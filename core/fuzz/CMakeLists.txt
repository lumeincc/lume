# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "LUME_BUILD_FUZZERS needs Clang and libFuzzer")
endif()

function(lume_add_fuzzer name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE lume::core)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
    lume_configure_target(${name})
endfunction()

lume_add_fuzzer(lume_padding_fuzzer padding_fuzzer.cpp)
lume_add_fuzzer(lume_phrase_fuzzer phrase_fuzzer.cpp)
lume_add_fuzzer(lume_wire_fuzzer wire_fuzzer.cpp)
