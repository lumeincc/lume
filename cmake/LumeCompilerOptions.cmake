# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

function(lume_configure_target target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive- /utf-8 /guard:cf)
        target_link_options(${target} PRIVATE /guard:cf)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
            target_compile_options(${target} PRIVATE /Zc:__cplusplus /Zc:preprocessor /sdl)
        else()
            target_compile_options(${target} PRIVATE
                -Wconversion -Wsign-conversion -Wshadow -Wnon-virtual-dtor -Wold-style-cast
                -Wcast-align -Wnull-dereference)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wnull-dereference
            -Werror -fstack-protector-strong)
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_compile_definitions(${target} PRIVATE _FORTIFY_SOURCE=3)
        endif()
    endif()

    if(LUME_SANITIZERS AND NOT MSVC)
        string(REPLACE ";" "," sanitizer_list "${LUME_SANITIZERS}")
        target_compile_options(${target} PRIVATE
            -fsanitize=${sanitizer_list} -fno-omit-frame-pointer -fno-sanitize-recover=all)
        target_link_options(${target} PRIVATE -fsanitize=${sanitizer_list})
    endif()

    if(LUME_COVERAGE AND NOT MSVC)
        target_compile_options(${target} PRIVATE --coverage -O0)
        target_link_options(${target} PRIVATE --coverage)
    endif()
endfunction()
