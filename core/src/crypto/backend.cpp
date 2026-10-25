// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "backend.hpp"

#include <oqs/oqs.h>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace lume::crypto::detail {

namespace {

void fill_from_sodium(std::uint8_t* output, std::size_t length)
{
    randombytes_buf(output, length);
}

bool start_backends()
{
    if (sodium_init() < 0) {
        return false;
    }
    OQS_init();
    OQS_randombytes_custom_algorithm(&fill_from_sodium);
    return true;
}

}

void ensure_backends_ready()
{
    static const bool ready = start_backends();
    if (!ready) {
        throw std::runtime_error("cryptographic backends could not be initialised");
    }
}

}
