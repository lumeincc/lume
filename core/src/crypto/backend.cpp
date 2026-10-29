// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "backend.hpp"

#include "memory_lock.hpp"
#include "self_test.hpp"

#include <oqs/oqs.h>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <stdexcept>

namespace lume::crypto::detail {

namespace {

bool& running_self_test() noexcept
{
    thread_local bool running = false;
    return running;
}

class SelfTestScope {
public:
    SelfTestScope() noexcept { running_self_test() = true; }
    ~SelfTestScope() { running_self_test() = false; }
    SelfTestScope(const SelfTestScope&) = delete;
    SelfTestScope& operator=(const SelfTestScope&) = delete;
    SelfTestScope(SelfTestScope&&) = delete;
    SelfTestScope& operator=(SelfTestScope&&) = delete;
};

void fill_from_sodium(std::uint8_t* output, std::size_t length)
{
    randombytes_buf(output, length);
}

Result<void> start() noexcept
{
    try {
        if (sodium_init() < 0) {
            return std::unexpected(Error::library_failure);
        }
        raise_lock_limit();
        OQS_init();
        OQS_randombytes_custom_algorithm(&fill_from_sodium);
        const SelfTestScope scope;
        return run_self_test();
    } catch (const std::exception&) {
        return std::unexpected(Error::library_failure);
    }
}

}

Result<void> operational_state()
{
    if (running_self_test()) {
        return {};
    }
    static const Result<void> state = start();
    return state;
}

void require_operational()
{
    throw_unless_operational(operational_state());
}

void throw_unless_operational(const Result<void>& state)
{
    if (!state) {
        throw std::runtime_error(
            state.error() == Error::self_test_failed ? "the cryptographic self-test failed"
                                                     : "the cryptographic libraries could not be started");
    }
}

}
