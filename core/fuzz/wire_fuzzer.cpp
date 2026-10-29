// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/wire/structures.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

namespace {

template <typename Read>
void expect_canonical(std::span<const std::uint8_t> input, Read read)
{
    const auto decoded = lume::wire::decode(input, read);
    if (!decoded) {
        return;
    }
    const auto encoded = lume::wire::encode(*decoded);
    if (!std::ranges::equal(encoded, input)) {
        std::abort();
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::span<const std::uint8_t> input(data, size);
    if (input.empty()) {
        return 0;
    }
    const auto body = input.subspan(1);
    switch (input.front() % 11) {
    case 0:
        expect_canonical(body, lume::wire::read_prekey_x);
        break;
    case 1:
        expect_canonical(body, lume::wire::read_prekey_kem);
        break;
    case 2:
        expect_canonical(body, lume::wire::read_initial_header);
        break;
    case 3:
        expect_canonical(body, lume::wire::read_ratchet_header);
        break;
    case 4:
        expect_canonical(body, lume::wire::read_ratchet_message);
        break;
    case 5:
        expect_canonical(body, lume::wire::read_inner);
        break;
    case 6:
        expect_canonical(body, lume::wire::read_seal);
        break;
    case 7:
        expect_canonical(body, lume::wire::read_username_certificate);
        break;
    case 8:
        expect_canonical(body, lume::wire::read_introduction);
        break;
    case 9:
        expect_canonical(body, lume::wire::read_content);
        break;
    default:
        expect_canonical(body, lume::wire::read_directory_keys);
        break;
    }
    return 0;
}
