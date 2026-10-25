// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/identity/phrase.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const auto entropy = lume::identity::entropy_from_phrase(std::span<const std::uint8_t>(data, size));
    if (!entropy) {
        return 0;
    }
    const auto phrase = lume::identity::phrase_from_entropy(*entropy);
    if (!phrase) {
        std::abort();
    }
    const auto again = lume::identity::entropy_from_phrase(phrase->view());
    if (!again || !again->equals(entropy->view())) {
        std::abort();
    }
    return 0;
}
