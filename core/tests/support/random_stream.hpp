// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "lume/crypto/bytes.hpp"
#include "lume/crypto/encoding.hpp"
#include "lume/crypto/hash.hpp"

#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <utility>

namespace lume::test {

class RandomStream {
public:
    explicit RandomStream(std::string seed)
        : seed_(std::move(seed))
    {
    }

    void operator()(std::span<std::uint8_t> output)
    {
        for (auto& byte : output) {
            if (pool_.empty()) {
                const crypto::Bytes seed(seed_.begin(), seed_.end());
                const auto block = crypto::sha256({seed, crypto::Encoder{}.u64(counter_).view()});
                ++counter_;
                pool_.assign(block.begin(), block.end());
            }
            byte = pool_.front();
            pool_.pop_front();
        }
    }

private:
    std::string seed_;
    std::uint64_t counter_ = 0;
    std::deque<std::uint8_t> pool_;
};

}
