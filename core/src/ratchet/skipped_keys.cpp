// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "lume/ratchet/skipped_keys.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

namespace lume::ratchet {
namespace {

constexpr std::size_t key_size = 32;

std::span<std::uint8_t> slot(crypto::SecretBytes& arena, std::size_t index)
{
    return arena.writable().subspan(index * key_size, key_size);
}

crypto::ByteView slot(const crypto::SecretBytes& arena, std::size_t index)
{
    return arena.view().subspan(index * key_size, key_size);
}

void move_slot(crypto::SecretBytes& arena, std::size_t from, std::size_t to)
{
    if (from != to) {
        std::ranges::copy(slot(std::as_const(arena), from), slot(arena, to).begin());
    }
}

void clear_slots(crypto::SecretBytes& arena, std::size_t from, std::size_t to)
{
    if (from < to) {
        std::ranges::fill(arena.writable().subspan(from * key_size, (to - from) * key_size), std::uint8_t{0});
    }
}

bool expired(const SkippedEntry& entry, std::uint64_t now)
{
    return now > entry.stored_at && now - entry.stored_at > skipped_key_lifetime;
}

}

template <typename Keep>
void SkippedKeys::keep_only(Keep keep)
{
    const std::size_t chains_before = chains_.size();
    std::size_t read = 0;
    std::size_t written = 0;
    std::size_t chains_kept = 0;
    for (std::size_t chain = 0; chain < chains_before; ++chain) {
        auto& entries = chains_.at(chain).entries;
        std::size_t kept = 0;
        for (std::size_t index = 0; index < entries.size(); ++index) {
            if (keep(chain, index, entries.at(index))) {
                move_slot(message_keys_, read, written);
                entries.at(kept) = entries.at(index);
                ++kept;
                ++written;
            }
            ++read;
        }
        entries.resize(kept);
        if (kept == 0) {
            continue;
        }
        move_slot(header_keys_, chain, chains_kept);
        if (chains_kept != chain) {
            chains_.at(chains_kept) = std::move(chains_.at(chain));
        }
        ++chains_kept;
    }
    chains_.resize(chains_kept);
    clear_slots(message_keys_, written, read);
    clear_slots(header_keys_, chains_kept, chains_before);
}

SkippedKeys SkippedKeys::clone() const
{
    SkippedKeys copy;
    copy.header_keys_ = header_keys_.clone();
    copy.message_keys_ = message_keys_.clone();
    copy.chains_ = chains_;
    return copy;
}

std::size_t SkippedKeys::size() const noexcept
{
    std::size_t total = 0;
    for (const auto& chain : chains_) {
        total += chain.entries.size();
    }
    return total;
}

std::size_t SkippedKeys::chain_count() const noexcept
{
    return chains_.size();
}

crypto::ByteView SkippedKeys::header_key(std::size_t chain) const
{
    if (chain >= chains_.size()) {
        throw std::out_of_range("no such skipped chain");
    }
    return slot(header_keys_, chain);
}

const RatchetKey& SkippedKeys::ratchet_key(std::size_t chain) const
{
    return chains_.at(chain).ratchet_key;
}

std::span<const SkippedEntry> SkippedKeys::entries(std::size_t chain) const
{
    return chains_.at(chain).entries;
}

crypto::ByteView SkippedKeys::message_key(std::size_t chain, std::size_t index) const
{
    if (index >= chains_.at(chain).entries.size()) {
        throw std::out_of_range("no such skipped key");
    }
    return slot(message_keys_, offset(chain) + index);
}

std::optional<std::size_t> SkippedKeys::find(std::size_t chain, std::uint32_t number) const
{
    const auto& entries = chains_.at(chain).entries;
    const auto match = std::ranges::find(entries, number, &SkippedEntry::number);
    if (match == entries.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(match - entries.begin());
}

void SkippedKeys::add(
    const crypto::SecretBytes& header_key, const RatchetKey& ratchet_key, std::uint32_t first_number,
    crypto::ByteView message_keys, std::uint64_t stored_at, std::size_t limit)
{
    const auto bound = std::min(limit, max_skipped_keys);
    const auto count = message_keys.size() / key_size;
    if (bound == 0 || count == 0) {
        return;
    }
    reserve();
    for (std::size_t position = count > bound ? count - bound : 0; position < count; ++position) {
        while (size() >= bound) {
            erase(0, 0);
        }
        if (!continues_last_chain(header_key, ratchet_key)) {
            if (chains_.size() == max_skipped_header_keys) {
                keep_only([](std::size_t chain, std::size_t, const SkippedEntry&) { return chain != 0; });
            }
            std::ranges::copy(header_key.view(), slot(header_keys_, chains_.size()).begin());
            chains_.push_back(Chain{.ratchet_key = ratchet_key, .entries = {}});
        }
        std::ranges::copy(message_keys.subspan(position * key_size, key_size), slot(message_keys_, size()).begin());
        chains_.back().entries.push_back(
            SkippedEntry{.number = first_number + static_cast<std::uint32_t>(position), .stored_at = stored_at});
    }
}

void SkippedKeys::erase(std::size_t chain, std::size_t index)
{
    if (index >= chains_.at(chain).entries.size()) {
        throw std::out_of_range("no such skipped key");
    }
    keep_only([chain, index](std::size_t at_chain, std::size_t at_index, const SkippedEntry&) {
        return at_chain != chain || at_index != index;
    });
}

void SkippedKeys::expire(std::uint64_t now)
{
    keep_only([now](std::size_t, std::size_t, const SkippedEntry& entry) { return !expired(entry, now); });
}

std::size_t SkippedKeys::offset(std::size_t chain) const
{
    std::size_t total = 0;
    for (std::size_t before = 0; before < chain; ++before) {
        total += chains_.at(before).entries.size();
    }
    return total;
}

bool SkippedKeys::continues_last_chain(const crypto::SecretBytes& header_key, const RatchetKey& ratchet_key) const
{
    return !chains_.empty() && chains_.back().ratchet_key == ratchet_key
        && header_key.equals(slot(header_keys_, chains_.size() - 1));
}

void SkippedKeys::reserve()
{
    if (message_keys_.empty()) {
        message_keys_ = crypto::SecretBytes(max_skipped_keys * key_size);
        header_keys_ = crypto::SecretBytes(max_skipped_header_keys * key_size);
    }
}

}
