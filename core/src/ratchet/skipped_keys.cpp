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

std::span<std::uint8_t> slots(crypto::SecretBytes& arena, std::size_t first, std::size_t count)
{
    return arena.writable().subspan(first * key_size, count * key_size);
}

crypto::ByteView slot(const crypto::SecretBytes& arena, std::size_t index)
{
    return arena.view().subspan(index * key_size, key_size);
}

void move_slot(crypto::SecretBytes& arena, std::size_t from, std::size_t to)
{
    if (from != to) {
        std::ranges::copy(slot(std::as_const(arena), from), slots(arena, to, 1).begin());
    }
}

void clear_slots(crypto::SecretBytes& arena, std::size_t from, std::size_t to)
{
    if (from < to) {
        std::ranges::fill(slots(arena, from, to - from), std::uint8_t{0});
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
    const std::size_t entries_before = entries_.size();
    std::size_t read = 0;
    std::size_t written = 0;
    std::size_t chains_kept = 0;
    for (std::size_t chain = 0; chain < chains_before; ++chain) {
        std::size_t kept = 0;
        for (std::size_t index = 0; index < chains_.at(chain).count; ++index) {
            if (keep(chain, read, entries_.at(read))) {
                move_slot(message_keys_, read, written);
                entries_.at(written) = entries_.at(read);
                ++written;
                ++kept;
            }
            ++read;
        }
        if (kept == 0) {
            continue;
        }
        move_slot(header_keys_, chain, chains_kept);
        chains_.at(chains_kept) = Chain{.ratchet_key = chains_.at(chain).ratchet_key, .count = kept};
        ++chains_kept;
    }
    chains_.erase(chains_.begin() + static_cast<std::ptrdiff_t>(chains_kept), chains_.end());
    entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(written), entries_.end());
    clear_slots(message_keys_, written, entries_before);
    clear_slots(header_keys_, chains_kept, chains_before);
}

SkippedKeys SkippedKeys::clone() const
{
    SkippedKeys copy;
    copy.header_keys_ = header_keys_.clone();
    copy.message_keys_ = message_keys_.clone();
    copy.chains_ = chains_;
    copy.entries_ = entries_;
    return copy;
}

std::size_t SkippedKeys::size() const noexcept
{
    return entries_.size();
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
    const auto count = chains_.at(chain).count;
    return std::span<const SkippedEntry>(entries_).subspan(offset(chain), count);
}

crypto::ByteView SkippedKeys::message_key(std::size_t chain, std::size_t index) const
{
    if (index >= chains_.at(chain).count) {
        throw std::out_of_range("no such skipped key");
    }
    return slot(message_keys_, offset(chain) + index);
}

std::optional<std::size_t> SkippedKeys::find(std::size_t chain, std::uint32_t number) const
{
    const auto chain_entries = entries(chain);
    const auto match = std::ranges::find(chain_entries, number, &SkippedEntry::number);
    if (match == chain_entries.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(match - chain_entries.begin());
}

void SkippedKeys::reserve(std::size_t limit)
{
    const auto bound = std::min(limit, max_skipped_keys);
    if (bound == 0) {
        return;
    }
    if (header_keys_.empty()) {
        header_keys_ = crypto::SecretBytes(max_skipped_header_keys * key_size);
    }
    if (message_keys_.size() < bound * key_size) {
        crypto::SecretBytes larger(bound * key_size);
        std::ranges::copy(message_keys_.view().first(entries_.size() * key_size), larger.writable().begin());
        message_keys_ = std::move(larger);
    }
    chains_.reserve(max_skipped_header_keys);
    entries_.reserve(bound);
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
    reserve(bound);
    const auto kept = std::min(count, bound);
    const auto first = count - kept;
    if (entries_.size() + kept > bound) {
        const auto dropped = entries_.size() + kept - bound;
        keep_only([dropped](std::size_t, std::size_t position, const SkippedEntry&) { return position >= dropped; });
    }
    if (!continues_last_chain(header_key, ratchet_key)) {
        if (chains_.size() == max_skipped_header_keys) {
            keep_only([](std::size_t chain, std::size_t, const SkippedEntry&) { return chain != 0; });
        }
        std::ranges::copy(header_key.view(), slots(header_keys_, chains_.size(), 1).begin());
        chains_.push_back(Chain{.ratchet_key = ratchet_key, .count = 0});
    }
    std::ranges::copy(message_keys.subspan(first * key_size), slots(message_keys_, entries_.size(), kept).begin());
    for (std::size_t position = first; position < count; ++position) {
        entries_.push_back(
            SkippedEntry{.number = first_number + static_cast<std::uint32_t>(position), .stored_at = stored_at});
    }
    chains_.back().count += kept;
}

void SkippedKeys::erase(std::size_t chain, std::size_t index)
{
    if (index >= chains_.at(chain).count) {
        throw std::out_of_range("no such skipped key");
    }
    const auto target = offset(chain) + index;
    keep_only([target](std::size_t, std::size_t position, const SkippedEntry&) { return position != target; });
}

void SkippedKeys::expire(std::uint64_t now)
{
    keep_only([now](std::size_t, std::size_t, const SkippedEntry& entry) { return !expired(entry, now); });
}

std::size_t SkippedKeys::offset(std::size_t chain) const
{
    std::size_t total = 0;
    for (std::size_t before = 0; before < chain; ++before) {
        total += chains_.at(before).count;
    }
    return total;
}

bool SkippedKeys::continues_last_chain(const crypto::SecretBytes& header_key, const RatchetKey& ratchet_key) const
{
    return !chains_.empty() && chains_.back().ratchet_key == ratchet_key
        && header_key.equals(slot(header_keys_, chains_.size() - 1));
}

}
