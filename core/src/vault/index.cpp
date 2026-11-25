// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/index.hpp"

#include "crypto/backend.hpp"
#include "lume/crypto/aead.hpp"
#include "lume/crypto/random.hpp"
#include "vault/index_internal.hpp"
#include "vault/vault_internal.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <ranges>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

namespace lume::vault {
namespace {

constexpr std::uint32_t count_bound = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint64_t counter_bound = std::numeric_limits<std::uint64_t>::max();

class Location {
public:
    Location(RecordType type, crypto::ByteView id, std::uint64_t counter, const Nonce& nonce)
        : located_{.address = {.type = type, .id = crypto::Bytes(id.begin(), id.end()), .counter = counter}, .nonce = nonce}
    {
    }

    Location(const Location&) = delete;
    Location& operator=(const Location&) = delete;
    Location(Location&&) = delete;
    Location& operator=(Location&&) = delete;

    ~Location()
    {
        crypto::detail::wipe(located_.address.id);
    }

    [[nodiscard]] const Located& located() const noexcept
    {
        return located_;
    }

    [[nodiscard]] const RecordAddress& address() const noexcept
    {
        return located_.address;
    }

    void place(const Nonce& nonce) noexcept
    {
        located_.nonce = nonce;
    }

private:
    Located located_;
};

struct Tally {
    std::size_t inserts = 0;
    std::size_t rewrites = 0;
    std::size_t erases = 0;
};

using KeyParts = std::tuple<std::piecewise_construct_t, std::tuple<RecordType>,
    std::tuple<crypto::ByteView::iterator, crypto::ByteView::iterator>>;

struct Sealed {
    crypto::Bytes address;
    crypto::Bytes record;
    Entry entry;
    Root term{};
};

Nonce leading_nonce(crypto::ByteView box) noexcept
{
    Nonce nonce{};
    std::ranges::copy(box.first(nonce.size()), nonce.begin());
    return nonce;
}

bool same_root(const Root& first, const Root& second) noexcept
{
    Root difference{};
    std::ranges::transform(first, second, difference.begin(),
        [](std::uint8_t left, std::uint8_t right) { return static_cast<std::uint8_t>(left ^ right); });
    return crypto::detail::is_zero(difference);
}

bool same_key(const Index::KeyView& first, const Index::KeyView& second) noexcept
{
    return first.type == second.type && std::ranges::equal(first.id, second.id);
}

KeyParts key_parts(const Change& change) noexcept
{
    return {std::piecewise_construct, std::tuple(change.type), std::tuple(change.id.begin(), change.id.end())};
}

std::vector<wire::ManifestEntry> listed(const TypeStates& types)
{
    std::vector<wire::ManifestEntry> entries;
    for (auto&& [type, state] : std::views::zip(std::views::iota(std::size_t{0}), types)) {
        if (state.count > 0) {
            entries.push_back(wire::ManifestEntry{.type = static_cast<std::uint8_t>(type), .count = state.count, .root = state.root});
        }
    }
    return entries;
}

std::size_t live_types(const TypeStates& types) noexcept
{
    return static_cast<std::size_t>(std::ranges::count_if(types, [](const TypeState& state) { return state.count > 0; }));
}

Result<void> validate(std::span<const Change> changes)
{
    std::vector<Index::KeyView> keys;
    keys.reserve(changes.size());
    for (const auto& change : changes) {
        if (change.type == 0 || change.id.size() > record_id_bound) {
            return std::unexpected(Error::invalid_parameters);
        }
        if (change.payload && change.payload->size() > payload_bound) {
            return std::unexpected(Error::record_too_large);
        }
        keys.push_back(Index::KeyView{.type = change.type, .id = change.id});
    }
    std::ranges::sort(keys, Index::Order{});
    if (std::ranges::adjacent_find(keys, same_key) != keys.end()) {
        return std::unexpected(Error::invalid_parameters);
    }
    return {};
}

Result<void> count(TypeState& state, Tally& tally, const Change& change, const Entry* entry)
{
    if (change.payload && entry == nullptr) {
        if (state.count == count_bound) {
            return std::unexpected(Error::invalid_parameters);
        }
        ++state.count;
        ++tally.inserts;
        return {};
    }
    if (change.payload) {
        if (entry->counter >= counter_bound - 1) {
            return std::unexpected(Error::invalid_parameters);
        }
        ++tally.rewrites;
        return {};
    }
    if (entry == nullptr) {
        return {};
    }
    if (state.count == 0) {
        return std::unexpected(Error::integrity);
    }
    --state.count;
    ++tally.erases;
    return {};
}

void reserve(Plan& plan, const Tally& tally)
{
    plan.rows.reserve(tally.inserts + tally.rewrites + tally.erases);
    plan.new_nodes.reserve(tally.inserts);
    plan.replaced.reserve(tally.rewrites);
    plan.erased.reserve(tally.erases);
}

Nonce fresh_nonce()
{
    return crypto::random_public_bytes<crypto::aead_nonce_size>();
}

detail::Draws fresh_draws()
{
    return detail::Draws{.slot = fresh_slot, .record_nonce = fresh_nonce, .address_nonce = fresh_nonce, .manifest_nonce = fresh_nonce};
}

struct Sealer {
    const Keys* keys = nullptr;
    const TermHasher* hasher = nullptr;
    const detail::Draws* draws = nullptr;
};

Result<Sealed> seal(const Sealer& sealer, const Change& change, crypto::ByteView payload, std::uint64_t slot, std::uint64_t counter)
{
    Location location(change.type, change.id, counter, Nonce{});
    auto record = detail::seal_record(*sealer.keys, location.address(), payload, sealer.draws->record_nonce());
    if (!record) {
        return std::unexpected(record.error());
    }
    const auto nonce = nonce_of(*record);
    if (!nonce) {
        return std::unexpected(nonce.error());
    }
    location.place(*nonce);
    auto address = detail::seal_address(*sealer.keys, slot, location.located(), sealer.draws->address_nonce());
    if (!address) {
        return std::unexpected(address.error());
    }
    const auto term = sealer.hasher->term(location.address(), *nonce);
    if (!term) {
        return std::unexpected(term.error());
    }
    const Entry entry{.slot = slot, .counter = counter, .nonce = *nonce, .address_nonce = leading_nonce(*address)};
    return Sealed{.address = std::move(*address), .record = std::move(*record), .entry = entry, .term = *term};
}

Result<Root> held_term(const TermHasher& hasher, const Change& change, const Entry& entry)
{
    const Location location(change.type, change.id, entry.counter, entry.nonce);
    return hasher.term(location.address(), entry.nonce);
}

Result<void> plan_insert(Plan& plan, Index::Map& holder, const Sealer& sealer, const Change& change, crypto::ByteView payload)
{
    const auto slot = sealer.draws->slot();
    auto sealed = seal(sealer, change, payload, slot, 0);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    auto& state = plan.types.at(change.type);
    state.root = add_term(state.root, sealed->term);
    const auto where = holder.emplace(std::piecewise_construct, key_parts(change), std::forward_as_tuple(sealed->entry)).first;
    plan.new_nodes.push_back(holder.extract(where));
    plan.rows.push_back(RowChange{.write = RowWrite::insert,
        .slot = sealed->entry.slot,
        .address = std::move(sealed->address),
        .record = std::move(sealed->record),
        .old_address_nonce = {},
        .old_record_nonce = {}});
    return {};
}

Result<void> plan_rewrite(Plan& plan, const Sealer& sealer, const Change& change, crypto::ByteView payload, const Entry& entry)
{
    auto sealed = seal(sealer, change, payload, entry.slot, entry.counter + 1);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    const auto held = held_term(*sealer.hasher, change, entry);
    if (!held) {
        return std::unexpected(held.error());
    }
    auto& state = plan.types.at(change.type);
    state.root = add_term(remove_term(state.root, *held), sealed->term);
    plan.replaced.emplace_back(std::piecewise_construct, key_parts(change), std::forward_as_tuple(sealed->entry));
    plan.rows.push_back(RowChange{.write = RowWrite::replace,
        .slot = entry.slot,
        .address = std::move(sealed->address),
        .record = std::move(sealed->record),
        .old_address_nonce = entry.address_nonce,
        .old_record_nonce = entry.nonce});
    return {};
}

Result<void> plan_erase(Plan& plan, const TermHasher& hasher, const Change& change, const Entry& entry)
{
    const auto held = held_term(hasher, change, entry);
    if (!held) {
        return std::unexpected(held.error());
    }
    auto& state = plan.types.at(change.type);
    state.root = remove_term(state.root, *held);
    plan.erased.emplace_back(std::piecewise_construct, std::tuple(change.type), std::tuple(change.id.begin(), change.id.end()));
    plan.rows.push_back(RowChange{.write = RowWrite::erase,
        .slot = entry.slot,
        .address = {},
        .record = {},
        .old_address_nonce = entry.address_nonce,
        .old_record_nonce = entry.nonce});
    return {};
}

Result<void> plan_change(Plan& plan, Index::Map& holder, const Sealer& sealer, const Change& change, const Entry* entry)
{
    if (change.payload && entry == nullptr) {
        return plan_insert(plan, holder, sealer, change, *change.payload);
    }
    if (change.payload) {
        return plan_rewrite(plan, sealer, change, *change.payload, *entry);
    }
    if (entry == nullptr) {
        return {};
    }
    return plan_erase(plan, *sealer.hasher, change, *entry);
}

}

const Entry* Index::find(RecordType type, crypto::ByteView id) const noexcept
{
    const auto found = entries_.find(KeyView{.type = type, .id = id});
    return found == entries_.end() ? nullptr : &found->second;
}

Result<void> Index::admit(const Located& located, std::uint64_t slot, const Nonce& address_nonce, const Root& term)
{
    const auto& address = located.address;
    if (address.type == 0 || address.id.size() > record_id_bound || slot == 0 || slot > slot_bound
        || address.counter == counter_bound) {
        return std::unexpected(Error::integrity);
    }
    auto& state = types_.at(address.type);
    if (state.count == count_bound) {
        return std::unexpected(Error::integrity);
    }
    const Entry entry{.slot = slot, .counter = address.counter, .nonce = located.nonce, .address_nonce = address_nonce};
    const auto placed = entries_.emplace(std::piecewise_construct,
        std::forward_as_tuple(std::piecewise_construct, std::tuple(address.type), std::tuple(address.id.begin(), address.id.end())),
        std::forward_as_tuple(entry));
    if (!placed.second) {
        return std::unexpected(Error::integrity);
    }
    ++state.count;
    state.root = add_term(state.root, term);
    return {};
}

Result<wire::Manifest> Index::manifest(std::uint64_t epoch) const
{
    auto types = listed(types_);
    if (types.size() > wire::manifest_types_bound) {
        return std::unexpected(Error::integrity);
    }
    return wire::Manifest{.epoch = epoch, .types = std::move(types)};
}

bool Index::matches(const wire::Manifest& manifest) const noexcept
{
    auto listed_type = manifest.types.begin();
    bool same = true;
    for (auto&& [type, state] : std::views::zip(std::views::iota(std::size_t{0}), types_)) {
        if (state.count == 0) {
            continue;
        }
        if (listed_type == manifest.types.end() || listed_type->type != type || listed_type->count != state.count) {
            return false;
        }
        same = same_root(listed_type->root, state.root) && same;
        ++listed_type;
    }
    return same && listed_type == manifest.types.end();
}

std::uint64_t Index::records() const noexcept
{
    return entries_.size();
}

const Index::Map& Index::entries() const noexcept
{
    return entries_;
}

Result<Plan> Index::plan(const OpenedHeader& opened, const TermHasher& hasher, std::span<const Change> changes) const
{
    return detail::plan(*this, opened, hasher, changes, fresh_draws());
}

void Index::apply(Plan&& plan) noexcept
{
    for (const auto& key : plan.erased) {
        if (const auto found = entries_.find(key); found != entries_.end()) {
            entries_.erase(found);
        }
    }
    for (const auto& [key, entry] : plan.replaced) {
        if (const auto found = entries_.find(key); found != entries_.end()) {
            found->second = entry;
        }
    }
    types_ = plan.types;
    for (auto& node : std::move(plan).new_nodes) {
        static_cast<void>(entries_.insert(std::move(node)));
    }
}

namespace detail {

Result<Plan> plan(const Index& index, const OpenedHeader& opened, const TermHasher& hasher, std::span<const Change> changes,
    const Draws& draws)
{
    if (const auto valid = validate(changes); !valid) {
        return std::unexpected(valid.error());
    }
    Plan next;
    next.types = index.types_;
    Tally tally;
    std::vector<const Entry*> held;
    held.reserve(changes.size());
    for (const auto& change : changes) {
        held.push_back(index.find(change.type, change.id));
        if (const auto counted = count(next.types.at(change.type), tally, change, held.back()); !counted) {
            return std::unexpected(counted.error());
        }
    }
    if (live_types(next.types) > wire::manifest_types_bound) {
        return std::unexpected(Error::invalid_parameters);
    }
    reserve(next, tally);
    Index::Map holder;
    const Sealer sealer{.keys = &opened.keys(), .hasher = &hasher, .draws = &draws};
    for (auto&& [change, entry] : std::views::zip(changes, held)) {
        if (const auto planned = plan_change(next, holder, sealer, change, entry); !planned) {
            return std::unexpected(planned.error());
        }
    }
    auto sealed = detail::seal_manifest(opened, listed(next.types), draws.manifest_nonce());
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    next.manifest = std::move(*sealed);
    return next;
}

}

}
