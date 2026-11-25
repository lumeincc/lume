// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/index.hpp"

#include "crypto/wiping_allocator.hpp"
#include "lume/crypto/bytes.hpp"
#include "lume/crypto/secret_bytes.hpp"
#include "lume/vault/vault.hpp"
#include "lume/wire/structures.hpp"
#include "support/expected.hpp"
#include "support/store_fixture.hpp"
#include "support/wiping_ledger.hpp"
#include "vault/keys.hpp"
#include "vault/records.hpp"
#include "vault/store.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lume::vault {
namespace {

using crypto::Bytes;
using crypto::ByteView;
using test::Backing;
using test::error_of;
using test::Material;
using test::must;
using test::Place;

constexpr std::uint64_t last_counter = std::numeric_limits<std::uint64_t>::max();
constexpr std::uint32_t last_count = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint8_t record_nonce_kind = 1;
constexpr std::uint8_t address_nonce_kind = 2;

struct Op {
    RecordType type = 0;
    Bytes id;
    std::optional<Bytes> payload;
};

struct Modelled {
    Bytes payload;
    std::uint64_t counter = 0;
};

using ModelKey = std::pair<RecordType, Bytes>;
using Model = std::map<ModelKey, Modelled>;
using Snapshot = std::map<ModelKey, Entry>;

const OpenedHeader& opened()
{
    return Material::keystore().opened();
}

const TermHasher& hasher()
{
    static const auto made = must(TermHasher::of(opened().keys()));
    return made;
}

std::uint64_t epoch()
{
    return opened().header().epoch;
}

Op put(RecordType type, std::string_view id, std::size_t size, std::uint8_t seed)
{
    return Op{.type = type, .id = test::bytes_of(id), .payload = test::patterned(size, seed)};
}

Op removal(RecordType type, std::string_view id)
{
    return Op{.type = type, .id = test::bytes_of(id), .payload = std::nullopt};
}

std::vector<Change> changes_of(const std::vector<Op>& ops)
{
    std::vector<Change> changes;
    changes.reserve(ops.size());
    for (const auto& op : ops) {
        changes.push_back(Change{
            .type = op.type, .id = op.id, .payload = op.payload ? std::optional<ByteView>(*op.payload) : std::nullopt});
    }
    return changes;
}

Located located(RecordType type, std::string_view id, std::uint64_t counter, std::uint8_t seed)
{
    return Located{.address = {.type = type, .id = test::bytes_of(id), .counter = counter},
        .nonce = test::nonce_from(record_nonce_kind, seed)};
}

Root term_of(const Located& location)
{
    return must(hasher().term(location.address, location.nonce));
}

Result<void> admit(Index& index, const Located& location, std::uint64_t slot, const Root& term)
{
    return index.admit(location, slot, test::nonce_from(address_nonce_kind, location.nonce.back()), term);
}

Result<void> admit(Index& index, const Located& location, std::uint64_t slot)
{
    return admit(index, location, slot, term_of(location));
}

Snapshot snapshot(const Index& index)
{
    Snapshot entries;
    for (const auto& [key, entry] : index.entries()) {
        entries.emplace(ModelKey{key.first, Bytes(key.second.begin(), key.second.end())}, entry);
    }
    return entries;
}

wire::Manifest from_scratch(const Index& index)
{
    std::map<RecordType, wire::ManifestEntry> types;
    for (const auto& [key, entry] : index.entries()) {
        const RecordAddress address{.type = key.first, .id = Bytes(key.second.begin(), key.second.end()), .counter = entry.counter};
        auto& listed = types[key.first];
        listed.type = key.first;
        ++listed.count;
        listed.root = add_term(listed.root, must(root_term(opened().keys(), address, entry.nonce)));
    }
    wire::Manifest manifest{.epoch = epoch(), .types = {}};
    for (const auto& [type, listed] : types) {
        manifest.types.push_back(listed);
    }
    return manifest;
}

void expect_row_opens(const RowChange& row, const Op& op, std::uint64_t counter)
{
    crypto::SecretBytes scratch;
    const auto location = must(open_address(opened().keys(), row.slot, row.address, scratch));
    EXPECT_EQ(location.address.type, op.type);
    EXPECT_EQ(location.address.id, op.id);
    EXPECT_EQ(location.address.counter, counter);
    EXPECT_EQ(location.nonce, must(nonce_of(row.record)));
    const auto payload = must(open_record(opened().keys(), location.address, location.nonce, row.record));
    EXPECT_TRUE(std::ranges::equal(payload.view(), op.payload.value_or(Bytes{})));
}

void expect_held_nonces(const RowChange& row, const Entry& held)
{
    EXPECT_EQ(row.slot, held.slot);
    EXPECT_EQ(row.old_address_nonce, held.address_nonce);
    EXPECT_EQ(row.old_record_nonce, held.nonce);
}

Plan checked_plan(const Index& index, Model& model, const std::vector<Op>& ops)
{
    const auto before = snapshot(index);
    auto plan = must(index.plan(opened(), hasher(), changes_of(ops)));
    std::size_t next = 0;
    for (const auto& op : ops) {
        const ModelKey key{op.type, op.id};
        const auto held = before.find(key);
        if (!op.payload && held == before.end()) {
            continue;
        }
        if (next == plan.rows.size()) {
            ADD_FAILURE() << "the plan has fewer rows than changes that write";
            break;
        }
        const auto& row = plan.rows.at(next++);
        if (!op.payload) {
            EXPECT_EQ(row.write, RowWrite::erase);
            expect_held_nonces(row, held->second);
            model.erase(key);
            continue;
        }
        const std::uint64_t counter = held == before.end() ? 0 : held->second.counter + 1;
        if (held == before.end()) {
            EXPECT_EQ(row.write, RowWrite::insert);
        } else {
            EXPECT_EQ(row.write, RowWrite::replace);
            expect_held_nonces(row, held->second);
        }
        expect_row_opens(row, op, counter);
        model[key] = Modelled{.payload = op.payload.value_or(Bytes{}), .counter = counter};
    }
    EXPECT_EQ(next, plan.rows.size());
    return plan;
}

void expect_consistent(const Index& index, const Model& model, ByteView sealed)
{
    const auto entries = snapshot(index);
    ASSERT_EQ(entries.size(), model.size());
    std::set<std::uint64_t> slots;
    for (const auto& [key, modelled] : model) {
        const auto found = entries.find(key);
        ASSERT_NE(found, entries.end());
        EXPECT_EQ(found->second.counter, modelled.counter);
        const auto* held = index.find(key.first, key.second);
        ASSERT_NE(held, nullptr);
        EXPECT_EQ(*held, found->second);
        slots.insert(found->second.slot);
    }
    EXPECT_EQ(slots.size(), model.size());
    EXPECT_EQ(index.records(), model.size());
    const auto scratch = from_scratch(index);
    EXPECT_EQ(must(index.manifest(epoch())), scratch);
    EXPECT_EQ(must(open_manifest(opened(), sealed)), scratch);
    EXPECT_TRUE(index.matches(scratch));
}

void step(Index& index, Model& model, const std::vector<Op>& ops)
{
    auto plan = checked_plan(index, model, ops);
    const auto sealed = plan.manifest;
    index.apply(std::move(plan));
    expect_consistent(index, model, sealed);
}

Error refused_before_sealing(const Index& index, const std::vector<Op>& ops)
{
    const auto made = crypto::detail::wiping_ledger().made;
    const auto error = error_of(index.plan(opened(), hasher(), changes_of(ops)));
    EXPECT_EQ(crypto::detail::wiping_ledger().made, made);
    return error;
}

std::string numbered(std::string_view prefix, std::size_t number)
{
    return std::string(prefix) + std::to_string(number);
}

std::vector<std::vector<Op>> script()
{
    std::vector<std::vector<Op>> steps{
        {put(1, "alice", 10, 1), put(1, "bob", 300, 2), put(2, "2026-11-01", 5000, 3), put(3, "", 0, 4)},
        {put(1, "alice", 20, 5), put(4, "x", 255, 6)},
        {removal(1, "bob"), put(2, "2026-11-02", 256, 7), removal(9, "absent")},
        {removal(2, "2026-11-01"), removal(2, "2026-11-02")},
        {put(2, "2026-11-01", 1, 8)},
        {put(1, "alice", 70000, 9), put(1, "bob", 3, 10), removal(4, "x"), put(3, "", 1, 11)},
    };
    constexpr std::size_t many = 40;
    std::vector<Op> added;
    std::vector<Op> mixed;
    for (std::size_t number = 0; number < many; ++number) {
        const auto type = static_cast<RecordType>(10 + (number % 10));
        const auto id = numbered("record ", number);
        const auto seed = static_cast<std::uint8_t>(number);
        added.push_back(put(type, id, 50 + number, seed));
        mixed.push_back(number % 2 == 0 ? put(type, id, 600 + number, seed) : removal(type, id));
    }
    steps.push_back(std::move(added));
    steps.push_back(std::move(mixed));
    return steps;
}

std::vector<Op> removals_of(const Model& model)
{
    std::vector<Op> ops;
    for (const auto& [key, modelled] : model) {
        ops.push_back(Op{.type = key.first, .id = key.second, .payload = std::nullopt});
    }
    return ops;
}

TEST(VaultIndex, AdmitsEachTypeAndIdOnce)
{
    Index index;
    const auto alice = located(1, "alice", 3, 1);
    ASSERT_TRUE(admit(index, alice, 10));
    ASSERT_TRUE(admit(index, located(2, "alice", 0, 2), 11));
    EXPECT_EQ(error_of(admit(index, located(1, "alice", 4, 3), 12)), Error::integrity);
    EXPECT_EQ(error_of(admit(index, located(1, "alice", 3, 1), 10)), Error::integrity);
    EXPECT_EQ(index.records(), 2U);
    const auto* found = index.find(1, test::bytes_of("alice"));
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(*found,
        (Entry{.slot = 10, .counter = 3, .nonce = alice.nonce, .address_nonce = test::nonce_from(address_nonce_kind, 1)}));
    EXPECT_EQ(index.find(1, test::bytes_of("bob")), nullptr);
    EXPECT_EQ(index.find(3, test::bytes_of("alice")), nullptr);
    const auto manifest = must(index.manifest(epoch()));
    ASSERT_EQ(manifest.types.size(), 2U);
    EXPECT_EQ(manifest.types.front(), (wire::ManifestEntry{.type = 1, .count = 1, .root = add_term(Root{}, term_of(alice))}));
    EXPECT_EQ(manifest, from_scratch(index));
}

TEST(VaultIndex, AdmitsOnlyWhatAnAddressCanHold)
{
    Index index;
    EXPECT_EQ(error_of(admit(index, located(0, "zero", 0, 1), 1, Root{})), Error::integrity);
    EXPECT_EQ(error_of(admit(index, located(1, std::string(record_id_bound + 1, 'a'), 0, 2), 2, Root{})), Error::integrity);
    EXPECT_EQ(error_of(admit(index, located(1, "slot zero", 0, 3), 0)), Error::integrity);
    EXPECT_EQ(error_of(admit(index, located(1, "past the slots", 0, 4), slot_bound + 1)), Error::integrity);
    EXPECT_EQ(index.records(), 0U);
    EXPECT_TRUE(admit(index, located(1, std::string(record_id_bound, 'a'), 0, 5), slot_bound));
    EXPECT_TRUE(admit(index, located(255, "", 0, 6), 1));
    EXPECT_EQ(must(index.manifest(epoch())), from_scratch(index));
}

TEST(VaultIndex, RefusesACounterThatCouldNotGrowAndLetsItsRecordGo)
{
    Index index;
    EXPECT_EQ(error_of(admit(index, located(1, "worn", last_counter, 1), 5)), Error::integrity);
    EXPECT_EQ(index.records(), 0U);
    ASSERT_TRUE(admit(index, located(1, "worn", last_counter - 1, 1), 5));
    const std::vector<Op> rewrite{put(1, "worn", 10, 2)};
    EXPECT_EQ(refused_before_sealing(index, rewrite), Error::invalid_parameters);
    Model model{{ModelKey{1, test::bytes_of("worn")}, Modelled{.payload = {}, .counter = last_counter - 1}}};
    step(index, model, {removal(1, "worn")});
    step(index, model, rewrite);
    const auto* renewed = index.find(1, test::bytes_of("worn"));
    ASSERT_NE(renewed, nullptr);
    EXPECT_EQ(renewed->counter, 0U);
}

TEST(VaultIndex, RewritesARecordUntilItsCounterReachesTheLastItCanAdmit)
{
    Index index;
    ASSERT_TRUE(admit(index, located(1, "nearly worn", last_counter - 2, 1), 5));
    Model model{{ModelKey{1, test::bytes_of("nearly worn")}, Modelled{.payload = {}, .counter = last_counter - 2}}};
    step(index, model, {put(1, "nearly worn", 10, 2)});
    const auto* rewritten = index.find(1, test::bytes_of("nearly worn"));
    ASSERT_NE(rewritten, nullptr);
    EXPECT_EQ(rewritten->counter, last_counter - 1);
    EXPECT_EQ(refused_before_sealing(index, {put(1, "nearly worn", 10, 3)}), Error::invalid_parameters);
}

TEST(VaultIndex, CountsUpToItsBound)
{
    Index index;
    Plan nearly_full;
    nearly_full.types.at(1).count = last_count - 1;
    index.apply(std::move(nearly_full));
    const auto planned = index.plan(opened(), hasher(), changes_of({put(1, "planned", 10, 1)}));
    ASSERT_TRUE(planned.has_value());
    EXPECT_EQ(planned->types.at(1).count, last_count);
    EXPECT_TRUE(admit(index, located(1, "admitted", 0, 2), 2));
    EXPECT_EQ(error_of(admit(index, located(1, "one more", 0, 3), 3)), Error::integrity);
    EXPECT_EQ(index.records(), 1U);
}

TEST(VaultIndex, RefusesACountPastItsBound)
{
    Index index;
    Plan full;
    full.types.at(1).count = last_count;
    index.apply(std::move(full));
    EXPECT_EQ(error_of(admit(index, located(1, "one more", 0, 1), 1)), Error::integrity);
    EXPECT_EQ(index.records(), 0U);
    EXPECT_EQ(refused_before_sealing(index, {put(1, "one more", 10, 1)}), Error::invalid_parameters);
    EXPECT_TRUE(admit(index, located(2, "another type", 0, 2), 2));
    EXPECT_TRUE(index.plan(opened(), hasher(), changes_of({put(2, "another type", 10, 2), put(3, "new", 10, 3)})));
}

TEST(VaultIndex, RefusesToRemoveFromATypeItCountsAsEmpty)
{
    Index index;
    ASSERT_TRUE(admit(index, located(1, "alice", 0, 1), 1));
    index.apply(Plan{});
    EXPECT_EQ(refused_before_sealing(index, {removal(1, "alice")}), Error::integrity);
}

TEST(VaultIndex, MatchesOnlyTheManifestOfItsOwnState)
{
    Index index;
    EXPECT_TRUE(index.matches(wire::Manifest{.epoch = epoch(), .types = {}}));
    ASSERT_TRUE(admit(index, located(1, "alice", 0, 1), 1));
    ASSERT_TRUE(admit(index, located(1, "bob", 0, 2), 2));
    ASSERT_TRUE(admit(index, located(3, "carol", 0, 3), 3));
    const auto manifest = must(index.manifest(7));
    EXPECT_EQ(manifest.epoch, 7U);
    EXPECT_TRUE(index.matches(manifest));
    EXPECT_FALSE(Index{}.matches(manifest));
    EXPECT_FALSE(index.matches(wire::Manifest{.epoch = 7, .types = {}}));

    auto changed = manifest;
    changed.types.at(0).count += 1;
    EXPECT_FALSE(index.matches(changed));
    changed = manifest;
    changed.types.at(1).type = 4;
    EXPECT_FALSE(index.matches(changed));
    changed = manifest;
    changed.types.at(0).root.front() ^= 1U;
    EXPECT_FALSE(index.matches(changed));
    changed = manifest;
    changed.types.at(1).root.back() ^= 1U;
    EXPECT_FALSE(index.matches(changed));
    changed = manifest;
    changed.types.pop_back();
    EXPECT_FALSE(index.matches(changed));
    changed = manifest;
    changed.types.push_back(wire::ManifestEntry{.type = 9, .count = 1, .root = {}});
    EXPECT_FALSE(index.matches(changed));
}

TEST(VaultIndex, ListsNoManifestForMoreTypesThanOneCanHold)
{
    Index index;
    for (std::size_t type = 1; type <= wire::manifest_types_bound + 1; ++type) {
        ASSERT_TRUE(admit(index, located(static_cast<RecordType>(type), "one", 0, static_cast<std::uint8_t>(type)), type));
    }
    EXPECT_EQ(error_of(index.manifest(epoch())), Error::integrity);
}

TEST(VaultIndexPlan, RefusesInvalidChangesBeforeSealingAnything)
{
    const Index index;
    const auto refused = [&index](const std::vector<Op>& ops) { return refused_before_sealing(index, ops); };
    EXPECT_EQ(refused({put(0, "zero", 10, 1)}), Error::invalid_parameters);
    EXPECT_EQ(refused({removal(0, "zero")}), Error::invalid_parameters);
    EXPECT_EQ(refused({put(1, std::string(record_id_bound + 1, 'a'), 10, 1)}), Error::invalid_parameters);
    EXPECT_EQ(refused({put(1, "alice", 10, 1), put(1, "alice", 20, 2)}), Error::invalid_parameters);
    EXPECT_EQ(refused({put(1, "alice", 10, 1), put(2, "bob", 10, 2), removal(1, "alice")}), Error::invalid_parameters);
    EXPECT_EQ(refused({put(1, "alice", payload_bound + 1, 1)}), Error::record_too_large);

    const auto largest = must(index.plan(opened(), hasher(), changes_of({put(1, std::string(record_id_bound, 'a'), payload_bound, 1)})));
    ASSERT_EQ(largest.rows.size(), 1U);
    EXPECT_EQ(largest.rows.front().record.size(), record_maximum);
    EXPECT_EQ(largest.rows.front().address.size(), sealed_address_size);
    EXPECT_EQ(largest.manifest.size(), sealed_manifest_size);
    EXPECT_TRUE(index.plan(opened(), hasher(), changes_of({put(1, "alice", 10, 1), put(2, "alice", 10, 2), put(1, "alicf", 10, 3)})));
}

TEST(VaultIndexPlan, KeepsTheManifestWithinItsTypeBound)
{
    Index index;
    Model model;
    std::vector<Op> filled;
    for (std::size_t type = 1; type <= wire::manifest_types_bound; ++type) {
        filled.push_back(put(static_cast<RecordType>(type), "first", 10, static_cast<std::uint8_t>(type)));
    }
    step(index, model, filled);
    EXPECT_EQ(must(index.manifest(epoch())).types.size(), wire::manifest_types_bound);

    EXPECT_EQ(refused_before_sealing(index, {put(33, "first", 10, 1)}), Error::invalid_parameters);
    EXPECT_EQ(snapshot(index).size(), wire::manifest_types_bound);
    step(index, model, {put(2, "first", 20, 2), put(2, "second", 20, 3)});
    step(index, model, {removal(1, "first"), put(33, "first", 10, 4)});
    EXPECT_EQ(must(index.manifest(epoch())).types.front().type, 2);

    std::vector<Op> crowded;
    for (std::size_t type = 100; type <= 100 + wire::manifest_types_bound; ++type) {
        crowded.push_back(put(static_cast<RecordType>(type), "first", 10, static_cast<std::uint8_t>(type)));
    }
    EXPECT_EQ(refused_before_sealing(Index{}, crowded), Error::invalid_parameters);
}

TEST(VaultIndexPlan, WritesNothingForTheRemovalOfAnAbsentRecord)
{
    Index index;
    Model model;
    step(index, model, {put(1, "alice", 10, 1)});
    const auto before = snapshot(index);
    auto plan = must(index.plan(opened(), hasher(), changes_of({removal(1, "bob"), removal(2, "alice")})));
    EXPECT_TRUE(plan.rows.empty());
    EXPECT_EQ(must(open_manifest(opened(), plan.manifest)), must(index.manifest(epoch())));
    index.apply(std::move(plan));
    EXPECT_EQ(snapshot(index), before);
}

TEST(VaultIndexPlan, AppliesWithoutAllocating)
{
    static_assert(noexcept(std::declval<Index&>().apply(std::declval<Plan>())));
    Index index;
    Model model;
    step(index, model, {put(1, "alice", 10, 1), put(1, "bob", 10, 2), put(2, "carol", 10, 3)});
    auto plan = checked_plan(index, model, {put(1, "alice", 20, 4), removal(1, "bob"), put(3, "dave", 10, 5), put(3, "erin", 10, 6)});
    const auto sealed = plan.manifest;
    const auto made = crypto::detail::wiping_ledger().made;
    index.apply(std::move(plan));
    EXPECT_EQ(crypto::detail::wiping_ledger().made, made);
    expect_consistent(index, model, sealed);
}

TEST(VaultIndexPlan, LeavesTheIndexUnchangedWhenPlanningRunsOutOfMemory)
{
    Index index;
    Model model;
    step(index, model, {put(1, "alice", 10, 1), put(1, "bob", 10, 2), put(2, "carol", 10, 3)});
    const auto before = snapshot(index);
    const auto manifest = must(index.manifest(epoch()));
    const std::vector<Op> ops{put(1, "alice", 40, 4), removal(1, "bob"), put(3, "dave", 40, 5), put(4, "erin", 40, 6)};
    const auto changes = changes_of(ops);
    std::uint64_t refusals = 0;
    std::optional<Plan> planned;
    for (std::uint64_t allowed = 0; !planned && allowed < 1000; ++allowed) {
        try {
            const test::LedgerLimit limit(allowed);
            planned.emplace(must(index.plan(opened(), hasher(), changes)));
        } catch (const std::bad_alloc&) {
            ++refusals;
        }
        EXPECT_EQ(snapshot(index), before);
        EXPECT_TRUE(index.matches(manifest));
    }
    ASSERT_TRUE(planned.has_value());
    EXPECT_GE(refusals, 4U);
    index.apply(std::move(*planned));
    EXPECT_EQ(index.records(), 4U);
    EXPECT_EQ(must(index.manifest(epoch())), from_scratch(index));
}

TEST(VaultIndexPlan, KeepsIncrementalRootsEqualToRootsFromScratchThroughAScriptedSequence)
{
    Index index;
    Model model;
    for (const auto& ops : script()) {
        step(index, model, ops);
    }
    EXPECT_FALSE(model.empty());
    step(index, model, removals_of(model));
    EXPECT_EQ(index.records(), 0U);
    EXPECT_TRUE(must(index.manifest(epoch())).types.empty());
}

class VaultIndexStore : public ::testing::TestWithParam<Backing> {};

INSTANTIATE_TEST_SUITE_P(Backings, VaultIndexStore, ::testing::Values(Backing::os, Backing::memory),
    [](const ::testing::TestParamInfo<Backing>& instance) { return test::backing_name(instance.param); });

void commit(Store& store, Index& index, Model& model, const std::vector<Op>& ops)
{
    auto plan = checked_plan(index, model, ops);
    const Bytes old_manifest = store.opened().manifest;
    const auto result = store.commit(plan.rows, std::nullopt, old_manifest, plan.manifest);
    ASSERT_EQ(result.outcome, Outcome::committed);
    const auto sealed = plan.manifest;
    index.apply(std::move(plan));
    EXPECT_EQ(store.opened().manifest, sealed);
    must(store.checkpoint());
    expect_consistent(index, model, sealed);
}

Store created(const Place& place, Index& index, Model& model, const std::vector<Op>& ops)
{
    auto store = must(Store::open_new(place.path(), place.vfs()));
    auto plan = checked_plan(index, model, ops);
    const auto sealed = plan.manifest;
    EXPECT_EQ(store.initialise(Material::keystore().header(), plan.manifest, plan.rows).outcome, Outcome::committed);
    index.apply(std::move(plan));
    must(store.checkpoint());
    expect_consistent(index, model, sealed);
    return store;
}

void expect_read_back(Store& store, const Index& index, const Model& model)
{
    EXPECT_EQ(store.opened().header, Material::keystore().header());
    const auto manifest = must(open_manifest(opened(), store.opened().manifest));
    Index rebuilt;
    crypto::SecretBytes scratch;
    must(store.begin_scan());
    for (;;) {
        const auto row = must(store.next_row());
        if (!row) {
            break;
        }
        const auto location = must(open_address(opened().keys(), row->slot, row->address, scratch));
        ASSERT_TRUE(rebuilt.admit(location, row->slot, test::leading_nonce(row->address), term_of(location)));
    }
    EXPECT_TRUE(rebuilt.matches(manifest));
    EXPECT_EQ(snapshot(rebuilt), snapshot(index));
    for (const auto& [key, entry] : snapshot(rebuilt)) {
        const auto body = must(store.body(entry.slot));
        if (!body) {
            ADD_FAILURE() << "a committed record has no body";
            continue;
        }
        const RecordAddress address{.type = key.first, .id = key.second, .counter = entry.counter};
        const auto payload = must(open_record(opened().keys(), address, entry.nonce, *body));
        EXPECT_TRUE(std::ranges::equal(payload.view(), model.at(key).payload));
    }
}

TEST_P(VaultIndexStore, CommitsEveryPlanAndReadsItBackThroughAFreshStore)
{
    const Place place(GetParam());
    Index index;
    Model model;
    const auto steps = script();
    {
        auto store = created(place, index, model, steps.front());
        for (const auto& ops : std::span(steps).subspan(1)) {
            commit(store, index, model, ops);
        }
    }
    auto fresh = must(Store::open_existing(place.path(), place.vfs()));
    expect_read_back(fresh, index, model);
    commit(fresh, index, model, removals_of(model));
    expect_read_back(fresh, index, model);
}

TEST_P(VaultIndexStore, RefusesAPlanMadeBeforeTheLastCommit)
{
    const Place place(GetParam());
    Index index;
    Model model;
    auto store = created(place, index, model, {put(1, "alice", 10, 1), put(1, "bob", 10, 2)});
    const Bytes first_manifest = store.opened().manifest;
    const auto stale_rewrite = must(index.plan(opened(), hasher(), changes_of({put(1, "alice", 30, 3)})));
    const auto stale_removal = must(index.plan(opened(), hasher(), changes_of({removal(1, "alice")})));
    commit(store, index, model, {put(1, "alice", 20, 4)});
    const auto before = snapshot(index);

    for (const auto* stale : {&stale_rewrite, &stale_removal}) {
        const auto result = store.commit(stale->rows, std::nullopt, store.opened().manifest, stale->manifest);
        EXPECT_EQ(result.outcome, Outcome::mismatch);
        EXPECT_EQ(result.error, Error::integrity);
    }
    const auto current = must(index.plan(opened(), hasher(), changes_of({put(1, "bob", 30, 5)})));
    const auto result = store.commit(current.rows, std::nullopt, first_manifest, current.manifest);
    EXPECT_EQ(result.outcome, Outcome::mismatch);
    EXPECT_EQ(snapshot(index), before);
    expect_read_back(store, index, model);

    commit(store, index, model, {put(1, "bob", 40, 6), removal(1, "alice")});
    expect_read_back(store, index, model);
}

}
}
