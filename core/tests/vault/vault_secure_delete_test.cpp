// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "vault/store.hpp"

#include "lume/crypto/bytes.hpp"
#include "support/store_fixture.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace lume::vault {
namespace {

using crypto::Bytes;
using crypto::ByteView;
using test::Backing;
using test::Material;
using test::must;
using test::Place;

constexpr std::size_t window = 32;
constexpr std::size_t stride = 64;
constexpr std::size_t pattern_size = 4096;
constexpr std::uint8_t pattern_seed = 0x5c;
constexpr std::string_view removed_id = "secure-delete-removed-identifier";
constexpr std::string_view kept_id = "secure-delete-kept-identifier";

class VaultSecureDelete : public ::testing::TestWithParam<Backing> {};

INSTANTIATE_TEST_SUITE_P(Backings, VaultSecureDelete, ::testing::Values(Backing::os, Backing::memory),
    [](const ::testing::TestParamInfo<Backing>& instance) { return test::backing_name(instance.param); });

std::vector<Bytes> files_of(const Place& place)
{
    std::vector<Bytes> files;
    for (const std::string_view suffix : {"", "-wal"}) {
        if (auto bytes = place.read(suffix)) {
            files.push_back(std::move(*bytes));
        }
    }
    return files;
}

std::size_t windows_found(const std::vector<Bytes>& files, ByteView box)
{
    std::size_t found = 0;
    for (std::size_t at = 0; at + window <= box.size(); at += stride) {
        const auto piece = box.subspan(at, window);
        for (const auto& file : files) {
            if (test::contains(file, piece)) {
                ++found;
                break;
            }
        }
    }
    return found;
}

class Disk {
public:
    explicit Disk(const Place& place)
        : files_(files_of(place))
    {
    }

    void lacks(ByteView box, std::string_view what) const
    {
        EXPECT_EQ(windows_found(files_, box), 0U) << what;
    }

    void holds(ByteView box, std::string_view what) const
    {
        EXPECT_GT(windows_found(files_, box), 0U) << what;
    }

    void lacks_text(std::string_view text) const
    {
        for (const auto& file : files_) {
            EXPECT_FALSE(test::contains(file, test::bytes_of(text))) << text;
        }
    }

    [[nodiscard]] std::size_t log_size() const
    {
        return files_.size() > 1 ? files_.back().size() : 0;
    }

private:
    std::vector<Bytes> files_;
};

TEST_P(VaultSecureDelete, LeavesNoReplacedOrRemovedBoxAndNoPlaintextInTheFiles)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto pattern = test::patterned(pattern_size, pattern_seed);
    const auto first = material.row(1001, 1, pattern, removed_id, 0);
    const auto second = material.row(1001, 2, pattern, removed_id, 1);
    const auto kept = material.row(1002, 3, pattern, kept_id, 0);
    const auto first_header = material.header();
    const auto second_header = material.header(1);
    const auto plaintext_absent = [&pattern](const Disk& disk) {
        disk.lacks(pattern, "payload");
        disk.lacks_text(removed_id);
        disk.lacks_text(kept_id);
        EXPECT_EQ(disk.log_size(), 0U);
    };

    auto store = test::created(place, material, {first, kept});
    {
        const Disk disk(place);
        plaintext_absent(disk);
        disk.holds(first.record, "first record");
        disk.holds(first.address, "first address");
        disk.holds(kept.record, "kept record");
        disk.holds(material.manifest(1), "first manifest");
        disk.holds(first_header, "first header");
    }

    const std::vector<RowChange> rewrite{test::replaced(first, second)};
    ASSERT_EQ(store.commit(rewrite, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
    ASSERT_TRUE(store.checkpoint().has_value());
    {
        const Disk disk(place);
        plaintext_absent(disk);
        disk.lacks(first.record, "replaced record");
        disk.lacks(first.address, "replaced address");
        disk.lacks(material.manifest(1), "replaced manifest");
        disk.holds(second.record, "second record");
        disk.holds(second.address, "second address");
        disk.holds(material.manifest(2), "second manifest");
    }

    const std::vector<RowChange> removal{test::erased(second)};
    ASSERT_EQ(store.commit(removal, std::nullopt, material.manifest(2), material.manifest(3)).outcome, Outcome::committed);
    ASSERT_TRUE(store.checkpoint().has_value());
    {
        const Disk disk(place);
        plaintext_absent(disk);
        disk.lacks(second.record, "removed record");
        disk.lacks(second.address, "removed address");
        disk.lacks(material.manifest(2), "replaced manifest");
        disk.holds(kept.record, "kept record");
        disk.holds(kept.address, "kept address");
        disk.holds(material.manifest(3), "third manifest");
    }

    const Swap swap{.old_header = first_header, .new_header = second_header};
    ASSERT_EQ(store.commit({}, swap, material.manifest(3), material.manifest(4)).outcome, Outcome::committed);
    ASSERT_TRUE(store.checkpoint().has_value());
    {
        const Disk disk(place);
        plaintext_absent(disk);
        disk.lacks(first_header, "replaced header");
        disk.lacks(material.manifest(3), "replaced manifest");
        disk.holds(second_header, "second header");
    }

    ASSERT_EQ(store.mark_wiped().outcome, Outcome::committed);
    ASSERT_TRUE(store.checkpoint().has_value());
    {
        const Disk disk(place);
        plaintext_absent(disk);
        disk.lacks(second_header, "wiped header");
        disk.lacks(material.manifest(4), "wiped manifest");
        disk.holds(kept.record, "kept record");
    }
}

TEST_P(VaultSecureDelete, LeavesNoLargestRecordAfterItIsRemoved)
{
    const Place place(GetParam());
    const auto& material = Material::keystore();
    const auto largest = material.row(2001, 1, test::patterned(payload_bound, pattern_seed), removed_id);
    auto store = test::created(place, material, {largest});
    ASSERT_EQ(largest.record.size(), record_maximum);
    Disk(place).holds(largest.record, "largest record");
    const std::vector<RowChange> removal{test::erased(largest)};
    ASSERT_EQ(store.commit(removal, std::nullopt, material.manifest(1), material.manifest(2)).outcome, Outcome::committed);
    ASSERT_TRUE(store.checkpoint().has_value());
    const Disk disk(place);
    disk.lacks(largest.record, "removed largest record");
    disk.lacks(test::patterned(payload_bound, pattern_seed), "payload");
    EXPECT_EQ(must(store.body(largest.slot)), std::nullopt);
}

}
}
