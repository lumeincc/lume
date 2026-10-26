// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#include "report.hpp"

#include "lume/crypto/bytes.hpp"
#include "lume/identity/phrase.hpp"

#include <string>

namespace lume::lab {

void walk_through(Report& report);

void new_account(Report& report);

void check_phrase(Report& report, crypto::ByteView phrase);

[[nodiscard]] std::string phrase_problem(identity::PhraseError error);

}
