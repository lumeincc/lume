# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import unittest

from check_includes import check

KEY_ACCESS = "core/src/vault/key_access.hpp"
INTERNAL = "core/src/vault/vault_internal.hpp"
HEADERS = (KEY_ACCESS, INTERNAL, "core/src/vault/keys.hpp", "core/include/lume/vault/vault.hpp")


def failures_for(name: str, line: str) -> list[str]:
    return check({name: line + "\n"}, HEADERS)


class GuardedHeaders(unittest.TestCase):
    def test_every_spelling_of_the_key_access_header_is_caught(self) -> None:
        for line in (
            '#include "vault/key_access.hpp"',
            "#include <vault/key_access.hpp>",
            '#include "key_access.hpp"',
            '#include "../vault/key_access.hpp"',
            '#include "./key_access.hpp"',
            '#include "vault//key_access.hpp"',
            '#include "Vault/Key_Access.hpp"',
            '  #  include   "vault/key_access.hpp"',
            '#include "vault\\\\key_access.hpp"',
        ):
            with self.subTest(line=line):
                self.assertTrue(failures_for("core/src/vault/store.cpp", line))

    def test_the_two_owners_may_include_the_key_access_header(self) -> None:
        for name in ("core/src/vault/keys.cpp", "core/src/vault/records.cpp"):
            with self.subTest(name=name):
                self.assertEqual(failures_for(name, '#include "vault/key_access.hpp"'), [])
        self.assertTrue(failures_for("core/tests/vault/vault_test.cpp", "#include <vault/key_access.hpp>"))

    def test_the_internal_header_is_for_its_owners_and_the_tests(self) -> None:
        self.assertEqual(failures_for("core/tests/vault/vault_test.cpp", '#include "vault/vault_internal.hpp"'), [])
        self.assertEqual(failures_for("core/src/vault/keys.cpp", '#include "vault/vault_internal.hpp"'), [])
        for name in ("core/src/vault/store.cpp", "core/src/session/session.cpp", "core/fuzz/vault_fuzzer.cpp"):
            with self.subTest(name=name):
                self.assertTrue(failures_for(name, "#include <vault/vault_internal.hpp>"))

    def test_public_headers_include_only_public_headers(self) -> None:
        name = "core/include/lume/vault/hardware.hpp"
        self.assertTrue(failures_for(name, "#include <vault/keys.hpp>"))
        self.assertTrue(failures_for(name, '#include "vault/keys.hpp"'))
        self.assertEqual(failures_for(name, '#include "lume/vault/vault.hpp"'), [])
        self.assertEqual(failures_for(name, '#include "vault.hpp"'), [])
        self.assertEqual(failures_for(name, "#include <optional>"), [])

    def test_an_include_without_a_header_name_is_refused(self) -> None:
        self.assertTrue(failures_for("core/src/vault/store.cpp", "#include LUME_HEADER"))

    def test_headers_outside_the_repository_are_ignored(self) -> None:
        self.assertEqual(failures_for("core/src/vault/keys.cpp", "#include <sodium.h>"), [])
        self.assertEqual(failures_for("core/src/vault/keys.cpp", '#include "../../../outside.hpp"'), [])


if __name__ == "__main__":
    unittest.main()
