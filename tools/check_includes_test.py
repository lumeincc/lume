# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import unittest

from check_includes import check

KEY_ACCESS = "core/src/vault/key_access.hpp"
INTERNAL = "core/src/vault/vault_internal.hpp"
HEADERS = (KEY_ACCESS, INTERNAL, "core/src/vault/keys.hpp", "core/include/lume/vault/vault.hpp")


def failures_for(name: str, text: str) -> list[str]:
    return check({name: text + "\n"}, HEADERS)


class GuardedHeaders(unittest.TestCase):
    def test_every_spelling_of_the_key_access_header_is_caught(self) -> None:
        for text in (
            '#include "vault/key_access.hpp"',
            "#include <vault/key_access.hpp>",
            '#include "key_access.hpp"',
            '#include "../vault/key_access.hpp"',
            '#include "./key_access.hpp"',
            '#include "vault//key_access.hpp"',
            '#include "Vault/Key_Access.hpp"',
            '  #  include   "vault/key_access.hpp"',
            '#include "vault\\\\key_access.hpp"',
            '%:include "vault/key_access.hpp"',
            '#\\\ninclude "vault/key_access.hpp"',
            '#inc\\\nlude "key_access.hpp"',
            '#include \\\n"vault/key_access.hpp"',
        ):
            with self.subTest(text=text):
                self.assertTrue(failures_for("core/src/vault/store.cpp", text))

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

    def test_a_guarded_header_cannot_be_reached_through_another_file(self) -> None:
        files = {
            "core/tests/support/vault.hpp": '#include "vault/vault_internal.hpp"\n',
            "core/src/vault/vault.cpp": '#include "../../tests/support/vault.hpp"\n',
            "core/tests/vault/store_test.cpp": '#include "support/vault.hpp"\n',
        }
        failures = check(files, HEADERS)
        self.assertEqual(len(failures), 1)
        self.assertIn("core/src/vault/vault.cpp", failures[0])
        self.assertIn("through core/tests/support/vault.hpp", failures[0])

    def test_public_headers_include_only_public_and_standard_headers(self) -> None:
        name = "core/include/lume/vault/hardware.hpp"
        for text in ("#include <vault/keys.hpp>", '#include "vault/keys.hpp"', "#include <sodium.h>", '#include "sodium.h"',
                     "#include <oqs/oqs.h>"):
            with self.subTest(text=text):
                self.assertTrue(failures_for(name, text))
        for text in ('#include "lume/vault/vault.hpp"', '#include "vault.hpp"', "#include <optional>", "#include <string_view>"):
            with self.subTest(text=text):
                self.assertEqual(failures_for(name, text), [])

    def test_includes_must_name_files_the_check_can_read(self) -> None:
        for text in ("#include LUME_HEADER", '#include "missing.hpp"', '#include "C:/dev/lume/core/src/vault/key_access.hpp"',
                     "#include </usr/include/vault/key_access.hpp>"):
            with self.subTest(text=text):
                self.assertTrue(failures_for("core/src/vault/store.cpp", text))
        inc = check({"core/src/vault/store.cpp": '#include "store_impl.inc"\n'}, (*HEADERS, "core/src/vault/store_impl.inc"))
        self.assertTrue(inc)

    def test_system_headers_are_allowed_outside_public_headers(self) -> None:
        self.assertEqual(failures_for("core/src/vault/keys.cpp", "#include <sodium.h>"), [])
        self.assertEqual(failures_for("core/src/vault/keys.cpp", "#include <oqs/oqs.h>"), [])


if __name__ == "__main__":
    unittest.main()
