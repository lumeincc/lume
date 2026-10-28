// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only

#include "report.hpp"
#include "walkthrough.hpp"

#include "lume/crypto/secret_bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>
#include <span>
#include <string_view>

namespace {

constexpr std::size_t longest_input = 1024;

constexpr std::string_view usage = R"(lume-lab - the LUME core, live

  lume-lab                 walk through accounts, recovery, PQXDH, attacks and safety numbers
  lume-lab new             create a throwaway account and show its phrase and keys
  lume-lab phrase          type a recovery phrase and see what the core says about it
  lume-lab help            this text

Every line marked [ ok ] is a check the real core just passed. The exit code is 0
only when every check passed.
)";

lume::crypto::SecretBytes read_phrase()
{
    static_cast<void>(std::setvbuf(stdin, nullptr, _IONBF, 0));
    lume::crypto::SecretBytes buffer(longest_input);
    auto next = buffer.writable().begin();
    std::size_t length = 0;
    for (int letter = std::getchar(); letter != EOF && letter != '\n'; letter = std::getchar()) {
        if (length < longest_input) {
            *next = static_cast<std::uint8_t>(letter);
            ++next;
            ++length;
        }
    }
    return lume::crypto::SecretBytes::copy_of(buffer.view().first(length));
}

int run(std::span<char*> arguments)
{
    const auto rest = arguments.subspan(arguments.empty() ? 0 : 1);
    const std::string_view command = rest.empty() ? std::string_view("walk") : std::string_view(rest.front());
    lume::lab::Report report;
    if (command == "walk") {
        lume::lab::walk_through(report);
    } else if (command == "new") {
        lume::lab::new_account(report);
    } else if (command == "phrase") {
        std::cout << "Type or paste a recovery phrase and press Enter.\n"
                  << "lume-lab keeps it only in locked memory; your terminal may keep its own copy of the line.\n> "
                  << std::flush;
        const auto phrase = read_phrase();
        lume::lab::check_phrase(report, phrase.view());
    } else {
        std::cout << usage;
        return command == "help" ? 0 : 2;
    }
    report.summary();
    return report.failures() == 0 ? 0 : 1;
}

}

int main(int argc, char** argv)
{
    try {
        return run(std::span(argv, static_cast<std::size_t>(argc)));
    } catch (const std::exception& error) {
        static_cast<void>(std::fputs("lume-lab stopped: ", stderr));
        static_cast<void>(std::fputs(error.what(), stderr));
        static_cast<void>(std::fputs("\n", stderr));
        return 1;
    } catch (...) {
        static_cast<void>(std::fputs("lume-lab stopped by an unexpected error\n", stderr));
        return 1;
    }
}
