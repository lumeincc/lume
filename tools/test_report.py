# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

import datetime
import html
import pathlib
import sys
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

MODULES = (
    ("Cryptographic primitives", ("Aead", "Ed25519", "Encoder", "Encoding", "Hash", "HkdfSha256", "HmacSha256", "Kdf",
                                  "Library", "MlKem768", "MlKem", "Random", "SecretBytes", "Sha256", "Sha512",
                                  "X25519", "XChaCha20Poly1305")),
    ("Identity and recovery phrase", ("DeviceCertificate", "Identity", "Phrase", "Wordlist")),
    ("Safety numbers", ("SafetyNumber", "IdentityMatching")),
    ("PQXDH handshake", ("Handshake", "Prekey")),
    ("Wire codec", ("WireCodec", "WireStructure", "WireStructures")),
    ("Live walkthrough", ("lab",)),
    ("Test support", ("Hex",)),
)
PROPERTY_SUFFIX = "Properties"


@dataclass
class Case:
    suite: str
    name: str
    seconds: float
    passed: bool
    property_test: bool
    message: str


@dataclass
class Module:
    title: str
    cases: list[Case] = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(not case.passed for case in self.cases)

    @property
    def seconds(self) -> float:
        return sum(case.seconds for case in self.cases)


def module_title(suite: str) -> str:
    base = suite.removesuffix(PROPERTY_SUFFIX)
    for title, suites in MODULES:
        if base in suites or suite in suites:
            return title
    return "Other"


def read_cases(report: pathlib.Path) -> list[Case]:
    cases = []
    for element in ElementTree.parse(report).getroot().iter("testcase"):
        full_name = element.get("name", "")
        suite, _, name = full_name.partition(".")
        failure = element.find("failure")
        error = element.find("error")
        problem = failure if failure is not None else error
        output = element.findtext("system-out") or ""
        message = ""
        if problem is not None:
            message = (problem.get("message") or "") + "\n" + output
        cases.append(Case(
            suite=suite,
            name=name or full_name,
            seconds=float(element.get("time", "0") or 0),
            passed=problem is None and element.get("status", "run") != "fail",
            property_test=suite.endswith(PROPERTY_SUFFIX),
            message=message.strip()))
    return cases


def group(cases: list[Case]) -> list[Module]:
    modules = {title: Module(title) for title, _ in MODULES}
    modules["Other"] = Module("Other")
    for case in cases:
        modules[module_title(case.suite)].cases.append(case)
    return [module for module in modules.values() if module.cases]


STYLE = """
:root { --bg: rgb(247 247 245); --card: rgb(255 255 255); --text: rgb(29 29 27); --muted: rgb(107 107 102); --line: rgb(227 227 222);
        --pass: rgb(31 122 63); --fail: rgb(179 38 30); --pass-bg: rgb(230 244 234); --fail-bg: rgb(251 233 231); }
@media (prefers-color-scheme: dark) {
  :root { --bg: rgb(18 18 17); --card: rgb(28 28 26); --text: rgb(236 236 232); --muted: rgb(154 154 148); --line: rgb(46 46 43);
          --pass: rgb(127 214 154); --fail: rgb(255 138 128); --pass-bg: rgb(22 48 31); --fail-bg: rgb(58 23 20); }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
       font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
.meta { color: var(--muted); margin-bottom: 24px; }
.verdict { border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; font-size: 18px; font-weight: 600; }
.verdict.pass { background: var(--pass-bg); color: var(--pass); }
.verdict.fail { background: var(--fail-bg); color: var(--fail); }
.verdict small { display: block; font-weight: 400; color: var(--text); font-size: 14px; margin-top: 4px; }
details { background: var(--card); border: 1px solid var(--line); border-radius: 12px; margin-bottom: 12px; }
summary { cursor: pointer; padding: 14px 18px; display: flex; gap: 12px; align-items: center; list-style: none; }
summary::-webkit-details-marker { display: none; }
summary .title { flex: 1; font-weight: 600; }
summary .count { color: var(--muted); font-variant-numeric: tabular-nums; }
.badge { border-radius: 999px; padding: 2px 10px; font-size: 13px; font-weight: 600; }
.badge.pass { background: var(--pass-bg); color: var(--pass); }
.badge.fail { background: var(--fail-bg); color: var(--fail); }
table { width: 100%; border-collapse: collapse; }
td { padding: 6px 18px; border-top: 1px solid var(--line); vertical-align: top; }
td.state { width: 56px; font-weight: 600; }
td.state.pass { color: var(--pass); }
td.state.fail { color: var(--fail); }
td.time { width: 90px; text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; }
.kind { color: var(--muted); font-size: 13px; }
pre { white-space: pre-wrap; background: var(--bg); border-radius: 8px; padding: 10px; margin: 6px 0 0; font-size: 13px; }
"""


def render(modules: list[Module], source: pathlib.Path) -> str:
    cases = [case for module in modules for case in module.cases]
    failed = sum(not case.passed for case in cases)
    properties = sum(case.property_test for case in cases)
    seconds = sum(case.seconds for case in cases)
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    verdict = (f'<div class="verdict pass">All {len(cases)} tests passed'
               if failed == 0 else f'<div class="verdict fail">{failed} of {len(cases)} tests failed')
    verdict += (f"<small>{len(cases) - properties} example and vector tests, {properties} property tests, "
                f"{seconds:.1f} s in total</small></div>")
    parts = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
             f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
             f"<title>LUME test report</title><style>{STYLE}</style></head><body><main>",
             "<h1>LUME core — test report</h1>",
             f'<div class="meta">{html.escape(when)} · {html.escape(str(source))}</div>', verdict]
    for module in modules:
        state = "pass" if module.failed == 0 else "fail"
        label = "all passed" if module.failed == 0 else f"{module.failed} failed"
        parts.append(f'<details{" open" if module.failed else ""}><summary><span class="title">{html.escape(module.title)}</span>'
                     f'<span class="count">{len(module.cases)} tests · {module.seconds:.1f} s</span>'
                     f'<span class="badge {state}">{label}</span></summary><table>')
        for case in sorted(module.cases, key=lambda item: (item.passed, item.suite, item.name)):
            mark = "pass" if case.passed else "fail"
            kind = "property" if case.property_test else "example"
            detail = f"<pre>{html.escape(case.message)}</pre>" if case.message else ""
            parts.append(f'<tr><td class="state {mark}">{"ok" if case.passed else "FAIL"}</td>'
                         f'<td>{html.escape(case.suite)} · {html.escape(case.name)} '
                         f'<span class="kind">{kind}</span>{detail}</td>'
                         f'<td class="time">{case.seconds:.2f} s</td></tr>')
        parts.append("</table></details>")
    parts.append("</main></body></html>")
    return "".join(parts)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: test_report.py <ctest junit xml> <html report>")
        return 2
    source = pathlib.Path(sys.argv[1])
    target = pathlib.Path(sys.argv[2])
    modules = group(read_cases(source))
    target.write_text(render(modules, source), encoding="utf-8")
    failed = sum(module.failed for module in modules)
    total = sum(len(module.cases) for module in modules)
    for module in modules:
        print(f"  {module.title:<32} {len(module.cases):>4} tests  {'ok' if module.failed == 0 else str(module.failed) + ' FAILED'}")
    print(f"{total - failed} of {total} tests passed. Report: {target.resolve()}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
