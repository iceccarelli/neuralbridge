"""A button must not promise an anonymous online check the deployment cannot perform.

The home page offers two "try it right here" playgrounds that POST to the hosted Assurance API.
That API is only reachable when the site is built with NEXT_PUBLIC_ASSURANCE_API_URL. Without it
the components answer "not deployed publicly yet" -- but only after a click, so a visitor who came
for "check it free, no account" found out late. Copy that makes the promise must therefore be inside
a ``HOSTED_API`` branch (app/lib/hostedApi.ts).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "app" / "page.tsx").read_text(encoding="utf-8")

# Phrases that promise an anonymous, working, online tool.
PROMISES = ("check it free", "free, no account", "try it right here")


def test_flag_is_derived_from_the_build_time_api_url():
    src = (ROOT / "app" / "lib" / "hostedApi.ts").read_text(encoding="utf-8")
    assert "NEXT_PUBLIC_ASSURANCE_API_URL" in src
    # Exactly "is the build-time URL set": `true`, `!url` or a different variable must fail.
    assert re.search(r"export const HOSTED_API = Boolean\(process\.env\.NEXT_PUBLIC_ASSURANCE_API_URL\);", src)


def test_home_page_imports_the_flag():
    assert re.search(r"import \{ HOSTED_API \} from '\./lib/hostedApi'", PAGE)


def test_every_online_promise_on_the_home_page_is_inside_a_hosted_api_branch():
    lines = PAGE.splitlines()
    unguarded = []
    for i, line in enumerate(lines):
        if not any(p in line for p in PROMISES):
            continue
        # The branch condition sits on this line or within the few lines above it.
        window = "\n".join(lines[max(0, i - 6) : i + 1])
        if "HOSTED_API" not in window:
            unguarded.append((i + 1, line.strip()))
    assert not unguarded, f"online-tool promise outside a HOSTED_API branch: {unguarded}"


def test_unhosted_variant_says_where_the_check_actually_runs():
    # The fallback branch must tell the visitor what they can do today, not just retract the promise.
    assert "runs on your own machine today" in PAGE
    assert "hosted endpoint not live yet" in PAGE


def test_promise_sits_in_the_hosted_arm_not_the_unhosted_one():
    # `{HOSTED_API ? 'A' : 'B'}`: the online promise must be arm A. Swapping the arms would pass the
    # window check above while showing the promise on the build that cannot keep it.
    for promise in PROMISES:
        for m in re.finditer(re.escape(promise), PAGE):
            before = PAGE[: m.start()]
            q = max(before.rfind("HOSTED_API ?"), before.rfind("{HOSTED_API\n"))
            assert q >= 0, promise
            between = before[q:]
            # No ':' arm separator may sit between the condition and the promise at the same nesting.
            assert "\n                : " not in between and "\n                  : " not in between, promise


# Copy that was static, promised a free/no-account online tool, and so was false in an unhosted build.
STALE = (
    "Start free",
    "Re-check one Declaration for free",
    "The free checks need no account",
    "Free, no account, nothing stored",
    "free Validator playground on the homepage",
    "Article 14 draft validation, calculators, offline kit. No account.",
)
SOURCES = (
    "app/page.tsx",
    "app/Header.tsx",
    "app/lib/search-index.ts",
    "public/llms.txt",
    "scripts/site_static/llms.txt.tmpl",
)


def test_static_surfaces_do_not_carry_the_retired_online_promises():
    hits = [
        (src, phrase)
        for src in SOURCES
        for phrase in STALE
        if phrase in (ROOT / src).read_text(encoding="utf-8")
    ]
    assert not hits, hits
