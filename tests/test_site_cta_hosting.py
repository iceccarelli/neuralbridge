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


def test_every_online_promise_in_the_layout_is_inside_a_hosted_api_branch():
    # The footer banner renders on every page; it promised "for free - no account" with a "Start free" button.
    layout = (ROOT / "app" / "layout.tsx").read_text(encoding="utf-8").splitlines()
    unguarded = [
        (i + 1, line.strip())
        for i, line in enumerate(layout)
        if any(p in line for p in (*PROMISES, "for free", "Start free"))
        and "HOSTED_API" not in "\n".join(layout[max(0, i - 6) : i + 1])
    ]
    assert not unguarded, unguarded


def test_unhosted_variant_says_where_the_check_actually_runs():
    # The fallback branch must tell the visitor what they can do today, not just retract the promise.
    assert "runs on your own machine today" in PAGE
    assert "hosted endpoint not live yet" in PAGE


def _promise_arm_violations(text: str, phrases: tuple[str, ...]) -> list[str]:
    """A promise must sit in the *hosted* arm of a `HOSTED_API ? A : B` expression: after the condition and
    before the `:` that starts the unhosted arm. Indentation-independent; swapping the arms fails it."""
    bad = []
    for phrase in phrases:
        for m in re.finditer(re.escape(phrase), text):
            before = text[: m.start()]
            cond = before.rfind("HOSTED_API")
            if cond < 0 or not re.match(r"HOSTED_API\s*\?", before[cond:]):
                bad.append(f"{phrase!r} @ {m.start()}: no `HOSTED_API ?` condition before it")
                continue
            between = before[cond:]
            if re.search(r"\)\s*:\s*[(<'\"`]|['\"`]\s*:\s*['\"`]|\n\s+:\s", between):
                bad.append(f"{phrase!r} @ {m.start()}: sits in the unhosted arm")
    return bad


def test_promises_sit_in_the_hosted_arm_in_page_and_layout():
    layout = (ROOT / "app" / "layout.tsx").read_text(encoding="utf-8")
    # `for free` / `Start free` only appear in layout.tsx inside the hosted arm; page.tsx's list is PROMISES.
    assert not _promise_arm_violations(PAGE, PROMISES)
    assert not _promise_arm_violations(layout, ("free, no account", "for free", "Start free"))
    assert "HOSTED_API ?" in layout  # the guard exists at all


def test_verify_page_does_not_claim_a_free_online_check_unconditionally():
    verify = (ROOT / "app" / "verify" / "page.tsx").read_text(encoding="utf-8")
    assert "HOSTED_API" in verify
    assert "Free, no account" not in verify
    assert not _promise_arm_violations(verify, ("FREE · NO ACCOUNT",))


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
