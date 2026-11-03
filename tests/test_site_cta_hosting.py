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
    assert "export const HOSTED_API" in src


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
