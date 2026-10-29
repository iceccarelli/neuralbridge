"""The marketing site's route and CLI tables are checked against the code they describe.

``app/lib/routes.ts`` is curated by hand and ``public/openapi.json`` is exported from the
service. Both used to drift (the committed schema was missing most of the change-assurance
routes, and ``/developers`` quoted a route count that was no longer true). A hand-written
table that a test cannot fail is how a site ends up describing a product that no longer
exists, so these tests fail instead.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from assurance.api.service import app

ROOT = Path(__file__).resolve().parents[1]
ROUTES_TS = (ROOT / "app" / "lib" / "routes.ts").read_text(encoding="utf-8")
METHODS = {"get", "post", "put", "patch", "delete"}


def _norm(path: str) -> str:
    """``{case_id}`` and ``{id}`` are the same route: only the shape of the path matters."""
    return re.sub(r"\{[^}]+\}", "{}", path)


def _served() -> set[tuple[str, str]]:
    return {(m.upper(), _norm(p)) for p, item in app.openapi()["paths"].items() for m in item if m in METHODS}


def _table_rows() -> list[tuple[str, str, str]]:
    return [(m, _norm(p), t) for m, p, t in
            re.findall(r"\{ method: '(\w+)', path: '([^']+)', tier: '(\w+)'", ROUTES_TS)]


def test_the_route_table_is_not_empty() -> None:
    assert len(_table_rows()) > 30


def test_every_route_on_the_developers_page_is_served() -> None:
    served = _served()
    missing = [f"{m} {p}" for m, p, _ in _table_rows() if (m, p) not in served]
    assert not missing, "app/lib/routes.ts lists routes the service does not serve: " + ", ".join(missing)


def test_every_change_and_watch_route_the_service_serves_is_on_the_page() -> None:
    # The groups the customer workspace and the docs lean on. A new route in one of them that the
    # page does not list is a page that no longer describes the product.
    listed = {(m, p) for m, p, _ in _table_rows()}
    prefixes = ("/v1/change/", "/v1/watch/", "/v1/fleet/", "/v1/supplier/")
    unlisted = sorted(f"{m} {p}" for m, p in _served() if p.startswith(prefixes) and (m, p) not in listed)
    assert not unlisted, "served but missing from app/lib/routes.ts: " + ", ".join(unlisted)


def test_the_committed_openapi_schema_is_what_the_service_serves() -> None:
    committed = json.loads((ROOT / "public" / "openapi.json").read_text(encoding="utf-8"))
    live = json.loads(json.dumps(app.openapi()))
    assert committed == live, "public/openapi.json is stale: run `python scripts/export_openapi.py`"


def _cli_domains() -> list[tuple[str, list[str]]]:
    out = []
    for domain, verbs in re.findall(r"\{ domain: '([\w-]+)', verbs: \[([^\]]*)\]", ROUTES_TS):
        out.append((domain, re.findall(r"'([\w-]+)'", verbs)))
    return out


@pytest.mark.parametrize("domain,verbs", _cli_domains())
def test_every_cli_verb_on_the_cli_page_exists(domain: str, verbs: list[str]) -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", domain, "--help"],
        capture_output=True, text=True, check=False, cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"), "COLUMNS": "400"},
    )
    assert result.returncode == 0, result.stderr
    absent = [v for v in verbs if not re.search(rf"(?<![\w-]){re.escape(v)}(?![\w-])", result.stdout)]
    assert not absent, f"`assurance {domain}` has no verb(s) {absent} that app/lib/routes.ts lists"


def test_every_repository_file_the_site_links_to_exists() -> None:
    # The site links to files on GitHub (blob/main/... and tree/main/...). Those links are
    # not crawled by the browser test, so check them against the tree they point into.
    missing: set[str] = set()
    for source in [*(ROOT / "app").rglob("*.ts*"), ROOT / "README.md", *(ROOT / "public").glob("*.txt")]:
        for _kind, rel in re.findall(r"(blob|tree)/main/([A-Za-z0-9_./-]+)", source.read_text(encoding="utf-8")):
            if not (ROOT / rel.rstrip("/.")).exists():
                missing.add(f"{rel} (in {source.relative_to(ROOT)})")
    assert not missing, "linked repository paths that do not exist: " + ", ".join(sorted(missing))
