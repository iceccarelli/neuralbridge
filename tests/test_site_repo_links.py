"""The website links into the source repository only when ``NEXT_PUBLIC_REPO_PUBLIC`` is exactly ``true``.

The repository is private and the code proprietary, so every link to it would 404 for a visitor and a
proprietary site should not invite people to a source tree. ``app/lib/links.ts`` is the one place
the repository and profile URLs are spelled; everything else goes through ``repoLink`` /
``<RepoLink>``. ``public/llms.txt`` and ``public/.well-known/agent.json`` are static, so they are
rendered by ``scripts/export_site_static.py`` from ``scripts/site_static/*.tmpl`` under the same flag.

Three layers, each able to fail on its own:

1. source: no hard-coded repository or profile URL outside ``app/lib/links.ts`` and the templates;
2. static files: the committed files are exactly what the generator writes with the flag off;
3. build: a production build with the default flag contains the URL nowhere a visitor can get it
   (HTML, RSC payloads, client JavaScript, sitemap), and a build with the flag on has the links back.

The builds run ``npm run build`` into their own ``NEXT_DIST_DIR`` (about 20 s each, once per module).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NEEDLE = "github.com/iceccarelli"
LINKS_TS = ROOT / "app" / "lib" / "links.ts"
TEXT_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".css", ".txt", ".html", ".xml", ".rsc", ".meta", ".body"}


def _generator():
    spec = importlib.util.spec_from_file_location("export_site_static", ROOT / "scripts" / "export_site_static.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def hard_coded_repo_urls(roots: list[Path], allowed: set[Path]) -> list[str]:
    """Every file under ``roots`` (or named in it) that spells the repository/profile URL."""
    found: list[str] = []
    for root in roots:
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for path in files:
            if path in allowed or path.suffix not in TEXT_SUFFIXES:
                continue
            if NEEDLE in path.read_text(encoding="utf-8", errors="replace"):
                found.append(str(path))
    return found


# ---------------------------------------------------------------------------------------------
# 1. source and static files
# ---------------------------------------------------------------------------------------------


class TestSource:
    def test_no_hard_coded_repository_url_outside_links_ts(self):
        roots = [ROOT / "app", ROOT / "public" / "llms.txt", ROOT / "public" / ".well-known" / "agent.json"]
        assert hard_coded_repo_urls(roots, {LINKS_TS}) == []

    def test_the_scanner_catches_a_hard_coded_link(self, tmp_path):
        """Mutation check on the check itself: a page that hard-codes the URL is reported."""
        app = tmp_path / "app"
        app.mkdir()
        (app / "clean.tsx").write_text("export const a = <a href='/contact'>x</a>;")
        assert hard_coded_repo_urls([app], set()) == []
        (app / "page.tsx").write_text(f"export const a = <a href='https://{NEEDLE}/neuralbridge'>x</a>;")
        assert len(hard_coded_repo_urls([app], set())) == 1

    def test_only_links_ts_reads_the_flag(self):
        readers = [
            str(p.relative_to(ROOT))
            for p in sorted((ROOT / "app").rglob("*.ts*"))
            if "NEXT_PUBLIC_REPO_PUBLIC" in p.read_text(encoding="utf-8") and p != LINKS_TS
        ]
        assert readers == []

    def test_the_flag_defaults_off_and_only_the_exact_string_true_turns_it_on(self):
        links = LINKS_TS.read_text(encoding="utf-8")
        assert "process.env.NEXT_PUBLIC_REPO_PUBLIC === 'true'" in links
        config = (ROOT / "next.config.js").read_text(encoding="utf-8")
        assert "NEXT_PUBLIC_REPO_PUBLIC === 'true' ? 'true' : 'false'" in config
        assert re.search(r"^NEXT_PUBLIC_REPO_PUBLIC=false$", (ROOT / ".env.example").read_text(), re.M)
        gen = _generator()
        for value, expected in [(None, False), ("", False), ("false", False), ("TRUE", False), ("1", False),
                                ("yes", False), ("true ", False), ("true", True)]:
            env = dict(os.environ)
            env.pop("NEXT_PUBLIC_REPO_PUBLIC", None)
            if value is not None:
                env["NEXT_PUBLIC_REPO_PUBLIC"] = value
            old = os.environ.copy()
            try:
                os.environ.clear()
                os.environ.update(env)
                assert gen.repo_public_from_env() is expected, value
            finally:
                os.environ.clear()
                os.environ.update(old)


class TestStaticFiles:
    def test_committed_files_are_the_flag_off_rendering(self):
        gen = _generator()
        for template, target in gen.OUTPUTS.items():
            assert target.read_text(encoding="utf-8") == gen.render(template, False), (
                f"{target.relative_to(ROOT)} is stale: run python scripts/export_site_static.py"
            )
        assert gen.main(["--check"]) == 0

    def test_flag_off_files_name_no_repository(self):
        for rel in ("public/llms.txt", "public/.well-known/agent.json"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            assert NEEDLE not in text and "@repo" not in text, rel
        agent = json.loads((ROOT / "public" / ".well-known" / "agent.json").read_text(encoding="utf-8"))
        assert "source" not in agent and "issues" not in agent["contact"]
        assert agent["contact"]["sales"] == "https://neuralbridge.io/contact"

    def test_flag_on_rendering_restores_the_repository_lines_and_is_valid_json(self):
        gen = _generator()
        llms = gen.render("llms.txt.tmpl", True)
        assert f"- Source repository: https://{NEEDLE}/neuralbridge" in llms
        agent = json.loads(gen.render("agent.json.tmpl", True))
        assert agent["source"] == f"https://{NEEDLE}/neuralbridge"
        assert agent["contact"]["issues"] == f"https://{NEEDLE}/neuralbridge/issues"
        assert "@repo" not in llms
        # Everything else is identical: the flag only adds the repository lines.
        off = gen.render("llms.txt.tmpl", False).split("\n")
        assert [ln for ln in llms.split("\n") if NEEDLE not in ln] == off

    def test_the_templates_only_mark_repository_lines(self):
        gen = _generator()
        for template in gen.OUTPUTS:
            for line in (gen.TEMPLATES / template).read_text(encoding="utf-8").split("\n"):
                assert line.startswith(gen.MARK) == (NEEDLE in line), line


# ---------------------------------------------------------------------------------------------
# 2. production builds
# ---------------------------------------------------------------------------------------------


def _build(flag: str | None, tmp_name: str) -> Path:
    if not (ROOT / "node_modules" / "next").exists():
        pytest.skip("node_modules is not installed (npm ci); the CI Site job runs this module after npm ci")
    dist = ROOT / tmp_name
    shutil.rmtree(dist, ignore_errors=True)
    env = dict(os.environ)
    env.pop("NEXT_PUBLIC_REPO_PUBLIC", None)
    if flag is not None:
        env["NEXT_PUBLIC_REPO_PUBLIC"] = flag
    env["NEXT_DIST_DIR"] = tmp_name
    env["NEXT_TELEMETRY_DISABLED"] = "1"
    tsconfig = ROOT / "tsconfig.json"
    before = tsconfig.read_text(encoding="utf-8")
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv
            [shutil.which("npm") or "npm", "run", "build"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=900,
        )
    finally:
        # `next build` adds the dist directory's type folders to tsconfig.json; put it back.
        tsconfig.write_text(before, encoding="utf-8")
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    return dist


def _built_text_files(dist: Path) -> list[Path]:
    """Everything a visitor can receive: pages, RSC payloads, client and server bundles, sitemap.

    Source maps are excluded: the server-side ones embed original source files and are never served.
    The build cache is excluded: it is not output.
    """
    return [
        p for p in sorted(dist.rglob("*"))
        if p.is_file() and "cache" not in p.relative_to(dist).parts and p.suffix in TEXT_SUFFIXES
    ]


@pytest.fixture(scope="module")
def private_build():
    dist = _build(None, ".next-repo-default")
    yield dist
    shutil.rmtree(dist, ignore_errors=True)


@pytest.fixture(scope="module")
def public_build():
    dist = _build("true", ".next-repo-public")
    yield dist
    shutil.rmtree(dist, ignore_errors=True)


def _html(dist: Path, name: str) -> str:
    return (dist / "server" / "app" / f"{name}.html").read_text(encoding="utf-8")


class TestDefaultBuild:
    def test_built_output_names_no_repository(self, private_build):
        files = _built_text_files(private_build)
        assert any(p.suffix == ".html" for p in files) and any("static" in p.parts for p in files)
        leaks = [str(p.relative_to(private_build)) for p in files if NEEDLE in p.read_text(encoding="utf-8", errors="replace")]
        assert leaks == []

    def test_every_page_renders_without_repository_affordances(self, private_build):
        pages = sorted((private_build / "server" / "app").rglob("*.html"))
        assert len(pages) > 20
        for page in pages:
            html = page.read_text(encoding="utf-8")
            assert "Edit this page on GitHub" not in html, page
            assert "Browse the source" not in html and "View source" not in html, page
            assert "GitHub repository" not in html and ">Contributing<" not in html, page
            assert "sameAs" not in html, page

    def test_json_ld_has_no_owner_profile_or_sameas(self, private_build):
        home = _html(private_build, "index")
        blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', home, re.S)
        assert blocks
        for block in blocks:
            data = json.loads(block)
            assert "sameAs" not in data
            assert "url" not in data.get("creator", {}) and "url" not in data.get("founder", {})

    def test_copy_still_reads_naturally(self, private_build):
        privacy = _html(private_build, "privacy")
        assert 'href="/contact">tell us</a>' in privacy and 'href="/contact">contact us</a>' in privacy
        platform = _html(private_build, "docs/platform")
        assert re.search(r"is in the\s+README(?:&#39;|&#x27;|')s platform section\.</p>", platform)
        start = _html(private_build, "docs/getting-started")
        assert "git clone" not in start and "get a copy of the source from NeuralBridge" in start
        verify = _html(private_build, "verify")
        assert "From a copy of the source" in verify and "git clone" not in verify

    def test_sitemap_and_search_have_no_repository_entry(self, private_build):
        sitemap = (private_build / "server" / "app" / "sitemap.xml.body").read_text(encoding="utf-8")
        assert NEEDLE not in sitemap and "https://neuralbridge.io/contact" in sitemap


class TestRepoPublicBuild:
    def test_footer_and_header_link_to_the_repository_again(self, public_build):
        home = _html(public_build, "index")
        assert f'href="https://{NEEDLE}/neuralbridge"' in home
        assert f"https://{NEEDLE}/neuralbridge/blob/main/CONTRIBUTING.md" in home
        assert f"https://{NEEDLE}/neuralbridge/tree/main/src/assurance/api" in home

    def test_docs_pages_offer_edit_on_github_and_keep_their_links(self, public_build):
        docs = _html(public_build, "docs/getting-started")
        assert "Edit this page on GitHub" in docs
        assert f"https://{NEEDLE}/neuralbridge/blob/main/docs/getting-started.md" in docs
        assert f"git clone https://{NEEDLE}/neuralbridge.git" in docs
        platform = _html(public_build, "docs/platform")
        assert f'href="https://{NEEDLE}/neuralbridge#neuralbridge--the-platform-underneath"' in platform

    def test_json_ld_same_as_is_back(self, public_build):
        home = _html(public_build, "index")
        assert f'"sameAs":["https://{NEEDLE}/neuralbridge"]' in home.replace(" ", "")
