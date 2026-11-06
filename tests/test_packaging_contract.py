"""The dependency split in ``pyproject.toml`` is measured, not asserted.

The base install used to declare 21 unconditional dependencies (a web framework, an ORM,
asyncpg, redis, tiktoken ...) although the offline kit imports one third-party package. The
split is now: base = ``cryptography``; everything else is a named extra. These tests pin it
two ways, neither of which needs a network:

1. **Runtime, default-deny, in a subprocess.** The offline kit is imported and *run* (every
   ``assurance`` module is imported; ``kit init/check/run`` and every CLI domain are
   executed) in an interpreter whose import system refuses every top-level package that is
   not the standard library, this checkout, or ``cryptography`` (and its own binding
   ``cffi``). This is the fast stand-in for a clean virtual environment: it blocks by name
   what a clean environment would not have. The real clean-venv proof (``python -m venv``,
   ``pip install -e .``, run the demo) was done by hand when the split was made and is
   recorded in the change description; it is not repeated here because creating a venv and
   downloading wheels is slow and needs an index, and a skipped test would be a gate that did
   not run.
2. **Static, by AST.** For each surface the third-party imports under its source files must be
   covered by the packages that surface's install declares. A new ``import redis`` in the kit,
   or a new import in ``neuralbridge.mcp.server`` that its extra lacks, fails here.

Imports inside a function (lazy imports with a clear error) count as the surface's *optional*
packages: they must be declared by some extra, but are not required by the base.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
EXTRAS = PROJECT["optional-dependencies"]
SELF = canonicalize_name(PROJECT["name"])

#: import name -> distribution, where the canonical form of the import name is not it.
IMPORT_TO_DIST = {
    "yaml": "pyyaml",
    "jwt": "pyjwt",
    "multipart": "python-multipart",
    "google": "google-cloud-bigquery",
}
#: packages the declared one brings in and the source imports directly; named here so that the
#: day a direct dependency is needed it has to be declared, not assumed.
PROVIDED_BY = {
    "starlette": "fastapi",     # fastapi is a thin layer over starlette
    "httpcore": "httpx",
    "bson": "motor",            # motor requires pymongo, which ships bson
    "cffi": "cryptography",
}
#: declared in the platform extra but imported by nothing under src/. Kept so `.[platform]`
#: is exactly the old unconditional install; moving a name out of this set requires it to be
#: imported, and a new import of one of these makes the test below ask you to delete it here.
PLATFORM_DECLARED_NOT_IMPORTED = {
    "sqlalchemy", "alembic", "opentelemetry-api", "opentelemetry-sdk",
    "opentelemetry-instrumentation-fastapi", "prometheus-client", "jinja2", "python-multipart",
}
STDLIB = set(sys.stdlib_module_names)


def dist_names(requirements: list[str], seen: frozenset[str] = frozenset()) -> set[str]:
    """Canonical distribution names, following ``neuralbridge-middleware[extra]`` references."""
    names: set[str] = set()
    for raw in requirements:
        req = Requirement(raw)
        name = canonicalize_name(req.name)
        if name == SELF:
            for extra in req.extras:
                if extra not in seen:
                    names |= dist_names(EXTRAS[extra], seen | {extra})
        else:
            names.add(name)
    return names


def base() -> set[str]:
    return dist_names(PROJECT["dependencies"])


def extra(*names: str) -> set[str]:
    return base().union(*(dist_names(EXTRAS[n], frozenset({n})) for n in names))


def third_party(paths: list[Path], *, nested: bool | None = None) -> dict[str, set[str]]:
    """top-level third-party import name -> files. ``nested`` True: only imports inside
    functions/try blocks; False: only module-level statements; None: all."""
    found: dict[str, set[str]] = {}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_level = {id(n) for n in tree.body}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module]
            else:
                continue
            if nested is not None and (id(node) in module_level) == nested:
                continue
            for mod in mods:
                top = mod.split(".")[0]
                if top not in STDLIB and top not in {"assurance", "neuralbridge", "tests"}:
                    found.setdefault(top, set()).add(str(path.relative_to(ROOT)))
    return found


def dist_of(import_name: str) -> str:
    name = IMPORT_TO_DIST.get(import_name, canonicalize_name(import_name))
    return PROVIDED_BY.get(name, name)


def uncovered(paths: list[Path], provided: set[str], **kw) -> dict[str, set[str]]:
    return {i: files for i, files in third_party(paths, **kw).items()
            if dist_of(i) not in provided}


def py(*parts: str) -> list[Path]:
    return sorted((SRC.joinpath(*parts)).rglob("*.py"))


# Modules of src/assurance that need an extra at import time, by the package that is missing.
# Measured with `import` of every module in a venv holding only cryptography.
ASSURANCE_NEEDS_EXTRA = {
    "assurance.api": "fastapi",
    "assurance.billing.payg": "httpx",
    "assurance.billing.reconcile": "httpx",
    "assurance.billing.stripe_gateway": "httpx",
    "assurance.check.schemas": "pydantic",
    "assurance.mcp.server": "httpx",
}
ASSURANCE_API_ONLY = {  # modules whose imports belong to the assurance-api extra, not the base
    "api", "check/schemas.py", "billing/stripe_gateway.py", "billing/payg.py",
    "billing/reconcile.py", "mcp",
}


def assurance_kit_files() -> list[Path]:
    """src/assurance minus the modules that need an extra at import time."""
    out = []
    for path in py("assurance"):
        rel = path.relative_to(SRC / "assurance").as_posix()
        if any(rel == a or rel.startswith(a + "/") for a in ASSURANCE_API_ONLY):
            continue
        out.append(path)
    return out


class TestDeclared:
    def test_the_base_install_is_cryptography_and_nothing_else(self):
        assert base() == {"cryptography"}

    def test_every_extra_the_docs_name_exists(self):
        for name in ("assurance-attest", "assurance-supplier-fetch", "assurance-api",
                     "assurance-mcp", "neuralbridge-ai-mcp", "platform", "bigquery",
                     "mongodb", "mysql", "dev", "docs"):
            assert name in EXTRAS, name

    def test_assurance_attest_is_the_same_install_as_the_base(self):
        assert dist_names(EXTRAS["assurance-attest"]) == base()

    def test_the_api_extra_is_the_service_image_input(self):
        """deploy/assurance/Dockerfile installs requirements/assurance-service.lock; the extra,
        the .txt and therefore the lock must name the same packages."""
        lines = (ROOT / "requirements" / "assurance-service.txt").read_text().splitlines()
        txt = {canonicalize_name(Requirement(ln).name) for ln in lines
               if ln.strip() and not ln.lstrip().startswith("#")}
        assert dist_names(EXTRAS["assurance-api"]) == txt

    def test_the_platform_extra_is_what_base_txt_installs_for_the_platform(self):
        """requirements/base.txt feeds prod.lock/test.lock (--no-deps installs): it must hold
        every package the platform, API, MCP and dev extras name, or those images/test legs
        would lack something `pip install -e '.[dev]'` has."""
        lines = (ROOT / "requirements" / "base.txt").read_text().splitlines()
        txt = {canonicalize_name(Requirement(ln).name) for ln in lines
               if ln.strip() and not ln.lstrip().startswith("#")}
        need = extra("platform", "assurance-api", "assurance-mcp", "neuralbridge-ai-mcp")
        assert need <= txt, sorted(need - txt)

    def test_platform_is_everything_the_project_used_to_install_unconditionally(self):
        # The 21 names before the split (git history: pyproject.toml at 806188b).
        before = {
            "fastapi", "uvicorn", "pydantic", "pydantic-settings", "sqlalchemy", "asyncpg",
            "alembic", "redis", "cryptography", "pyjwt", "httpx", "pyyaml", "structlog",
            "opentelemetry-api", "opentelemetry-sdk", "opentelemetry-instrumentation-fastapi",
            "prometheus-client", "tiktoken", "jinja2", "python-multipart", "passlib"}
        assert len(before) == 21
        assert before <= dist_names(EXTRAS["platform"]), sorted(
            before - dist_names(EXTRAS["platform"]))

    def test_dev_covers_everything_the_tests_import(self):
        provided = dist_names(EXTRAS["dev"]) | base() | {"pytest"}
        missing = {i: sorted(f)[:2] for i, f in
                   third_party(sorted((ROOT / "tests").rglob("*.py"))).items()
                   if dist_of(i) not in provided and i not in {"_pytest"}}
        assert not missing, f"tests import packages `.[dev]` does not install: {missing}"


class TestStaticSurfaces:
    def test_the_offline_kit_imports_only_the_base_at_module_level(self):
        bad = uncovered(assurance_kit_files(), base(), nested=False)
        assert not bad, f"module-level third-party import in the offline kit: {bad}"

    def test_the_offline_kit_imports_beyond_base_only_lazily_and_only_declared_packages(self):
        everything = extra("assurance-api", "assurance-supplier-fetch")
        bad = uncovered(assurance_kit_files(), everything, nested=True)
        assert not bad, f"lazy import no extra declares: {bad}"

    def test_the_api_surface_is_covered_by_the_api_extra(self):
        files = [p for p in py("assurance") if "/mcp/" not in p.as_posix()]
        bad = uncovered(files, extra("assurance-api"))
        assert not bad, f"imports `.[assurance-api]` does not install: {bad}"

    def test_the_assurance_mcp_gateway_is_covered_by_its_extra(self):
        bad = uncovered(py("assurance", "mcp"), extra("assurance-mcp"))
        assert not bad, bad

    def test_neuralbridge_ai_mcp_is_covered_by_its_extra(self):
        files = [SRC / "neuralbridge" / "__init__.py", SRC / "neuralbridge" / "config.py",
                 *py("neuralbridge", "mcp")]
        bad = uncovered(files, extra("neuralbridge-ai-mcp"))
        assert not bad, bad

    def test_the_platform_is_covered_by_the_platform_extra_and_the_vendor_extras(self):
        vendor = {"bigquery.py": "bigquery", "mongodb.py": "mongodb", "mysql.py": "mysql"}
        platform_files = []
        for path in py("neuralbridge"):
            if "/neuralbridge/mcp/" in path.as_posix():
                continue                       # covered by neuralbridge-ai-mcp (+ platform)
            if path.parent.name == "databases" and path.name in vendor:
                bad = uncovered([path], extra("platform", vendor[path.name]))
                assert not bad, (path.name, bad)
                continue
            platform_files.append(path)
        bad = uncovered(platform_files, extra("platform"))
        assert not bad, f"imports `.[platform]` does not install: {bad}"
        bad = uncovered(py("neuralbridge", "mcp"), extra("platform", "neuralbridge-ai-mcp"))
        assert not bad, bad

    def test_platform_declared_but_unimported_packages_are_exactly_the_documented_set(self):
        imported = {dist_of(i) for i in third_party(py("neuralbridge") + py("assurance"))}
        declared = dist_names(EXTRAS["platform"])
        unused = {d for d in declared if d not in imported}
        # httpx etc. may be reached transitively; only direct imports count here.
        assert unused == PLATFORM_DECLARED_NOT_IMPORTED, (
            f"declared-not-imported changed: now {sorted(unused)}. A newly imported package "
            f"must be removed from PLATFORM_DECLARED_NOT_IMPORTED; a newly unused one added, "
            f"or dropped from pyproject.toml if the founder agrees")


_BLOCKER = r"""
import importlib.abc, importlib.machinery, json, sys
ALLOWED = {"assurance", "tests", "cryptography", "cffi", "_cffi_backend", "pycparser"}
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        top = name.split(".")[0]
        if top in sys.stdlib_module_names or top in ALLOWED or top.startswith("_"):
            return None
        raise ModuleNotFoundError(f"No module named {top!r} (blocked: not in the base install)",
                                  name=top)
sys.meta_path.insert(0, Deny())
sys.path.insert(0, sys.argv[1])
import importlib, pkgutil
import assurance
failed = {}
for info in pkgutil.walk_packages(assurance.__path__, "assurance."):
    if info.name == "assurance.__main__":
        continue
    try:
        importlib.import_module(info.name)
    except ModuleNotFoundError as exc:
        failed[info.name] = exc.name
json.dump(failed, sys.stdout)
"""


def _run(code: str, *args: str, cwd: Path, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code, *args], capture_output=True, text=True, check=False,
        cwd=cwd, timeout=timeout, env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(SRC)})


class TestOfflineKitRunsWithOnlyTheBase:
    def test_exactly_the_documented_modules_need_an_extra(self, tmp_path):
        done = _run(_BLOCKER, str(SRC), cwd=tmp_path)
        assert done.returncode == 0, done.stderr[-2000:]
        failed = json.loads(done.stdout)
        assert failed == ASSURANCE_NEEDS_EXTRA, (
            "the set of assurance modules that cannot be imported on a base install changed: "
            f"{failed}. If a module now needs a package, declare it in the right extra and "
            "update README 'Install' and ASSURANCE_NEEDS_EXTRA; if one stopped needing it, "
            "update this table.")

    def test_the_kit_and_every_cli_domain_run_under_default_deny(self, tmp_path):
        code = _BLOCKER.split("import importlib, pkgutil")[0] + r"""
import json
from pathlib import Path
from assurance.cli import main
plant = Path(sys.argv[2])
assert main(['kit', 'init', str(plant)]) == 0
assert main(['report', 'demo', '--out', str(plant / 'demo')]) == 0
assert (plant / 'demo' / 'report.html').exists()
for domain in ('report', 'collect', 'art14', 'machine', 'machinery', 'fleet', 'bridge', 'watch',
               'attest', 'kit', 'supplier', 'check', 'change', 'evidence', 'intel', 'value',
               'ops', 'tenant', 'billing'):
    try:
        main([domain, '--help'])
    except SystemExit as exc:
        assert exc.code in (0, None), domain
# the one domain that reads the API's routes says what it needs instead of a traceback
assert main(['capabilities', '--check']) == 2
print('ok')
"""
        done = _run(code, str(SRC), str(tmp_path / "plant"), cwd=tmp_path)
        assert done.returncode == 0, done.stderr[-2500:] + done.stdout[-500:]
        assert done.stdout.strip().endswith("ok")


class TestTheDocsMatch:
    def test_the_readme_install_table_names_every_extra_it_tells_you_to_install(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        section = text.split("## Install: what each extra adds", 1)[1].split("\n## ", 1)[0]
        named = set(re.findall(r"\.\[([\w\-]+)\]", section))
        assert {"assurance-supplier-fetch", "assurance-api", "assurance-mcp", "platform",
                "neuralbridge-ai-mcp", "dev"} <= named
        for name in named:
            assert name in EXTRAS, f"README names `.[{name}]`, which pyproject does not define"

    def test_every_install_command_in_the_docs_names_an_existing_extra(self):
        offenders = []
        paths = [ROOT / "README.md", *(ROOT / "docs").rglob("*.md"),
                 *(ROOT / "app").rglob("*.tsx"), *(ROOT / "deploy").rglob("*.md")]
        for path in paths:
            for extras in re.findall(r"pip install[^\n`]*?\.\[([\w,\-]+)\]", path.read_text(
                    encoding="utf-8", errors="ignore")):
                for name in extras.split(","):
                    if name not in EXTRAS:
                        offenders.append((str(path.relative_to(ROOT)), name))
        assert not offenders, offenders
