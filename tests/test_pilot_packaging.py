"""What a stranger is told to install, against what the project actually is.

The hint in ``assurance.attest.keys`` told people to ``pip install 'neuralbridge[assurance-attest]'``.
There is no distribution of that name in this project (it is ``neuralbridge-middleware``), so the
command installed an unrelated name from the index. And ``pip install -e '.[assurance-attest]'``,
which the README gave as the way to start, installs every one of the project's *core*
dependencies (a web framework, an ORM, asyncpg, redis, tiktoken ...) beside the one the offline kit
imports, which is not "one runtime dependency". The base install has since been reduced to
``cryptography`` (the platform's packages moved to the ``platform`` extra;
``tests/test_packaging_contract.py`` measures the split). The offline kit needs ``cryptography``
and, without installing the project, the checkout on ``PYTHONPATH``; these tests read
``pyproject.toml`` and fail when the words drift from it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PROJECT = PYPROJECT["project"]
BASE_DEPENDENCIES = {re.split(r"[\[<>=!~ ]", d)[0].lower() for d in PROJECT["dependencies"]}

#: Everywhere a stranger is told how to install the offline kit.
INSTALL_INSTRUCTIONS = [
    "README.md", "docs/getting-started.md",
    "app/page.tsx", "app/cli/page.tsx", "app/verify/page.tsx",
    ".github/workflows/assurance.yml",
]


def _import_error_without_cryptography() -> str:
    code = (
        "import sys\n"
        "sys.modules['cryptography'] = None\n"        # an import now raises ImportError
        "try:\n"
        "    import assurance.attest.keys\n"
        "except ImportError as exc:\n"
        "    print(exc)\n")
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=False,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")}, timeout=60)
    assert done.returncode == 0, done.stderr
    return " ".join(done.stdout.split())


class TestTheHintNamesARealThing:
    def test_every_requirement_in_the_hint_is_this_project_or_cryptography(self):
        hint = _import_error_without_cryptography()
        requirements = re.findall(r"pip install '([^']+)'|pip install ([A-Za-z][\w.\-]*)", hint)
        names = [quoted or bare for quoted, bare in requirements]
        assert names, hint
        for requirement in names:
            match = re.fullmatch(r"([A-Za-z][\w.\-]*)(?:\[([\w,\-]+)\])?", requirement)
            assert match, requirement
            name, extras = match.group(1), match.group(2)
            assert name in {PROJECT["name"], "cryptography"}, (
                f"{requirement!r} names a distribution this project is not: the project is "
                f"{PROJECT['name']!r}")
            for extra in (extras.split(",") if extras else []):
                assert extra in PYPROJECT["project"]["optional-dependencies"], extra
        assert "pip install cryptography" in hint

    def test_the_extra_the_docs_name_exists_and_carries_cryptography(self):
        extra = PROJECT["optional-dependencies"]["assurance-attest"]
        assert any(r.startswith("cryptography") for r in extra)

    def test_the_wrong_distribution_name_appears_nowhere(self):
        wrong = re.compile(r"neuralbridge\[")
        hits = []
        for path in [*(ROOT / "src").rglob("*.py"), *ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md"),
                     *(ROOT / "app").rglob("*.ts*"), *(ROOT / "deploy").rglob("*.md")]:
            if wrong.search(path.read_text(encoding="utf-8", errors="ignore")):
                hits.append(str(path.relative_to(ROOT)))
        assert not hits, hits

    def test_the_hint_no_longer_calls_it_the_one_runtime_dependency_of_an_install(self):
        hint = _import_error_without_cryptography()
        assert "`cryptography` and nothing else" in hint, hint
        assert "core dependencies" not in hint, hint


class TestTheInstructionsStateWhatInstallingDoes:
    def test_the_base_install_is_cryptography_and_the_platform_packages_are_an_extra(self):
        """What the README says: the base is minimal, the platform's packages are opt-in."""
        assert BASE_DEPENDENCIES == {"cryptography"}
        platform = {re.split(r"[\[<>=!~ ]", d)[0].lower()
                    for d in PROJECT["optional-dependencies"]["platform"]}
        assert {"fastapi", "sqlalchemy", "asyncpg", "redis", "tiktoken"} <= platform

    def test_every_install_instruction_gives_the_minimal_path(self):
        missing = []
        for rel in INSTALL_INSTRUCTIONS:
            text = (ROOT / rel).read_text(encoding="utf-8")
            if "pip install cryptography" not in text or "PYTHONPATH=src" not in text:
                missing.append(rel)
        assert not missing, f"no `pip install cryptography` + `PYTHONPATH=src` in: {missing}"

    def test_the_readme_says_what_the_base_install_is_and_where_the_rest_went(self):
        text = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
        assert "`cryptography` and nothing else" in text
        assert "core dependencies" not in text       # no stale count of twenty-one
        assert "assurance-attest" in text            # the extra is still mentioned, truthfully
        assert "'.[platform]'" in text               # where the platform's packages went
        for name in ("fastapi", "sqlalchemy", "asyncpg", "redis"):
            assert name in text                      # named in the Install table

    def test_no_instruction_still_presents_the_extra_as_the_whole_install(self):
        bare = re.compile(r"^\s*pip install -e '\.\[assurance-attest\]'\s*$", re.M)
        offenders = [rel for rel in INSTALL_INSTRUCTIONS
                     if bare.search((ROOT / rel).read_text(encoding="utf-8"))]
        assert not offenders, offenders


class TestTheMinimalPathReallyWorks:
    """With only the standard library and cryptography importable, plus the checkout."""

    #: Import names of the core dependencies whose module name differs from the distribution's.
    ALIASES = {"pyyaml": "yaml", "pyjwt": "jwt", "python_multipart": "multipart",
               "python_jose": "jose", "opentelemetry_api": "opentelemetry",
               "opentelemetry_sdk": "opentelemetry",
               "opentelemetry_instrumentation_fastapi": "opentelemetry",
               "google_cloud_bigquery": "google"}

    def test_a_kit_is_written_filled_checked_and_run_with_nothing_but_cryptography(
            self, tmp_path):
        # tests/test_packaging_contract.py blocks default-deny; this one also names every
        # package any non-test extra could install.
        extras = {k: v for k, v in PROJECT["optional-dependencies"].items()
                  if k not in {"dev", "docs"}}
        distributions = {re.split(r"[\[<>=!~ ]", d)[0].lower().replace("-", "_")
                         for deps in extras.values() for d in deps
                         if not d.startswith("neuralbridge-middleware")} - {"cryptography"}
        blocked = sorted({self.ALIASES.get(d, d) for d in distributions})
        code = (
            "import json, sys\n"
            f"for name in {blocked!r}:\n"
            "    sys.modules[name] = None\n"            # an import of it now raises ImportError
            "from pathlib import Path\n"
            "sys.path.insert(0, sys.argv[2])\n"
            "from tests.support import write_export\n"
            "from assurance.cli import main\n"
            "plant = Path(sys.argv[1])\n"
            "assert main(['kit', 'init', str(plant)]) == 0\n"
            "kit = json.loads((plant / 'kit.json').read_text())\n"
            "kit.update(organisation='Acme', prepared_by='a@acme.example')\n"
            "(plant / 'kit.json').write_text(json.dumps(kit))\n"
            "plan = json.loads((plant / 'plans' / 'cell.json').read_text())\n"
            "plan.update(manufacturer='Acme', model='Scan-9')\n"
            "for item in plan['items']:\n"
            "    item['supplier'] = 'ScanCo'\n"
            "(plant / 'plans' / 'cell.json').write_text(json.dumps(plan))\n"
            "(plant / 'exports' / 'CELL-0412' / 'PUT-EXPORTS-HERE.txt').unlink()\n"
            "write_export(plant / 'exports' / 'CELL-0412', stamp='2026-09-14T06:02:11Z',\n"
            "             operator='m', seq='0040')\n"
            "assert main(['kit', 'check', str(plant / 'kit.json')]) == 0\n"
            "assert main(['kit', 'run', str(plant / 'kit.json'), '--out', str(plant / 'out')]) == 0\n"
            "for domain in ('kit', 'machine', 'machinery', 'change', 'collect', 'evidence',\n"
            "               'watch', 'fleet', 'attest', 'art14', 'report', 'billing'):\n"
            "    try:\n"
            "        main([domain, '--help'])\n"
            "    except SystemExit as exc:\n"
            "        assert exc.code in (0, None), domain\n")
        done = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code, str(tmp_path / "plant"), str(ROOT)],
            capture_output=True, text=True, check=False, cwd=tmp_path, timeout=180,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src")})
        assert done.returncode == 0, done.stderr[-2500:]
        assert (tmp_path / "plant" / "out" / "report.html").exists()
