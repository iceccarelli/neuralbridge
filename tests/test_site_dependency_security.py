"""The website's framework dependencies stay on patched releases.

The Next.js site (``app/``) runs the Image Optimization API, Server Actions and the App Router on
whatever ``next`` the lockfile resolves. ``next@14.2.15`` carried dozens of advisories (npm's own
registry flags it as deprecated for a security vulnerability), among them unauthenticated remote
code execution in the Image Optimization API (SVG: GHSA-2464-fhr4-w9xw; AVIF: GHSA-2xp9-vwfh-vxw4),
an authorization bypass in middleware (GHSA-f82v-jwr5-mffw) and several denial-of-service and SSRF
issues. The SVG fix also needs ``sharp`` 0.35.5 or later.

CI runs pytest, not Node, so a downgrade, a caret range that resolves lower in a fresh lockfile, or a
hand-edited ``package.json`` that leaves the lockfile behind would otherwise merge unnoticed. These
tests read what is actually pinned and locked. They do not call the network; they cannot prove the
absence of a vulnerability that has not been published, only that the known-bad versions are not
what we ship. ``npm audit --omit=dev`` is the live check and is recorded in the pull request.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
LOCK = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))


def _evaluated_next_config() -> dict:
    """``next.config.js`` as Next sees it, not as text: a substring check cannot tell
    ``unoptimized: true`` from ``"unoptimized": true`` or a comment that mentions a flag."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; the next.config.js checks need it")
    out = subprocess.run(
        [node, "-e", "process.stdout.write(JSON.stringify(require(process.argv[1])))",
         str(ROOT / "next.config.js")],
        capture_output=True, text=True, check=True, timeout=60)
    return json.loads(out.stdout)

#: The lowest release on each supported line that contains the 14 October 2026 fixes
#: (registry: 15.5.28 is the last 15.x, 16.4.1 the first 16.x with them).
MIN_NEXT = {15: (15, 5, 28), 16: (16, 4, 1)}
MIN_SHARP = (0, 35, 5)
#: @img/sharp-libvips-*: 1.3.4 bundles librsvg 2.63.2 (1.3.3 bundled 2.62.91).
MIN_LIBVIPS = (1, 3, 4)


def _version(text: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", text)
    assert match, f"{text!r} is not an exact x.y.z version"
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _locked(name: str) -> dict:
    entry = LOCK["packages"].get(f"node_modules/{name}")
    assert entry, f"{name} is not in package-lock.json"
    return entry


def test_next_is_pinned_exactly():
    declared = PACKAGE["dependencies"]["next"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", declared), (
        f"next is declared as {declared!r}; pin an exact patched release so a fresh install "
        "cannot resolve a different one")


def test_the_locked_next_is_a_patched_release():
    locked = _version(_locked("next")["version"])
    floor = MIN_NEXT.get(locked[0])
    assert floor is not None, (
        f"next {locked} is on an unsupported major line; supported lines: {sorted(MIN_NEXT)}")
    assert locked >= floor, f"next {locked} is below the patched release {floor}"


def test_the_lockfile_and_package_json_agree_on_next():
    assert _locked("next")["version"] == PACKAGE["dependencies"]["next"]


def test_the_lockfile_does_not_mark_next_as_vulnerable():
    """npm's registry sets ``deprecated`` on releases with a known security vulnerability."""
    assert "deprecated" not in _locked("next"), _locked("next").get("deprecated")


def test_sharp_is_at_least_the_librsvg_fix():
    assert _version(_locked("sharp")["version"]) >= MIN_SHARP
    declared = PACKAGE["dependencies"]["sharp"]
    assert _version(declared.lstrip("^~")) >= MIN_SHARP, declared


def test_no_nested_sharp_below_the_fix():
    for path, entry in LOCK["packages"].items():
        if path.endswith("/sharp") and entry.get("version"):
            assert _version(entry["version"]) >= MIN_SHARP, f"{path}: {entry['version']}"


def test_the_libvips_that_carries_librsvg_is_patched():
    """The SVG fix lives in the prebuilt libvips (it bundles librsvg), not in sharp's JS."""
    found = 0
    for path, entry in LOCK["packages"].items():
        if "/@img/sharp-libvips-" in f"/{path}" and entry.get("version"):
            found += 1
            assert _version(entry["version"]) >= MIN_LIBVIPS, f"{path}: {entry['version']}"
    assert found, "no @img/sharp-libvips-* in the lockfile; sharp would build libvips itself"


def test_next_native_binaries_match_next():
    """``@next/swc-*`` ships with the same version as ``next``; a stale one means a hand-edited lock."""
    version = _locked("next")["version"]
    swc = {p: e for p, e in LOCK["packages"].items() if p.startswith("node_modules/@next/swc-")}
    assert swc, "no @next/swc-* packages locked"
    for path, entry in swc.items():
        assert entry["version"] == version, f"{path}: {entry['version']} != next {version}"


def test_next_never_resolves_a_bundled_postcss_with_known_source_map_reads():
    """Next bundles its own postcss; 8.5.23+ carries the sourceMappingURL fixes."""
    nested = LOCK["packages"].get("node_modules/next/node_modules/postcss")
    if nested is not None:
        assert _version(nested["version"]) >= (8, 5, 23), nested["version"]


def test_every_locked_package_comes_from_the_npm_registry_with_an_integrity_hash():
    """A hand-edited ``resolved`` URL (or a dropped hash) is how a lockfile is turned into a
    supply-chain vector; ``npm ci`` would install whatever it points at."""
    for path, entry in LOCK["packages"].items():
        if not path or entry.get("link"):
            continue
        resolved = entry.get("resolved")
        assert resolved and resolved.startswith("https://registry.npmjs.org/"), f"{path}: {resolved}"
        assert str(entry.get("integrity", "")).startswith("sha512-"), f"{path}: integrity"


def test_the_declared_node_floor_matches_what_next_requires():
    engines = LOCK["packages"]["node_modules/next"].get("engines", {}).get("node", "")
    floor = re.search(r">=\s*(\d+)\.(\d+)", engines)
    assert floor, f"next declares no Node floor ({engines!r}); this guard needs updating"
    needed = (int(floor.group(1)), int(floor.group(2)))
    declared_text = PACKAGE.get("engines", {}).get("node", "")
    declared = re.fullmatch(r">=\s*(\d+)\.(\d+)(?:\.\d+)?", declared_text.strip())
    # A range such as "^18.18.0 || >=20.9.0" would admit a Node that cannot build the site.
    assert declared, f"package.json engines.node must be a single '>=x.y.z' floor, not {declared_text!r}"
    assert (int(declared.group(1)), int(declared.group(2))) >= needed
    lock_root = LOCK["packages"][""].get("engines", {}).get("node")
    assert lock_root == declared_text, "package-lock.json root is out of step with package.json engines"


def test_image_optimization_is_not_widened():
    """SVG through the optimizer was the route to the critical RCE; do not opt back in. Evaluated,
    not grepped, so formatting and comments cannot hide or fake a setting."""
    cfg = _evaluated_next_config()
    images = cfg.get("images", {}) or {}
    assert not images.get("dangerouslyAllowSVG"), "SVG must not go through the image optimizer"
    assert not images.get("unoptimized"), "images.unoptimized hides the optimizer instead of patching it"
    assert not images.get("remotePatterns"), "no remote image sources: nothing outside /public may be fetched"
    assert not images.get("domains"), "no remote image sources: nothing outside /public may be fetched"
    assert not images.get("localPatterns"), "do not widen the local paths the optimizer will read"


def test_image_cache_ttl_keeps_the_pre_16_behaviour():
    """Next 16 defaults ``minimumCacheTTL`` to 4 h; a hero replaced at the same URL would be stale."""
    assert _evaluated_next_config().get("images", {}).get("minimumCacheTTL") == 60


def test_the_dev_origin_allowlist_is_loopback_only():
    origins = _evaluated_next_config().get("allowedDevOrigins", [])
    assert set(origins) <= {"127.0.0.1", "localhost"}, origins


def test_there_is_no_dead_lint_script():
    """``next lint`` was removed in Next 16; a script that cannot run hides that nothing lints."""
    assert PACKAGE["scripts"].get("lint") != "next lint"
    assert PACKAGE["scripts"].get("typecheck") == "tsc --noEmit"
    if "lint" in PACKAGE["scripts"]:
        configs = [p for p in ROOT.glob("eslint.config.*")] + [p for p in ROOT.glob(".eslintrc*")]
        assert configs, "a lint script needs a lint config, or it only looks like something is checked"


# ---------------------------------------------------------------------------
# Next 15+ route params are a Promise; Next 16 removed synchronous access.
# ---------------------------------------------------------------------------

APP = ROOT / "app"
_DYNAMIC_SEGMENT = re.compile(r"\[[^/\]]+\]")


def _code(text: str) -> str:
    """Source without ``//`` comment lines, so an explanation may quote the old form."""
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("//"))


def _dynamic_route_files() -> list[Path]:
    out = []
    for path in sorted(APP.rglob("*.ts*")):
        rel = path.relative_to(APP).as_posix()
        if path.name in {"page.tsx", "layout.tsx", "route.ts", "route.tsx"} and _DYNAMIC_SEGMENT.search(rel):
            out.append(path)
    return out


def test_there_are_dynamic_routes_to_guard():
    names = {p.relative_to(APP).as_posix() for p in _dynamic_route_files()}
    assert any(n.startswith("solutions/[slug]") for n in names), names
    assert any(n.startswith("docs/[[...slug]]") for n in names), names


_ALLOWED_PARAMS_USES = (
    (re.compile(r"\bawait\s+params\b"), "await params"),
    (re.compile(r"\{\s*params\s*\}"), "{ params }"),
    (re.compile(r"\bparams\s*:\s*[A-Z]\w*"), "params: <TypeAlias>"),
)


@pytest.mark.parametrize("path", _dynamic_route_files(), ids=lambda p: p.relative_to(APP).as_posix())
def test_dynamic_route_params_are_awaited(path):
    """``params.slug`` read directly is ``undefined`` on Next 16: /solutions/* became a 404 and
    every /docs/* page silently rendered the docs index with a canonical of /docs/. The build and
    ``tsc`` both passed, so only the code itself can guard this.

    The only accepted uses of ``params`` are: taking it in a signature as ``{ params }`` typed by a
    ``type X = Promise<...>`` alias, and ``await params``. Anything else (``(params as any).slug``,
    ``{ params: { slug } }``, ``params[...]``, passing it on) is refused, and every function that
    takes ``params`` must await it."""
    code = _code(path.read_text(encoding="utf-8"))
    if not re.search(r"\bparams\b", code):
        return
    aliases = re.findall(r"\btype\s+(\w+)\s*=\s*Promise<", code)
    assert aliases, f"{path.name}: params must be typed by a `type X = Promise<...>` alias"
    for name in re.findall(r"\bparams\s*:\s*([A-Za-z_]\w*)", code):
        assert name in aliases, f"{path.name}: params is typed {name!r}, which is not a Promise alias"

    rest = code
    for pattern, _ in _ALLOWED_PARAMS_USES:
        rest = pattern.sub(" ", rest)
    leftover = re.search(r".{0,30}\bparams\b.{0,30}", rest)
    assert not leftover, f"{path.name}: params is used other than as `await params`: {leftover.group(0)!r}"

    taken = len(re.findall(r"\{\s*params\s*\}", code))
    awaited = len(re.findall(r"\bawait\s+params\b", code))
    assert taken and awaited >= taken, (
        f"{path.name}: {taken} function(s) take params but only {awaited} await it")
