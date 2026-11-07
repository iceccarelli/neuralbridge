"""scripts/verify-release.sh fails closed, and the publish workflow keeps its safety shape.

HONEST SCOPE: cosign and gh are replaced by small stub executables that print what the real tools
print on success or failure. This proves the SCRIPT's logic (every mismatch is a refusal, a missing
tool is "unchecked", never a pass). It does NOT prove that a real signature or attestation exists:
no release workflow has run, and no real cosign/gh/Sigstore call is made here.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-release.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "publish-docker.yml"

IMAGE = "ghcr.io/example-org/example-repo"
DIGEST = "sha256:" + "a1" * 32
OTHER = "sha256:" + "b2" * 32

bash = shutil.which("bash")
pytestmark = pytest.mark.skipif(bash is None, reason="bash is required")


# Everything the script and the stubs execute besides the stubs themselves and python3. Never gh or cosign.
_SYSTEM_TOOLS = ("bash", "sh", "cat", "sed", "grep", "tr", "head", "tail", "cut", "sort", "awk", "date",
                 "mktemp", "rm", "mkdir", "env", "dirname", "basename", "readlink", "uname", "wc", "tee",
                 "printf", "sleep", "ls", "id", "true", "false", "test")


def _exe(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _cosign_json(digest: str) -> str:
    return json.dumps([{"critical": {"image": {"docker-manifest-digest": digest}}}])


def _gh_json(digest: str, ptype: str) -> str:
    return json.dumps([{"verificationResult": {"statement": {
        "predicateType": ptype,
        "subject": [{"digest": {"sha256": digest.split(":", 1)[1]}}],
        "predicate": {"bomFormat": "CycloneDX"}}}}])


def _stubs(tmp_path: Path, *, cosign: str | None = "ok", gh: str | None = "ok",
           cosign_digest: str = DIGEST, gh_digest: str = DIGEST,
           gh_ptype_override: str | None = None, gh_fail_on: str | None = None) -> dict[str, str]:
    """Build a PATH with stub cosign/gh and the system tools the script needs (no real gh)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "python3").symlink_to(sys.executable)
    # A hermetic PATH: only the stubs and the ordinary system utilities the script and the stubs
    # use, each linked in by name. Putting /usr/bin on PATH wholesale let a REAL cosign or gh
    # (GitHub's runners ship gh in /usr/bin) answer the "tool is missing" cases.
    for tool in _SYSTEM_TOOLS:
        found = shutil.which(tool)
        if found and not (bindir / tool).exists():
            (bindir / tool).symlink_to(found)
    log = tmp_path / "calls.log"
    if cosign is not None:
        fail = cosign != "ok"
        _exe(bindir / "cosign",
             f'echo "cosign $*" >> "{log}"\n'
             + ('echo "no matching signatures" >&2; exit 1\n' if fail
                else f"cat <<'EOF'\n{_cosign_json(cosign_digest)}\nEOF\n"))
    if gh is not None:
        fail_branch = ""
        if gh_fail_on:
            fail_branch = (f'case "$*" in *{gh_fail_on}*) echo "no attestations" >&2; exit 1;; esac\n')
        # print the predicate type the caller asked for unless overridden
        override = repr(gh_ptype_override)
        hexd = gh_digest.split(":", 1)[1]
        _exe(bindir / "gh",
             f'echo "gh $*" >> "{log}"\n' + fail_branch
             + f'exec python3 - "$@" <<\'PY\'\n'
               "import json, sys\n"
               "a = sys.argv[1:]\n"
               "pt = a[a.index('--predicate-type') + 1]\n"
               f"pt = {override} or pt\n"
               "print(json.dumps([{'verificationResult': {'statement': {'predicateType': pt,\n"
               f"  'subject': [{{'digest': {{'sha256': '{hexd}'}}}}],\n"
               "  'predicate': {'bomFormat': 'CycloneDX'}}}}]))\n"
               "PY\n")
    env = {"PATH": str(bindir), "HOME": str(tmp_path), "TMPDIR": str(tmp_path)}
    return env


def _run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, test-owned stubs
        [bash, str(SCRIPT), *args], env=env, capture_output=True, text=True,
                          timeout=60)


def _good_args() -> list[str]:
    return ["--image", IMAGE, "--digest", DIGEST]


def test_all_three_verified_passes_and_pins_identity(tmp_path: Path) -> None:
    env = _stubs(tmp_path)
    out = tmp_path / "sbom.json"
    r = _run(env, *_good_args(), "--sbom-out", str(out))
    assert r.returncode == 0, r.stderr
    assert "VERIFIED" in r.stderr
    assert json.loads(out.read_text())["bomFormat"] == "CycloneDX"
    calls = (tmp_path / "calls.log").read_text()
    # cosign is pinned to the GitHub OIDC issuer and this repo's publish workflow on a version tag
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in calls
    assert r"example-org/example-repo/\.github/workflows/publish-docker\.yml@refs/tags/v" in calls
    # gh is pinned to the repo, the signer workflow and both predicate types, on the OCI subject
    assert f"oci://{IMAGE}@{DIGEST}" in calls
    assert "--repo example-org/example-repo" in calls
    assert "--signer-workflow example-org/example-repo/.github/workflows/publish-docker.yml" in calls
    assert "https://slsa.dev/provenance/v1" in calls and "https://cyclonedx.org/bom" in calls


def test_assurance_suffix_maps_to_the_same_repository(tmp_path: Path) -> None:
    env = _stubs(tmp_path)
    r = _run(env, "--image", IMAGE + "-assurance", "--digest", DIGEST)
    assert r.returncode == 0, r.stderr
    assert "--repo example-org/example-repo " in (tmp_path / "calls.log").read_text()


def test_exact_ref_replaces_the_tag_pattern(tmp_path: Path) -> None:
    env = _stubs(tmp_path)
    r = _run(env, *_good_args(), "--ref", "refs/tags/v1.2.3")
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "calls.log").read_text()
    assert r"@refs/tags/v1\.2\.3$" in calls
    assert "refs/tags/v[A-Za-z0-9" not in calls


def test_cosign_rejection_fails(tmp_path: Path) -> None:
    r = _run(_stubs(tmp_path, cosign="fail"), *_good_args())
    assert r.returncode == 1
    assert "VERIFIED" not in r.stderr
    # provenance was never consulted after the signature failed
    assert "gh attestation" not in (tmp_path / "calls.log").read_text()


def test_cosign_signature_for_another_digest_fails(tmp_path: Path) -> None:
    r = _run(_stubs(tmp_path, cosign_digest=OTHER), *_good_args())
    assert r.returncode == 1
    assert "not for the requested digest" in r.stderr


@pytest.mark.parametrize("which", ["slsa.dev/provenance", "cyclonedx.org/bom"])
def test_missing_attestation_fails(tmp_path: Path, which: str) -> None:
    r = _run(_stubs(tmp_path, gh_fail_on=which), *_good_args())
    assert r.returncode == 1
    assert "VERIFIED" not in r.stderr


def test_attestation_for_another_digest_fails(tmp_path: Path) -> None:
    r = _run(_stubs(tmp_path, gh_digest=OTHER), *_good_args())
    assert r.returncode == 1
    assert "VERIFIED" not in r.stderr


def test_attestation_with_another_predicate_type_fails(tmp_path: Path) -> None:
    r = _run(_stubs(tmp_path, gh_ptype_override="https://example.invalid/other"), *_good_args())
    assert r.returncode == 1


@pytest.mark.parametrize("missing", ["cosign", "gh"])
def test_missing_tool_is_unchecked_not_a_pass(tmp_path: Path, missing: str) -> None:
    env = _stubs(tmp_path, cosign=None if missing == "cosign" else "ok",
                 gh=None if missing == "gh" else "ok")
    r = _run(env, *_good_args())
    assert r.returncode == 2
    assert "UNCHECKED" in r.stderr


@pytest.mark.parametrize("args", [
    [],
    ["--image", IMAGE],
    ["--image", IMAGE, "--digest", "latest"],
    ["--image", IMAGE, "--digest", "sha256:" + "A" * 64],
    ["--image", IMAGE, "--digest", "sha256:abc"],
    ["--image", IMAGE + ":v1", "--digest", DIGEST],
    ["--image", IMAGE + "@" + DIGEST, "--digest", DIGEST],
    ["--image", "docker.io/x/y", "--digest", DIGEST],
    ["--image", "ghcr.io/Example/Repo", "--digest", DIGEST],
    ["--image", IMAGE, "--digest", DIGEST, "--ref", "main"],
    ["--image", IMAGE, "--digest", DIGEST, "--repo", "no-slash"],
    ["--image", IMAGE, "--digest", DIGEST, "--bogus"],
])
def test_bad_arguments_are_unchecked_and_run_nothing(tmp_path: Path, args: list[str]) -> None:
    r = _run(_stubs(tmp_path), *args)
    assert r.returncode == 2, r.stderr
    assert not (tmp_path / "calls.log").exists()


# ── the workflow's shape ────────────────────────────────────────────────────────────────────

def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _on(wf: dict) -> dict:
    return wf.get("on") or wf[True]  # PyYAML parses a bare `on` key as boolean True


def test_publish_only_on_version_tag_or_dispatch() -> None:
    on = _on(_workflow())
    assert set(on) == {"push", "workflow_dispatch"}
    assert on["push"] == {"tags": ["v*"]}  # no branches key: a branch push never publishes


def test_old_unsigned_release_workflow_is_gone() -> None:
    assert not (ROOT / ".github" / "workflows" / "release.yml").exists()
    pushing = [p.name for p in (ROOT / ".github" / "workflows").glob("*.yml")
               if "push: true" in p.read_text()]
    assert pushing == ["publish-docker.yml"]


def test_least_privilege_permissions() -> None:
    wf = _workflow()
    assert wf["permissions"] == {"contents": "read"}
    assert wf["jobs"]["guard"]["permissions"] == {"contents": "read"}
    perms = wf["jobs"]["publish"]["permissions"]
    assert perms == {"contents": "read", "packages": "write", "id-token": "write",
                     "attestations": "write"}


def test_both_images_built_and_every_artifact_is_bound_to_the_digest() -> None:
    wf = _workflow()
    job = wf["jobs"]["publish"]
    assert wf["jobs"]["publish"]["needs"] == "guard"
    files = {m["dockerfile"] for m in job["strategy"]["matrix"]["include"]}
    assert files == {"Dockerfile", "deploy/assurance/Dockerfile"}
    steps = job["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert any(u.startswith("actions/attest-build-provenance@") for u in uses)
    assert any(u.startswith("actions/attest-sbom@") for u in uses)
    assert any(u.startswith("sigstore/cosign-installer@") for u in uses)
    for s in steps:
        u = s.get("uses", "")
        if u.startswith(("actions/attest-build-provenance@", "actions/attest-sbom@")):
            w = s["with"]
            assert "subject-digest" in w and "subject-name" in w
            assert w["push-to-registry"] is True
            assert "@" not in str(w["subject-name"]) and ":" not in str(w["subject-name"]).split("/")[-1]
    sign = next(s for s in steps if "cosign sign" in s.get("run", ""))
    assert '"${IMAGE}@${DIGEST}"' in sign["run"]  # the digest, not a tag
    assert any("verify-release.sh" in s.get("run", "") for s in steps)  # self-check


def test_no_moving_latest_tag_and_no_cache_and_no_secrets() -> None:
    text = WORKFLOW.read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "latest" not in code.replace("ubuntu-latest", "")
    secrets_used = {ln.strip() for ln in text.splitlines() if "secrets." in ln}
    assert all("secrets.GITHUB_TOKEN" in ln for ln in secrets_used), secrets_used
    assert "cache-to" not in text and "cache-from" not in text


def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    # Pinned by full commit SHA (the release tag is in a trailing comment; tests/test_ops_release_pypi.py
    # checks that comment). A tag or a branch can be moved by the action's owner; a SHA cannot.
    import re

    for job in _workflow()["jobs"].values():
        for step in job["steps"]:
            u = step.get("uses")
            if u:
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u), u


def test_verify_script_is_executable_and_fail_closed() -> None:
    assert os.access(SCRIPT, os.X_OK)
    text = SCRIPT.read_text()
    assert "set -uo pipefail" in text
    assert "--certificate-identity-regexp" in text and "--certificate-oidc-issuer" in text
    assert "|| true" not in text
