"""Static checks on the two Dockerfiles and their build context. No Docker daemon is needed.

HONEST SCOPE: these read the files. No image was built from them in this repository's sandbox (no
daemon), so none of this shows the images build or run; the CI `docker` and `assurance-image`
jobs are the first builds. What is pinned here are the properties that a reviewer reads off the
file and that are cheap to lose by accident: a non-root user, hash-checked installs, a health
check that probes a route that exists, no secret baked into a layer, and a build context that
cannot sweep a key file or a local database into an image.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "platform": ROOT / "Dockerfile",
    "assurance": ROOT / "deploy" / "assurance" / "Dockerfile",
}


def _instructions(path: Path) -> list[tuple[str, str]]:
    """(INSTRUCTION, rest) with continuation lines joined and comments dropped."""
    out, buf = [], ""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.startswith("#"):
            continue
        buf += (" " if buf else "") + line.rstrip("\\").strip()
        if not line.endswith("\\"):
            head, _, rest = buf.partition(" ")
            out.append((head.upper(), rest))
            buf = ""
    return out


@pytest.fixture(params=sorted(IMAGES))
def image(request: pytest.FixtureRequest) -> tuple[str, list[tuple[str, str]]]:
    return request.param, _instructions(IMAGES[request.param])


def test_final_stage_runs_as_a_non_root_user(image) -> None:
    name, ins = image
    users = [rest for head, rest in ins if head == "USER"]
    assert users, f"{name}: no USER instruction"
    assert users[-1] not in {"root", "0", "0:0"}, f"{name}: final USER is root"
    # and nothing after USER switches back
    last_user = max(i for i, (h, _) in enumerate(ins) if h == "USER")
    assert not [r for h, r in ins[last_user + 1:] if h == "USER"]


def test_base_images_are_pinned_to_a_version_tag(image) -> None:
    name, ins = image
    for head, rest in ins:
        if head == "FROM":
            ref = rest.split()[0]
            if ref in {s.split()[-1] for h, s in ins if h == "FROM" and " AS " in s.upper()}:
                continue  # a later stage built FROM an earlier named stage
            assert ":" in ref and not ref.endswith(":latest"), f"{name}: unpinned base {ref}"
            assert re.search(r":\d", ref), f"{name}: base {ref} carries no version"


def test_python_dependencies_install_from_the_hash_checked_lock(image) -> None:
    name, ins = image
    pips = [rest for head, rest in ins if head == "RUN" and "pip install" in rest]
    assert pips
    locked = [p for p in pips if "-r" in p and ".lock" in p]
    assert locked, f"{name}: no lock-file install"
    for p in locked:
        assert "--require-hashes" in p and "--no-deps" in p, f"{name}: {p}"
    for p in pips:  # any other pip install must not resolve anything (the package itself)
        if p not in locked:
            assert "--no-deps" in p, f"{name}: a pip install that resolves dependencies: {p}"


def test_no_secret_is_baked_into_a_layer(image) -> None:
    name, ins = image
    secretish = re.compile(r"(SECRET|PASSWORD|TOKEN|API_?KEY|PRIVATE|CREDENTIAL)", re.I)
    for head, rest in ins:
        if head in {"ARG", "ENV"}:
            for assignment in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", rest) or rest.split()[:1]:
                assert not secretish.search(assignment), f"{name}: {head} {assignment} looks like a secret"
        if head in {"COPY", "ADD"}:
            assert not re.search(r"\.env|\.pem|\.key|id_rsa|\.db\b", rest), f"{name}: {head} {rest}"
        if head == "RUN":
            assert not re.search(r"(sk|rk|pk)_(live|test)_|whsec_|BEGIN [A-Z ]*PRIVATE", rest), name
    flat = IMAGES[name].read_text()
    assert not re.search(r"(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8}|whsec_[A-Za-z0-9]{8}", flat)


def test_the_image_declares_a_health_check_that_probes_a_route_that_exists(image) -> None:
    name, ins = image
    checks = [rest for head, rest in ins if head == "HEALTHCHECK"]
    assert checks, f"{name}: no HEALTHCHECK"
    text = " ".join(checks)
    path = re.search(r"https?://[^/\s'\"]+(/[^\s'\"]*)", text)
    assert path, text
    probe = path.group(1)
    if name == "platform":
        # The routes are mounted under /api/v1 (neuralbridge.main). A probe of /health returned
        # 404 and would have kept the container unhealthy for ever.
        from fastapi.testclient import TestClient

        from neuralbridge.main import app
        status = TestClient(app).get(probe).status_code
        assert status == 200, f"{probe} answers {status}"
    else:
        from fastapi.testclient import TestClient

        from assurance.api.service import app as assurance_app
        assert TestClient(assurance_app).get(probe).status_code == 200


def test_every_other_health_probe_in_the_repo_points_at_a_real_route() -> None:
    from fastapi.testclient import TestClient

    from neuralbridge.main import app
    client = TestClient(app)
    probes = []
    for rel in ("docker-compose.yml", "deploy/k8s/deployment.yaml"):
        text = (ROOT / rel).read_text()
        probes += [(rel, p) for p in re.findall(r"(?:localhost:8000|path:\s*)(/[A-Za-z0-9/_-]*health[A-Za-z0-9/_-]*)", text)]
    assert probes
    for rel, probe in probes:
        assert client.get(probe).status_code == 200, f"{rel}: {probe}"


def test_build_context_excludes_secrets_and_local_state() -> None:
    ignore = {ln.strip() for ln in (ROOT / ".dockerignore").read_text().splitlines()
              if ln.strip() and not ln.startswith("#")}
    for needed in (".git", ".env", ".env.*", "*.db", "*.pem", "*.key", "**/node_modules", ".claude"):
        assert needed in ignore, f".dockerignore does not exclude {needed}"
    # the Dockerfiles only COPY these; none of them may be excluded
    for kept in ("src", "requirements", "pyproject.toml", "README.md", "examples"):
        assert kept not in ignore


def test_the_service_image_keeps_one_worker_and_says_why() -> None:
    text = IMAGES["assurance"].read_text()
    cmd = [rest for head, rest in _instructions(IMAGES["assurance"]) if head == "CMD"][-1]
    assert '"--workers", "1"' in cmd
    assert "tests/test_multiworker_real.py" in text
