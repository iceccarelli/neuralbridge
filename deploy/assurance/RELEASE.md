# Release identity, SBOM and provenance

What can be said about a release of this repository today, how to produce the artifacts, and
what is **not** established. Facts verified in a sandbox on the date of the change are marked
with the command that produced them; anything not marked was read from files, not run.

## 1. How a release is identified

A release is the triple below. Record all three together; any one alone is not enough.

| Identifier | How to get it | What it pins |
|---|---|---|
| Git commit SHA (full 40 hex) | `git rev-parse HEAD` on the checkout you built from | the source, the `.txt` bounds, the lock files, the Dockerfiles |
| Lock file SHA-256 | `sha256sum requirements/assurance-service.lock` (service) or `requirements/prod.lock` (platform image) | the exact third-party versions **and** the SHA-256 of every wheel/sdist pip may accept |
| Image digest | `docker image inspect --format '{{.Id}}' <image>` after a build, or the registry digest after a push | the bytes actually deployed. Redeploy by digest, not by tag |

The lock hash is redundant with the commit SHA (the lock is a file in the commit) but is what you
quote when two commits share a lock. Record also `python --version` and the base image tag.

## 2. The lock files

`scripts/lock.sh` regenerates them with `uv pip compile --generate-hashes` from the default PyPI
index; `scripts/lock.sh --check` reports drift without writing.

| Lock | Input | Used by |
|---|---|---|
| `requirements/assurance-service.lock` | `requirements/assurance-service.txt` (fastapi, uvicorn[standard], pydantic, httpx, cryptography) | the service in `deploy/assurance/Dockerfile` (not yet wired in, see below), `OPS.md` section 1 |
| `requirements/prod.lock` | `requirements/prod.txt` (which includes `base.txt`) | root `Dockerfile` (the NeuralBridge platform image; the image `publish-docker.yml` and `release.yml` build) |
| `requirements/test.lock` | `requirements/test.txt` | reproducing the test environment locally; CI does not use it yet |

All three are `--universal` (environment markers; valid on linux amd64/arm64, macOS, Windows).
Install form, which makes pip refuse any file whose hash is not listed:

```bash
pip install --require-hashes --no-deps -r requirements/prod.lock
pip install --no-deps -e .
```

Verified in the sandbox with uv 0.11.32 (`uv pip install --require-hashes -r ...`):
`assurance-service.lock` into a fresh Python 3.12 venv, `prod.lock` and `test.lock` into fresh
Python 3.11 venvs. In each, after `pip install --no-deps -e .`, `python -m assurance capabilities
--check` printed "the catalogue matches the code." (exit 0) and `import assurance.api.service`
succeeded; the service import and the check also work from the five-package service lock alone.
From the `test.lock` venv, `tests/test_assurance_capabilities.py tests/test_assurance_enrol.py
tests/test_intel_store.py tests/test_ops_cycle.py` gave 123 passed.

Not verified: that CI's Python 3.13 job passes from `test.lock`; that any lock installs on
Windows/macOS; a `docker build` of any image.

## 3. Dependency advisories in the locked sets

Command (pip-audit 2.10.1, installed in a scratch venv; it queries the PyPI advisory service, so
results change daily and must be re-run before relying on them):
`pip-audit -r requirements/<lock> --require-hashes --disable-pip`

| Lock | 2026-11-02, before | 2026-11-02, after |
|---|---|---|
| `assurance-service.lock` | no known vulnerabilities | no known vulnerabilities |
| `prod.lock` | `python-jose 3.5.0` PYSEC-2026-4298 (CVE-2026-85394 / GHSA-3qf3-8w2g-rqmx); `ecdsa 0.19.2` PYSEC-2026-1325 (CVE-2024-23342 / GHSA-wj6h-64fc-37mp), listed twice | no known vulnerabilities |
| `test.lock` | same three findings | no known vulnerabilities |

What changed: `python-jose[cryptography]` was removed from `requirements/base.txt` and
`pyproject.toml`; `src/neuralbridge/security/auth.py` now uses PyJWT, which was already a declared
dependency (floor raised from `>=2.8.0` to `>=2.10.1`; the locks pin 2.15.1). `prod.lock` and
`test.lock` were regenerated with `scripts/lock.sh`; the only differences are the removal of
`python-jose`, `ecdsa`, `rsa`, `pyasn1` and `six` (nothing else in the locked set required them),
and `scripts/lock.sh --check` reports no drift. pip-audit listed no fixed version of either
advisory, so removal, not a bump, was the only remedy.

Scope and limits. Before the change, `neuralbridge.security.auth` was imported by no module under
`src/` (only by `tests/test_security.py`), and `neuralbridge.main` did not import it; in the
installed environment python-jose used its `cryptography` backend and `ecdsa` was not imported.
Those facts are why the exposure was assessed as not reachable from the shipped application; they
are not a claim about code outside this repository. `auth.py` now also pins the accepted algorithm
to the configured one, rejects a token whose header names another algorithm or `none`, requires
`exp` and `sub`, and `Settings` refuses a non-HMAC `jwt_algorithm` and an HMAC secret that looks
like PEM, SSH or DER key material (`tests/test_security_jwt_hardening.py`). That is hardening of
one module, not an audit of the platform's authentication, and a clean pip-audit means only that
the advisory database lists nothing for the pinned versions today. The assurance service never
used python-jose. The CI `security` job still runs `safety check -r requirements/base.txt || true`,
so it never fails on a finding and does not scan the lock.

## 4. SBOM

**What CI produces.** The `sbom` job in `.github/workflows/ci.yml` runs only on `main`, after the
`test` job: `cyclonedx-py requirements requirements/base.txt -o sbom.json --of JSON`, uploaded as
the `sbom` artifact. It is built from `base.txt`, i.e. from the `>=` lower bounds, so it lists
the requested names and ranges, not the versions an image actually contains, and it omits the
`prod.txt` additions (gunicorn, OTLP exporter, sentry). It is not tied to an image digest.

**Locally, from the lock** (verified with `cyclonedx-bom` 7.6.0, `cyclonedx-py requirements`,
offline from the lock file):

```bash
pip install cyclonedx-bom
cyclonedx-py requirements requirements/assurance-service.lock --of JSON -o sbom-service.json
cyclonedx-py requirements requirements/prod.lock --of JSON -o sbom-platform.json
```

Real output on the date of the change: CycloneDX spec 1.6, JSON; the service lock gives 26
components in ~200 KB, `prod.lock` 86 components in ~520 KB. Each component carries name,
exact version, a `pkg:pypi` purl and the SHA-256 hashes from the lock. It does not describe the
base image's OS packages, the Python interpreter, the Node dashboard stage of the root image or
this project's own package. An image-level SBOM would need an image scanner and has not been done.

## 5. What is NOT established

- **No signed provenance or attestation exists.** No SLSA level is claimed. There is no build
  attestation, no image signature (cosign or similar), and no SBOM attestation. `publish-docker.yml`
  and `release.yml` push images without provenance or signing steps.
- **The lock is not yet what the service image installs.** `deploy/assurance/Dockerfile` still
  installs with `>=`; `tests/test_assurance_dockerfile_deps.py` parses that `pip install` line, so
  switching it to the lock means changing that test in the same commit. The root `Dockerfile`
  now installs `prod.lock` with `--require-hashes`; the pip invocation was exercised in a Python
  3.11 venv, but the image has **not been built** (the sandbox had a docker client and no daemon).
- **Base images are not pinned by digest** (`python:3.11-slim`, `python:3.12-slim`, `node:22-alpine`),
  nor are apt packages (`curl`), nor the GitHub Actions (`@v4` tags). The npm side of the root image
  runs `npm install` in `src/dashboard`, not `npm ci`.
- **CI tests do not run from the lock**: they install `requirements/test.txt`, so a green CI run does
  not prove the locked versions pass. The `Lock drift (advisory)` job checks only that the lock still
  matches its input; it is `continue-on-error` and not a required check.
- A hash proves a file is the one that was locked, not that the upstream release is benign.
- The lock is generated from the index at generation time; if PyPI yanks or alters a file later,
  `--require-hashes` will fail the install rather than substitute.

## 6. Procedure for a release record

1. Check out the commit; `git rev-parse HEAD`; `git status --short` is empty.
2. `scripts/lock.sh --check` exits 0; `python -m pytest tests/test_requirements_lock.py` passes.
3. Build the image; record `docker image inspect --format '{{.Id}}'` and the base image's digest
   (`docker image inspect --format '{{index .RepoDigests 0}}' python:3.12-slim`).
4. Generate the SBOM from the lock (section 4) and store it beside the record.
5. Run `pip-audit -r requirements/<lock> --require-hashes`; record the output and the date.
6. Store SHA, lock SHA-256, image digest, SBOM file hash, audit output together. These are
   records you made; they are not an attestation by anyone else.
