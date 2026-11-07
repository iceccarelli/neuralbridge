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
| `requirements/assurance-service.lock` | `requirements/assurance-service.txt` (fastapi, uvicorn[standard], pydantic, httpx, cryptography) | the service in `deploy/assurance/Dockerfile` (`pip install --require-hashes --no-deps`; `tests/test_assurance_dockerfile_deps.py` pins that), `OPS.md` section 1 |
| `requirements/prod.lock` | `requirements/prod.txt` (which includes `base.txt`) | root `Dockerfile` (the NeuralBridge platform image; `publish-docker.yml` builds it) |
| `requirements/test.lock` | `requirements/test.txt` | the Python 3.11 leg of the CI `test` job (`pip install --require-hashes --no-deps`); also for reproducing the test environment locally |

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
results change daily and must be re-run before relying on them). Re-run on 2026-11-07 against the
three committed locks: no known vulnerabilities in any. bandit 1.9.4 over `src/neuralbridge/` and
`src/assurance/` (`-ll`, with `scripts/bandit-baseline.json`, as CI runs it): no new medium or high
finding.
`pip-audit -r requirements/<lock> --require-hashes --disable-pip`

| Lock | 2026-11-02, before | 2026-11-02, after |
|---|---|---|
| `assurance-service.lock` | no known vulnerabilities | no known vulnerabilities |
| `prod.lock` | `python-jose 3.5.0` PYSEC-2026-4298 (CVE-2026-85394 / GHSA-3qf3-8w2g-rqmx); `ecdsa 0.19.2` PYSEC-2026-1325 (CVE-2024-23342 / GHSA-wj6h-64fc-37mp), listed twice | no known vulnerabilities |
| `test.lock` | same three findings | no known vulnerabilities |

What changed: `python-jose[cryptography]` was removed from `requirements/base.txt` and
`pyproject.toml`; `src/neuralbridge/security/auth.py` now uses PyJWT, which was already a declared
dependency (floor raised from `>=2.8.0` to `>=2.15.0`; the locks pin 2.15.1). The floor is 2.15.0
because the OSV database (queried 2026-11-02) lists PyJWT advisories fixed as late as 2.15.0; 2.15.0 and
2.15.1 had no known vulnerabilities in that query, while 2.10.1 had 32. `prod.lock` and
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
used python-jose. The CI `security` job runs the same `pip-audit` command against all three locks and fails on
any finding (no `|| true`; an unfixable advisory may only be allow-listed by its id, with a
reason, in the workflow). It also runs bandit over `src/neuralbridge/` and `src/assurance/`.

## 4. SBOM

**What CI produces.** The `sbom` job in `.github/workflows/ci.yml` runs only on `main`, after the
`test` job: `cyclonedx-py requirements` over `requirements/prod.lock` and
`requirements/assurance-service.lock`, uploaded as the `sbom` artifact (`sbom-platform.json`,
`sbom-assurance-service.json`). It is built from the locks, so it lists exact versions and
SHA-256s, not the `>=` lower bounds. This CI file is not tied to an image digest; the release workflow (section 5) generates a CycloneDX SBOM per image from the same lock and attaches it to the pushed digest as an attestation (not yet run).
On a push to `main` the job also runs GitHub's `actions/attest-build-provenance` over those two
files (keyless, no secret or key). That attests that the workflow run produced those files; it is
not an image signature. The step has not yet run on GitHub: check the first `main` run after
merge.

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
base image's OS packages, the Python interpreter, or
this project's own package. An image-level SBOM would need an image scanner and has not been done.

## 5. The release path: written, statically validated, NOT RUN

`.github/workflows/publish-docker.yml` is the only workflow that pushes an image. **It has never run
on GitHub.** What was done to it here: `actionlint` (1.7.12, with shellcheck on the `run:` blocks)
reports nothing; `tests/test_verify_release.py` pins its shape (triggers, permissions, that both
images are built and that every attestation is bound to the digest, no `latest`, no cache, no secret
but `GITHUB_TOKEN`). Nothing was built, pushed, signed or attested, and no GitHub, GHCR or Sigstore
service was contacted.

What it does when it runs, per image (the platform image from `Dockerfile` as
`ghcr.io/<owner>/<repo>`, the assurance service from `deploy/assurance/Dockerfile` as
`ghcr.io/<owner>/<repo>-assurance`):

| step | what | bound to |
|---|---|---|
| trigger | a pushed `v*` tag or a manual `workflow_dispatch`. **Never** a branch push, a pull request, a merge, or a GitHub "release published" event | |
| guard | the built commit must be an ancestor of `origin/main`, else the workflow fails before anything is built | commit |
| build + push | `docker/build-push-action`, `linux/amd64` only, no cache; tags `X.Y.Z`, `X.Y`, `sha-<40 hex>` (a dispatch from a branch gets the `sha-` tag only); **no `latest`** | pushed digest |
| sign | `cosign sign --yes image@sha256:...`, keyless (Sigstore, the workflow's OIDC identity), recorded in Rekor | digest |
| provenance | `actions/attest-build-provenance` (SLSA provenance v1), `subject-name` + `subject-digest`, `push-to-registry` | digest |
| SBOM | CycloneDX from the lock the image installs, attached with `actions/attest-sbom`, `push-to-registry` | digest |
| self-check | `scripts/verify-release.sh` for that digest; the job fails if it does not pass | digest |

Permissions: workflow default `contents: read`; the `publish` job adds `packages: write`, `id-token:
write`, `attestations: write`; the `guard` job only `contents: read`. The job runs in a GitHub
environment named `release`: **adding required reviewers to it (Settings, Environments) makes every
publish wait for a person; this file cannot set that, and without it nothing waits.** The only
credentials are the run's `GITHUB_TOKEN` and OIDC identity. Actions are pinned to major-version tags,
as in the other workflows, **not** to commit SHAs (a tag can be moved by its owner; pinning SHAs is a
decision for the founder). Changes from before: `release.yml` (an unsigned second push of the root image
and a moving `latest`) is deleted; the `release: published` trigger is removed (a release made from a tag
fired both and built twice); `linux/arm64` is dropped (no QEMU step existed, so that build was never
shown to work); the GHA build cache is not used for releases.

**For an outsider: verify a release against its digest.**

```bash
scripts/verify-release.sh --image ghcr.io/<owner>/<repo> --digest sha256:<64 hex> [--ref refs/tags/vX.Y.Z]
scripts/verify-release.sh --image ghcr.io/<owner>/<repo>-assurance --digest sha256:<64 hex> --sbom-out sbom.cdx.json
```

It needs `cosign` (2.x), `gh` (2.50 or newer, signed in or `GH_TOKEN` set: `gh attestation verify` calls
the GitHub API) and `python3`. It passes only if (1) `cosign verify` finds a signature whose certificate
names this repository's `publish-docker.yml` at the given ref (any `refs/tags/v*` if no `--ref`) issued
by GitHub Actions' OIDC issuer, and every signed payload names the digest asked for; (2) `gh attestation
verify` finds an SLSA provenance attestation for the digest signed by that workflow; (3) the same for the
CycloneDX SBOM attestation. Exit `0` verified; `1` something was checked and did not verify; `2` could
not check (missing tool, malformed argument): **2 is not a pass**. A tag, a digest in the wrong shape, an
image outside `ghcr.io` and a `--ref` that is not a ref are refused before any call.
`tests/test_verify_release.py` runs the script against stub `cosign` and `gh` binaries and shows every
mismatch (rejection, another digest, another predicate type, a missing attestation, a missing tool, bad
arguments) fails closed. **It has not been run against a real signed image, and the shape of `gh
attestation verify --format json` it parses (`verificationResult.statement`) is taken from the gh
documentation, not from output.** Expect to fix the script on first contact with a real release.

A pass means: the registry bytes at that digest were built and signed by that workflow in that
repository from a commit on `main`. It does not mean the code is defect-free, that the dependencies
are benign, that the repository was not itself compromised, or that the SBOM covers OS packages (it is
derived from the lock, not scanned from the image). No SLSA level is claimed.

**Founder steps before the first release** (none has been done): decide whether the GHCR packages are
public (an outsider cannot pull them or fetch the attestations otherwise); add required reviewers to the
`release` environment; push a `v*` tag from a commit on `main`; read the run; run
`scripts/verify-release.sh` from a machine that is not the CI runner and record the digests; tell the
operator to deploy by digest. `publish-pypi.yml` still publishes to PyPI when a GitHub release is
published: it is outside this change, unsigned, and a second publish path to decide about.

## 5a. What is NOT established

- **No image has been signed or attested**; the workflow above is the plan, not a result. The only
  other attestation designed to run is the SBOM-file provenance step of the CI `sbom` job (section 4),
  also unrun until the first `main` push.
- **Neither image build has been run by the author.** `deploy/assurance/Dockerfile` installs
  `requirements/assurance-service.lock` and the root `Dockerfile` installs `prod.lock`, each with
  `pip install --require-hashes --no-deps` (`tests/test_assurance_dockerfile_deps.py` pins the service
  image's command; `tests/test_container_static.py` reads both files: non-root final `USER`, versioned
  bases, hash-checked installs, no secret-shaped `ARG`/`ENV`/`COPY`, a `HEALTHCHECK` that probes a route
  that exists, a `.dockerignore` that excludes keys and databases). The sandbox has a docker client and
  no daemon, so no image was built; the pip invocation was exercised with real pip in Python 3.11 venvs.
  The CI `assurance-image` job builds the service image and smoke-tests it; its first run on GitHub is
  the first time that image is built from the lock. The root image has a CI build job (`docker`) that runs
  `import neuralbridge` only.
- **A container defect found by reading, fixed here, not confirmed by a build:** the root image's
  `HEALTHCHECK`, `docker-compose.yml` and `deploy/k8s/deployment.yaml` probed `/health`,
  `/health/live` and `/health/ready`, which the application does not serve at those paths (it mounts them
  under `/api/v1`; `/health` answered 404 to a test client), so the container would have been unhealthy
  for ever and a Kubernetes pod never ready. They now probe `/api/v1/health*`, which a test client
  answers 200. The assurance service image had no `HEALTHCHECK`; it now has a standard-library probe of
  `/livez` (the command was run against a local server; Docker never executed it).
- **Base images are not pinned by digest** (`python:3.11-slim`, `python:3.12-slim`), nor are apt
  packages (`curl`), nor the GitHub Actions (major-version tags). Digests were not resolved here (that
  needs a registry call and goes stale). The root image has no Node stage any more (the former
  `src/dashboard` build was retired); the site is built by the `site` CI job with `npm ci`.
- **Only one CI test leg runs from the lock**: Python 3.11 installs `requirements/test.lock` with
  `--require-hashes`; 3.12 and 3.13 install `requirements/test.txt` (latest allowed versions) on
  purpose, to see forward drift. The service lock (`assurance-service.lock`, Python 3.12) is not
  used by any test leg; its coverage is the import-closure test and the `assurance-image` job. The
  `Lock drift` job (`scripts/lock.sh --check`) fails the run when a lock no longer matches its
  input; whether it is a *required* status check is a repository setting, not a file.
  `scripts/lock.sh --check` was run on 2026-11-07 and reports all three locks current.
- A hash proves a file is the one that was locked, not that the upstream release is benign.
- The lock is generated from the index at generation time; if PyPI yanks or alters a file later,
  `--require-hashes` will fail the install rather than substitute.

## 6. Procedure for a release record

1. Check out the commit; `git rev-parse HEAD`; `git status --short` is empty.
2. `scripts/lock.sh --check` exits 0; `python -m pytest tests/test_requirements_lock.py` passes.
3. Build the image (or take the digest the release workflow printed, after
   `scripts/verify-release.sh` passed for it); record `docker image inspect --format '{{.Id}}'` and the base image's digest
   (`docker image inspect --format '{{index .RepoDigests 0}}' python:3.12-slim`).
4. Generate the SBOM from the lock (section 4) and store it beside the record.
5. Run `pip-audit -r requirements/<lock> --require-hashes`; record the output and the date.
6. Store SHA, lock SHA-256, image digest, SBOM file hash, audit output together. These are
   records you made; they are not an attestation by anyone else.
