"""Patch 002 — remove fabricated compliance output.

Three assertions in this service were manufactured rather than measured:

  1. /api/v1/compliance/* returned hardcoded literals, including the sentence
     "All known vulnerabilities have been assessed and mitigated" from a
     function that has never seen a vulnerability, and a 100% readiness score
     computed from its own dict of the word "compliant".
  2. sbom.py stamped each component with sha256(name + version) — the hash of a
     concatenated string, not of any artifact — in a CycloneDX document, where
     that field means integrity.
  3. /api/v1/logs/export returned "integrity": "hash_chain_verified" as a
     string literal while verify_integrity() was never called.

A company selling assurance cannot ship any of them. Each is replaced with
something true, not merely removed.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
if not (ROOT / "src" / "neuralbridge").is_dir():
    ROOT = pathlib.Path.cwd()
assert (ROOT / "src" / "neuralbridge").is_dir(), f"run this from the repo root; {ROOT} is not it"

changed = []

# ---------------------------------------------------------------- 1. compliance
COMPLIANCE = '''"""NeuralBridge compliance routes — withdrawn.

Every endpoint that previously lived here returned a hardcoded literal. The
readiness score was computed from its own dict of the word "compliant"; the CRA
report asserted "All known vulnerabilities have been assessed and mitigated"
without consulting any vulnerability; the SBOM endpoint returned eight invented
package names and never called the generator.

They are withdrawn rather than deleted so that anything still calling them
receives an explicit answer instead of a 404 it might read as a routing fault.

The real thing is ``assurance.security.art14`` — a register that records what
actually happened, keeps it in a hash-chained ledger, and refuses to export a
chain that does not verify.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/compliance")

_WITHDRAWN = {
    "error": "withdrawn",
    "reason": (
        "This endpoint returned hardcoded values rather than measurements. It has been "
        "withdrawn rather than left in place, because a fabricated compliance assertion is "
        "worse than none."
    ),
    "use_instead": {
        "service": "assurance.security.art14 — CRA Article 14 register",
        "http": "/v1/register and /v1/cases/{case_id}",
        "cli": "assurance art14 register",
        "validate_a_draft_filing": "POST /v1/spec/validate",
    },
    "note": (
        "CRA Article 14 has applied since 11 September 2026 and, by Art. 69(3), covers "
        "products placed on the market before 11 December 2027. The remaining CRA "
        "obligations apply from 11 December 2027."
    ),
}


def _withdrawn(path: str) -> None:
    raise HTTPException(status_code=410, detail={**_WITHDRAWN, "withdrawn_path": path})


@router.get("/status", summary="Withdrawn — see assurance.security.art14")
async def compliance_status() -> dict[str, Any]:
    """Withdrawn: returned a readiness score computed from its own literals."""
    _withdrawn("/compliance/status")
    return {}


@router.get("/cra-report", summary="Withdrawn — see assurance.security.art14")
async def generate_cra_report() -> dict[str, Any]:
    """Withdrawn: asserted that vulnerabilities had been assessed and mitigated."""
    _withdrawn("/compliance/cra-report")
    return {}


@router.get("/sbom", summary="Withdrawn — see assurance.security.art14")
async def generate_sbom() -> dict[str, Any]:
    """Withdrawn: returned invented package names, never calling the generator."""
    _withdrawn("/compliance/sbom")
    return {}


@router.get("/gdpr", summary="Withdrawn — see assurance.security.art14")
async def gdpr_register() -> dict[str, Any]:
    """Withdrawn: listed security measures the service does not implement."""
    _withdrawn("/compliance/gdpr")
    return {}


@router.get("/incidents", summary="Withdrawn — see assurance.security.art14")
async def incidents() -> dict[str, Any]:
    """Withdrawn: returned an empty incident list unconditionally."""
    _withdrawn("/compliance/incidents")
    return {}
'''

p = ROOT / "src/neuralbridge/api/routes/compliance.py"
p.write_text(COMPLIANCE, encoding="utf-8")
changed.append(str(p.relative_to(ROOT)))

# ---------------------------------------------------------------- 2. sbom hashes
p = ROOT / "src/neuralbridge/compliance/sbom.py"
s = p.read_text(encoding="utf-8")
OLD_HASH = '''        purl = f"pkg:pypi/{name}@{version}"
        hashes = {
            "SHA-256": hashlib.sha256(
                f"{name}{version}".encode(),
            ).hexdigest(),
        }

        return SBOMComponent(
            name=name,
            version=version,
            purl=purl,
            supplier="PyPI",
            license_id="UNKNOWN",
            hashes=hashes,
        )'''
NEW_HASH = '''        purl = f"pkg:pypi/{name}@{version}"

        # No hash is emitted. The previous implementation recorded
        # sha256(name + version) -- the hash of a concatenated string, not of
        # any artifact. In CycloneDX the `hashes` field means integrity: a
        # consumer uses it to verify the bytes they received are the bytes the
        # producer described. A value that cannot do that is worse than an
        # absent one, because it looks like it can.
        #
        # To populate this honestly, hash the distribution actually installed
        # (the wheel or sdist on disk, or the digest the index published) and
        # record which of those you used.

        return SBOMComponent(
            name=name,
            version=version,
            purl=purl,
            supplier="PyPI",
            license_id="UNKNOWN",
            hashes={},
        )'''
assert OLD_HASH in s, "sbom.py: fabricated-hash block not found (already patched?)"
s = s.replace(OLD_HASH, NEW_HASH, 1)
# hashlib was imported solely to manufacture that value.
s = s.replace("import hashlib\n", "", 1)
p.write_text(s, encoding="utf-8")
changed.append(str(p.relative_to(ROOT)))

# ---------------------------------------------------------------- 3. logs integrity
p = ROOT / "src/neuralbridge/api/routes/logs.py"
s = p.read_text(encoding="utf-8")
OLD_LOG = '''    return {
        "format": file_format,
        "file_path": tmp.name,
        "exported_at": datetime.now(tz=UTC).isoformat(),
        "integrity": "hash_chain_verified",
    }'''
NEW_LOG = '''    # Actually verify, rather than asserting that we did. The previous
    # implementation returned the string "hash_chain_verified" while
    # verify_integrity() was never called from anywhere in the codebase --
    # a verification badge over an unverified export.
    chain_ok = await audit.verify_integrity()

    return {
        "format": file_format,
        "file_path": tmp.name,
        "exported_at": datetime.now(tz=UTC).isoformat(),
        "integrity": {
            "hash_chain_verified": chain_ok,
            "method": "recomputed over the full chain at export time",
            "limitation": (
                "A self-recomputable chain detects accident and casual tampering. It does "
                "not defeat an actor with write access to the store; that needs a signature "
                "over the head, or an external anchor, held outside this service."
            ),
        },
    }'''
assert OLD_LOG in s, "logs.py: integrity literal not found (already patched?)"
s = s.replace(OLD_LOG, NEW_LOG, 1)
p.write_text(s, encoding="utf-8")
changed.append(str(p.relative_to(ROOT)))

# ---------------------------------------------------------------- 4. tests
p = ROOT / "tests/test_api.py"
s = p.read_text(encoding="utf-8")
OLD_TESTS = '''        assert response.status_code == 200
        data = response.json()
        assert "overall_status" in data
        assert "cra_deadline" in data
        assert data["cra_deadline"] == "2026-09-11"

    def test_cra_report(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/cra-report")
        assert response.status_code == 200
        data = response.json()
        assert data["report_type"] == "CRA Vulnerability Report"

    def test_sbom_generation(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/sbom")
        assert response.status_code == 200
        data = response.json()
        assert data["bomFormat"] == "CycloneDX"

    def test_gdpr_register(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/gdpr")
        assert response.status_code == 200
        data = response.json()
        assert "gdpr_article_30_register" in data'''
NEW_TESTS = '''        # Withdrawn in patch 002. These endpoints returned hardcoded literals:
        # a readiness score computed from its own dict of the word "compliant",
        # and a CRA report asserting vulnerabilities had been assessed and
        # mitigated without consulting any. They now answer 410 and name the
        # register that does the real work.
        assert response.status_code == 410
        detail = response.json()["detail"]
        assert detail["error"] == "withdrawn"
        assert "art14" in detail["use_instead"]["service"]

    def test_cra_report(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/cra-report")
        assert response.status_code == 410

    def test_sbom_generation(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/sbom")
        assert response.status_code == 410

    def test_gdpr_register(self, api_client: TestClient):
        response = api_client.get("/api/v1/compliance/gdpr")
        assert response.status_code == 410'''
assert OLD_TESTS in s, "test_api.py: compliance assertions not found (already patched?)"
s = s.replace(OLD_TESTS, NEW_TESTS, 1)
p.write_text(s, encoding="utf-8")
changed.append(str(p.relative_to(ROOT)))


# ------------------------------------------------- 5. a front door for the API
# Separate from the three corrections above and independently revertible: the
# bare URL returned a 404, which is the first thing a prospect sees.
p = ROOT / "src/assurance/api/routes.py"
s = p.read_text(encoding="utf-8")
ANCHOR = '@public_router.get("/healthz"'
ROOT_ROUTE = '''@public_router.get("/", response_model=dict, summary="What this service is")
def root() -> dict[str, Any]:
    """The front door.

    Someone who reaches the bare URL should learn what this is, and what they
    can try without an account, in one response.
    """
    return {
        "service": "Industrial Assurance \u2014 CRA Article 14 register",
        "regulation": "Regulation (EU) 2024/2847, Article 14",
        "applicable_since": "2026-09-11",
        "scope_note": (
            "By Art. 69(3) this applies to every in-scope product placed on the market "
            "before 11 December 2027. There is no grandfathering for reporting, and the "
            "duty outlives a product's support period."
        ),
        "deadlines": {
            "early_warning": "24 h from becoming aware",
            "notification": "72 h from becoming aware",
            "final_report_vulnerability": (
                "14 days from a corrective OR MITIGATING measure becoming available "
                "(Art. 14(2)(c))"
            ),
            "final_report_incident": (
                "1 calendar month from submission of the 72 h notification (Art. 14(4)(c))"
            ),
        },
        "start_here": {
            "interactive_docs": "/docs",
            "openapi_schema": "/openapi.json",
            "health": "/healthz",
            "try_without_an_account": {
                "method": "POST",
                "path": "/v1/spec/validate",
                "what_it_does": (
                    "Checks a draft filing against the 39-field ENISA platform "
                    "specification and reports what is missing, what exceeds a character "
                    "limit, and which listed territories are not EU Member States. "
                    "Records nothing."
                ),
            },
        },
        "field_spec": {"source": "ENISA CRA SRP Glossary", "version": GLOSSARY_VERSION,
                       "dated": GLOSSARY_DATE},
        "not_legal_advice": True,
    }


'''
if "def root()" not in s:
    assert ANCHOR in s, "routes.py: healthz anchor not found"
    s = s.replace(ANCHOR, ROOT_ROUTE + ANCHOR, 1)
    p.write_text(s, encoding="utf-8")
    changed.append(str(p.relative_to(ROOT)))

print("patch 002 applied to:")
for c in changed:
    print("  " + c)
