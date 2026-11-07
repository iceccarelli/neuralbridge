# Synthetic SBOM and CSAF advisory

Two invented documents for `assurance ingest` (see `deploy/assurance/INGEST.md`).
Every name, version, hash and advisory here is made up: DemoCo, ControlCo and Open Motion GmbH
are not real parties, and nothing describes real equipment or a real vulnerability.

```bash
assurance ingest sbom-import synthetic-sbom.cdx.json --ledger register.db
assurance ingest csaf-import synthetic-advisory.csaf.json --ledger register.db
```

`tests/test_assurance_ingest_lifecycle.py` runs the whole slice on them.
