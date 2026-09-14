# assurance

Evidence infrastructure for products whose software controls physical things.

One question, in several regulatory dialects: **can you prove what this system
is, what it contains, what it was tested against, what it actually did, and why
this version was allowed to ship or operate?**

```
assurance/
├── core/        identity (content addressing), evidence objects, assurance tiers
├── evidence/    the append-only hash-chained ledger every record lands in
├── security/
│   └── art14/   EU CRA Article 14 reporting — live since 2026-09-11
└── api/         the HTTP register (needs the `assurance-api` extra)
```

The core has no runtime dependencies. The HTTP register needs FastAPI and
uvicorn, and that is the only place either is imported.

## Why this exists

Article 14 of Regulation (EU) 2024/2847 has applied since **11 September 2026**,
and Article 69(3) extends it to every in-scope product placed on the market
**before 11 December 2027**. There is no grandfathering for reporting, and the
Commission's guidance confirms the duty outlives a product's support period. A
machine shipped in 2019 is in scope today, with a 24-hour clock and a fine
ceiling of €15,000,000 or 2.5% of worldwide turnover.

Three things make this hard in practice, and each is designed for here:

**The clock starts at a fact nobody records.** Every deadline runs from
"becoming aware", which the Regulation does not define and the Commission's
guidance defines as the moment an initial assessment gives reasonable certainty.
The reporting platform does not yet capture that fact — the vulnerability field
is documented as arriving in a future release, and the incident field records
*detection*, which is a different moment. `Awareness` is the compensating
record, and it is required to carry its reasoning.

**The final-report clocks have different triggers.** A vulnerability final
report is due 14 days after a corrective *or mitigating* measure becomes
available — a documented workaround starts it as surely as a patch. An incident
final report is due one month after the 72-hour notification was *submitted*.
`clock.py` encodes both, including the calendar-month arithmetic.

**The platform's own countdown is wrong.** In the current release the 72-hour
counter displays 48 hours after the early warning, so a filing can appear
overdue while still in time. The register shows both and says which governs.

## Use

```bash
export ASSURANCE_LEDGER=art14-register.db

assurance art14 signal    C1 --at 2026-09-18T21:40:00Z --channel customer_or_integrator \
                             --description "Integrator observed exploitation" --by "m.braun:Head of Engineering"

assurance art14 awareness C1 --at 2026-09-19T06:30:00Z \
                             --started 2026-09-18T22:05:00Z --completed 2026-09-19T06:30:00Z \
                             --track actively_exploited_vulnerability \
                             --because "SIEM export shows a shell spawned from the service port" \
                             --by "m.braun:Head of Engineering"

assurance art14 triage    C1 --answer reliable_evidence_of_malicious_exploitation=yes ... --by "..."
assurance art14 validate  --track actively_exploited_vulnerability --stage early_warning --payload draft.json
assurance art14 file      C1 --stage early_warning --payload draft.json --by "..."
assurance art14 case      C1
assurance art14 register
assurance art14 verify
assurance art14 export    --case C1 -o bundle.json
```

`assurance art14 fields --track ... --stage ...` prints the platform's field
specification, including which fields the platform cannot currently capture.

## The HTTP register

```bash
pip install -e ".[assurance-api]"

export ASSURANCE_LEDGER=art14-register.db
export ASSURANCE_API_KEYS=change-me-before-this-holds-anything-real
assurance-api                      # or: uvicorn assurance.api.service:app
```

Interactive documentation at `/docs`, schema at `/openapi.json`.

| | |
|---|---|
| `POST /v1/cases/{id}/signal` | open a case; no clock starts here |
| `POST /v1/cases/{id}/awareness` | establish the moment every deadline runs from |
| `POST /v1/cases/{id}/triage` | work the reportability decision path |
| `POST /v1/cases/{id}/availability` | product, versions, Member States |
| `POST /v1/cases/{id}/measure` | a corrective **or mitigating** measure became available |
| `POST /v1/cases/{id}/filings` | record a submission, validated against the field spec |
| `POST /v1/cases/{id}/user-notification` | the Article 14(8) notification |
| `GET /v1/cases/{id}` | the case, with deadlines and what is still owed |
| `GET /v1/cases/{id}/export` | a verifiable bundle; refuses if the chain does not verify |
| `GET /v1/register` · `GET /v1/register/breaches` | readiness across every case |
| `GET /v1/spec/fields` · `POST /v1/spec/validate` | the field spec, and a dry-run validator |
| `GET /v1/ledger/verify` | chain verification and the head attestation |
| `GET /healthz` | liveness, and an honest statement of the auth mode |

Every write returns what is now outstanding, because the next question after
recording anything is always "and now what is due".

Refusals carry the provision they rest on:

```
HTTP 409  {"error": "clock_not_started",
           "detail": "the 14-day final-report clock has not started: no corrective
                      or mitigating measure has been recorded as available. A
                      documented workaround counts — record it when it exists
                      (Art. 14(2)(c))."}
```

**Authentication is not optional.** With no keys configured, every register
route returns 503 and `/healthz` reports `degraded`. `ASSURANCE_ALLOW_UNAUTHENTICATED=1`
exists for local evaluation and makes the service say so on `/healthz`.

## Design rules

**Declared gaps.** Every validated object carries `checks_skipped`. "Here is
what I did not verify" is the sentence an auditor wants, and a system that
cannot say it is claiming more than it knows.

**Nothing is decided for you.** Triage returns *undetermined* until a human
answers. "Reliable evidence that a malicious actor has exploited it" is a
judgement; a library that guessed it would be manufacturing a regulatory
position.

**Refuse rather than guess.** An awareness record without reasoning, an
unattributed evidence object, a final filing before its clock has started, and
an export from a ledger that does not verify are all errors, not warnings.

**Tamper-evidence, honestly scoped.** The ledger detects editing, removal and
re-ordering, and every append spans one `BEGIN IMMEDIATE` transaction so
concurrent writers cannot fork the chain. It does **not** defeat an
administrator with write access and time — for that, sign or publish
`head_attestation()` with a key held outside the system.

## Sources

Regulation (EU) 2024/2847 (OJ L, 2024/2847, 20.11.2024), Articles 3, 13, 14, 16,
64, 69, 71 · Commission Communication C(2026) 5252 final, Annex, 27.7.2026,
§§209–221 (non-binding) · Commission FAQs on the CRA, Section 5 · ENISA CRA SRP
Glossary v1.3, 10.9.2026 · ENISA CRA SRP FAQ.

## Known limits

- `sensitive or important data or functions` (Art. 14(5)(a)) is undefined in the
  Regulation and unelaborated in the FAQ and guidance. Borderline severity calls
  have no official interpretive support; the register records the reasoning and
  declares the gap.
- The Commission guidance relied on for the awareness test is expressly
  non-binding.
- No implementing act under Art. 14(10) specifying notification format has been
  identified. The ENISA Glossary is operational guidance and can change without
  legislative process; `GLOSSARY_VERSION` is printed in every report so a stale
  build announces itself.
- This is engineering software, not legal advice.
