# Pricing

If it is not gated in code, it is not on this page — `GET /v1/plans` on a running
instance returns this same table, generated from the entitlements
`src/assurance/billing/plans.py` enforces.

| Capability | Validator | Register | Cell |
|---|:---:|:---:|:---:|
| Free verification (Declaration, manifest, attestation) | ✓ | ✓ | ✓ |
| Article 14 draft validation & calculators | ✓ | ✓ | ✓ |
| Offline enrolment kit | ✓ | ✓ | ✓ |
| Article 14 register (both clocks; cases are not metered — no per-case cap or charge) | — | ✓ | ✓ |
| Hash-chained ledger with verifiable export | — | ✓ | ✓ |
| Machine safety verification | — | — | ✓ |
| Annex III manifests & passports | — | — | ✓ |
| Fleet advisory fan-out | — | — | ✓ |
| Change-assurance cases (`/v1/change/*`; closure is a named human decision; a validated verification needs a recorder attestation accepted under a trust list the operator configures, none is configured in a default deployment, so a required re-verification is closed in practice by a named person's waiver) | — | — | ✓ |
| Counter-signed head attestation | — | — | ✓ |

| | Price |
|---|---|
| **Validator** | Free. No card, no account required. |
| **Register** | €390 / month |
| **Cell** | €1,290 / month |

These prices are launch hypotheses; they have not been validated with paying customers.

Re-checking someone else's evidence needs no account and no API key — the
audience for a piece of evidence is a regulator, an insurer, or a customer's
customer, none of whom should need one here. Declaration, evidence-bundle,
passport and attestation checks are not metered. The file verifier
(`POST /v1/evidence/verify`, and `/verify` on this site) allows 20 a day per
address; manifest diff allows 10 a day. Register and Cell have no daily cap on
either. These are anti-abuse allowances, not prices; nothing here promises they
stay so — `GET /v1/plans` is what the software enforces.

This page is the same table as the one at
[neuralbridge.io/#pricing](https://neuralbridge.io/#pricing); purchase only works on a deployment with Stripe prices configured (none today), and until then
`POST /v1/checkout` answers 503 `price_not_configured`.

There is also a fourth, unlisted tier — **Supplier** — for component
suppliers who want to publish signed advisories to a hosted feed. It has no
self-serve price yet (sales-assigned only); see
[ADR-0001](https://github.com/iceccarelli/neuralbridge/blob/main/deploy/assurance/ADR-0001-supplier-api.md)
for why.
