# Pricing

Assurance tiers are computed from the weakest input, never passed in. If it
is not gated in code, it is not on this page — `GET /v1/plans` on a running
instance returns this same table, generated from the entitlements
`src/assurance/billing/plans.py` enforces.

| Capability | Validator | Register | Cell |
|---|:---:|:---:|:---:|
| Free verification (Declaration, manifest, attestation) | ✓ | ✓ | ✓ |
| Article 14 draft validation & calculators | ✓ | ✓ | ✓ |
| Offline enrolment kit | ✓ | ✓ | ✓ |
| Article 14 register (unlimited cases, both clocks) | — | ✓ | ✓ |
| Hash-chained ledger with verifiable export | — | ✓ | ✓ |
| Machine safety verification | — | — | ✓ |
| Annex III manifests & passports | — | — | ✓ |
| Fleet advisory fan-out | — | — | ✓ |
| Counter-signed head attestation | — | — | ✓ |

| | Price |
|---|---|
| **Validator** | Free. No card, no account required. |
| **Register** | €390 / month |
| **Cell** | €1,290 / month |

Verification stays free at every tier, forever — the audience for a piece of
evidence is a regulator, an insurer, or a customer's customer, none of whom
should ever need to hold an API key here.

See the live, purchasable version of this table at
[neuralbridge.io/#pricing](https://neuralbridge.io/#pricing) — clicking Buy
there calls the real `POST /v1/checkout` route once a deployment exists.

There is also a fourth, unlisted tier — **Supplier** — for component
suppliers who want to publish signed advisories to a hosted feed. It has no
self-serve price yet (sales-assigned only); see
[ADR-0001](https://github.com/iceccarelli/neuralbridge/blob/main/deploy/assurance/ADR-0001-supplier-api.md)
for why.
