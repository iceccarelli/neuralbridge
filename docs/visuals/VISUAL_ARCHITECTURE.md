# NeuralBridge Visual Architecture

Production visual assets for neuralbridge.io and the repository README.
All diagrams follow the Supabase/Fly.io/Cursor engineering standard: dark carbon navy, cyan cryptographic links, precise monospace labels.
NeuralBridge produces continuous cryptographically verifiable evidence for EU CRA Article 14 and EU Machinery Regulation 2023/1230 Annex III §1.1.9. It is evidence tooling, not legal certification.

## Index

### 01. hero-cryptographic-machine-assurance

![Isometric industrial robot cell tethered by cyan hash links to a telemetry ledger showing verified ISO/TS 15066 envelope and counter-signed head.](../../public/images/visuals/hero-cryptographic-machine-assurance.png)

**Route:** `/` — Hero + README.md Banner
**Alt:** Isometric industrial robot cell tethered by cyan hash links to a telemetry ledger showing verified ISO/TS 15066 envelope and counter-signed head.
**Caption:** Cryptographic machine assurance: hash-chained proof that the floor machine matches the verified safety state.

```tsx
<picture>
  <source srcSet="/images/visuals/hero-cryptographic-machine-assurance.webp" type="image/webp" />
  <img src="/images/visuals/hero-cryptographic-machine-assurance.png" alt="Isometric industrial robot cell tethered by cyan hash links to a telemetry ledger showing verified ISO/TS 15066 envelope and counter-signed head." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge links an industrial collaborative robot cell to a hash-chained ledger proving continuous match to the verified safety state under EU Machinery Regulation 2023/1230 Annex III and ISO/TS 15066. The diagram shows counter-signed head attestation with EXIT 0, providing cryptographic evidence rather than a static declaration.

### 02. silent-drift-broken-declaration-of-conformity

![Timeline showing static paper Declaration of Conformity frozen at Day 0 while physical reality drifts into an unverified safety gap.](../../public/images/visuals/silent-drift-broken-declaration-of-conformity.png)

**Route:** `/` — Why this exists
**Alt:** Timeline showing static paper Declaration of Conformity frozen at Day 0 while physical reality drifts into an unverified safety gap.
**Caption:** Silent drift: a Declaration of Conformity detaches from shop-floor reality after each unverified intervention.

```tsx
<picture>
  <source srcSet="/images/visuals/silent-drift-broken-declaration-of-conformity.webp" type="image/webp" />
  <img src="/images/visuals/silent-drift-broken-declaration-of-conformity.png" alt="Timeline showing static paper Declaration of Conformity frozen at Day 0 while physical reality drifts into an unverified safety gap." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge visualizes how a static EU Machinery Regulation Declaration of Conformity becomes stale as PLC hotfixes, parameter edits, and firmware swaps occur without re-verification. The evidence gap illustrates the need for continuous hash-chained monitoring.

### 03. end-to-end-assurance-operator-pipeline

![Seven-stage operator pipeline from enrolment through named human decision to counter-signed machine passport.](../../public/images/visuals/end-to-end-assurance-operator-pipeline.png)

**Route:** `/docs/getting-started` — The operator pipeline
**Alt:** Seven-stage operator pipeline from enrolment through named human decision to counter-signed machine passport.
**Caption:** End-to-end assurance pipeline: deterministic stages turning raw exports into an externally verifiable Machine Passport.

```tsx
<picture>
  <source srcSet="/images/visuals/end-to-end-assurance-operator-pipeline.webp" type="image/webp" />
  <img src="/images/visuals/end-to-end-assurance-operator-pipeline.png" alt="Seven-stage operator pipeline from enrolment through named human decision to counter-signed machine passport." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge's operator pipeline sequences kit enrolment, baseline sealing, scheduled drift checks, ChangeAssuranceCase opening, safety re-verification, named human decision, and counter-signed passport under CRA Article 14 and Machinery Regulation requirements.

### 04. hash-chain-edits-vs-countersigned-head-truncation

![Side-by-side comparison: hash chain catches mid-file edits but misses tail truncation; only off-host counter-signed head detects ledger rewind.](../../public/images/visuals/hash-chain-edits-vs-countersigned-head-truncation.png)

**Route:** `/docs/assurance/attest` — Attest Engine Spotlight
**Alt:** Side-by-side comparison: hash chain catches mid-file edits but misses tail truncation; only off-host counter-signed head detects ledger rewind.
**Caption:** Hash chain versus counter-signed head: mid-ledger edits are caught, silent truncation requires off-host attestation.

```tsx
<picture>
  <source srcSet="/images/visuals/hash-chain-edits-vs-countersigned-head-truncation.webp" type="image/webp" />
  <img src="/images/visuals/hash-chain-edits-vs-countersigned-head-truncation.png" alt="Side-by-side comparison: hash chain catches mid-file edits but misses tail truncation; only off-host counter-signed head detects ledger rewind." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge demonstrates that a hash chain alone detects internal edits but not tail truncation of the ledger. Only an off-host counter-signed head (assurance attest sign, refusing co-location with register.db) triggers EXIT 1 on shortening.

### 05. eu-cra-article-14-dual-deadline-clocks

![Dual chronometers for CRA Article 14 24-hour early warning and 72-hour notification clocks anchored at T=0 awareness.](../../public/images/visuals/eu-cra-article-14-dual-deadline-clocks.png)

**Route:** `/solutions/compliance-officer` — CRA Article 14 Register
**Alt:** Dual chronometers for CRA Article 14 24-hour early warning and 72-hour notification clocks anchored at T=0 awareness.
**Caption:** EU CRA Article 14 dual deadline clocks: 24h early warning and 72h notification, linked to un-metered hash-chained register.

```tsx
<picture>
  <source srcSet="/images/visuals/eu-cra-article-14-dual-deadline-clocks.webp" type="image/webp" />
  <img src="/images/visuals/eu-cra-article-14-dual-deadline-clocks.png" alt="Dual chronometers for CRA Article 14 24-hour early warning and 72-hour notification clocks anchored at T=0 awareness." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge surfaces the CRA Article 14(4) 24-hour early-warning and 72-hour notification clocks starting at awareness of an actively exploited vulnerability or severe incident, connected to the GET /v1/register hash-chained case log with zero per-incident metering.

### 06. machinery-regulation-annex-iii-staleness-join

![Ledger join of safety software intervention log against recorded verifications showing CURRENT versus STALE status.](../../public/images/visuals/machinery-regulation-annex-iii-staleness-join.png)

**Route:** `/docs/assurance/machinery` — Annex III staleness join
**Alt:** Ledger join of safety software intervention log against recorded verifications showing CURRENT versus STALE status.
**Caption:** Machinery Regulation Annex III §1.1.9 staleness join: verification after last change is CURRENT; earlier is STALE.

```tsx
<picture>
  <source srcSet="/images/visuals/machinery-regulation-annex-iii-staleness-join.webp" type="image/webp" />
  <img src="/images/visuals/machinery-regulation-annex-iii-staleness-join.png" alt="Ledger join of safety software intervention log against recorded verifications showing CURRENT versus STALE status." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge joins the safety software and intervention log with recorded safety function verifications under EU Machinery Regulation 2023/1230 Annex III §1.1.9, marking functions verified after the last change as CURRENT and earlier ones as STALE.

### 07. legacy-tools-vs-hash-chained-ledger-matrix

![Four-column matrix contrasting spreadsheets, PLM, OT scanners, and NeuralBridge hash-chained ledger.](../../public/images/visuals/legacy-tools-vs-hash-chained-ledger-matrix.png)

**Route:** `/` — Tooling Comparison
**Alt:** Four-column matrix contrasting spreadsheets, PLM, OT scanners, and NeuralBridge hash-chained ledger.
**Caption:** Legacy tools versus NeuralBridge ledger: only the ledger provides air-gapped SHA-256 provenance, Annex III joins, and counter-signed heads.

```tsx
<picture>
  <source srcSet="/images/visuals/legacy-tools-vs-hash-chained-ledger-matrix.webp" type="image/webp" />
  <img src="/images/visuals/legacy-tools-vs-hash-chained-ledger-matrix.png" alt="Four-column matrix contrasting spreadsheets, PLM, OT scanners, and NeuralBridge hash-chained ledger." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge's capability matrix shows spreadsheets, PLM/ALM, and OT asset scanners fail to capture shop-floor hotfixes, air-gapped cells, or ISO/TS 15066 margins, while the hash-chained ledger enforces cryptographic evidence for CRA and Machinery Regulation.

### 08. pricing-entitlement-tiers-validator-register-cell

![Three entitlement tiers—Validator free, Register €390/mo, Cell €1,290/mo—generated from code-enforced plans.](../../public/images/visuals/pricing-entitlement-tiers-validator-register-cell.png)

**Route:** `/pricing` — GET /v1/plans Capability Architecture
**Alt:** Three entitlement tiers—Validator free, Register €390/mo, Cell €1,290/mo—generated from code-enforced plans.
**Caption:** Pricing tiers generated from GET /v1/plans entitlements; €390 and €1,290 are launch hypotheses.

```tsx
<picture>
  <source srcSet="/images/visuals/pricing-entitlement-tiers-validator-register-cell.webp" type="image/webp" />
  <img src="/images/visuals/pricing-entitlement-tiers-validator-register-cell.png" alt="Three entitlement tiers—Validator free, Register €390/mo, Cell €1,290/mo—generated from code-enforced plans." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge pricing (Validator free, Register, Cell) is generated directly from the entitlement table enforced in code via GET /v1/plans. External verification remains always free; cases are unmetered.

### 09. offline-enrolment-kit-socket-guard-airgap

![Isometric air-gapped plant with process socket guard blocking outbound traffic while writing local evidence.db and report.html.](../../public/images/visuals/offline-enrolment-kit-socket-guard-airgap.png)

**Route:** `/docs/assurance/kit` — Air-Gapped Plant Execution
**Alt:** Isometric air-gapped plant with process socket guard blocking outbound traffic while writing local evidence.db and report.html.
**Caption:** Offline enrolment kit: cryptography-only dependency, process-level socket guard, zero network, evidence sealed locally.

```tsx
<picture>
  <source srcSet="/images/visuals/offline-enrolment-kit-socket-guard-airgap.webp" type="image/webp" />
  <img src="/images/visuals/offline-enrolment-kit-socket-guard-airgap.png" alt="Isometric air-gapped plant with process socket guard blocking outbound traffic while writing local evidence.db and report.html." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge offline enrolment kit (python -m assurance kit check / kit run) imports only cryptography, arms a process socket guard refusing all outbound TCP/UDP and DNS, and seals any attempt into evidence.db for air-gapped CRA and Machinery Regulation evidence collection.

### 10. fleet-advisory-deterministic-hash-fanout

![Authenticated supplier advisory fan-out by exact SHA-256, version, or component name across machine serials; public intel remains inspect-only.](../../public/images/visuals/fleet-advisory-deterministic-hash-fanout.png)

**Route:** `/docs/assurance/fleet` — Multi-Site OEM Fleet Advisory
**Alt:** Authenticated supplier advisory fan-out by exact SHA-256, version, or component name across machine serials; public intel remains inspect-only.
**Caption:** Deterministic hash fan-out: advisories matched by SHA-256 binary hash, exact version, or component—never semver arithmetic.

```tsx
<picture>
  <source srcSet="/images/visuals/fleet-advisory-deterministic-hash-fanout.webp" type="image/webp" />
  <img src="/images/visuals/fleet-advisory-deterministic-hash-fanout.png" alt="Authenticated supplier advisory fan-out by exact SHA-256, version, or component name across machine serials; public intel remains inspect-only." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge fans authenticated supplier advisories across fleet serials strictly by SHA-256 hash, exact version string, or component name via POST /v1/fleet/advisory. Unauthenticated NVD/KEV/EPSS feeds stay inspect-only with no auto stop-use.

### 11. change-assurance-case-human-gate-state-machine

![State machine for ChangeAssuranceCase: triggers open immutable case, require re-verification, then named human decision to close.](../../public/images/visuals/change-assurance-case-human-gate-state-machine.png)

**Route:** `/docs/assurance` — CHANGE.md / Workspace
**Alt:** State machine for ChangeAssuranceCase: triggers open immutable case, require re-verification, then named human decision to close.
**Caption:** ChangeAssuranceCase state machine: software drafts, humans decide; zero auto-close after drift or advisory.

```tsx
<picture>
  <source srcSet="/images/visuals/change-assurance-case-human-gate-state-machine.webp" type="image/webp" />
  <img src="/images/visuals/change-assurance-case-human-gate-state-machine.png" alt="State machine for ChangeAssuranceCase: triggers open immutable case, require re-verification, then named human decision to close." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge opens a ChangeAssuranceCase on drift, authenticated advisory, or intervention, requiring safety re-verification and a named human decision (operator ID, timestamp, signed rationale) before close—never automatic.

### 12. immutable-ledger-anatomy-and-watch-exit-codes

![Hash-chained ledger anatomy above three distinct assurance watch exit codes: 0 quiet, 1 findings, 2 could not see.](../../public/images/visuals/immutable-ledger-anatomy-and-watch-exit-codes.png)

**Route:** `/docs/assurance/watch` — Ledger & Scheduled Watch Contract
**Alt:** Hash-chained ledger anatomy above three distinct assurance watch exit codes: 0 quiet, 1 findings, 2 could not see.
**Caption:** Immutable ledger anatomy and assurance watch contract: EXIT 2 (could not look) never shares a code with EXIT 0 (nothing moved).

```tsx
<picture>
  <source srcSet="/images/visuals/immutable-ledger-anatomy-and-watch-exit-codes.webp" type="image/webp" />
  <img src="/images/visuals/immutable-ledger-anatomy-and-watch-exit-codes.png" alt="Hash-chained ledger anatomy above three distinct assurance watch exit codes: 0 quiet, 1 findings, 2 could not see." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge hash-chained ledger records manifests, interventions, ISO/TS 15066 verifications, cases, and counter-signed heads. assurance watch enforces EXIT 0 quiet, EXIT 1 findings, EXIT 2 could-not-see with checks_skipped, never collapsing 'could not look' into clean.

### 13. iso15066-safety-envelope-and-coverage-states

![Isometric cobot workspace with ISO/TS 15066 envelopes and coverage matrix of six explicit states including UNCHECKED.](../../public/images/visuals/iso15066-safety-envelope-and-coverage-states.png)

**Route:** `/applications` — Cobots & Collaborative Cells
**Alt:** Isometric cobot workspace with ISO/TS 15066 envelopes and coverage matrix of six explicit states including UNCHECKED.
**Caption:** ISO/TS 15066 safety envelopes and per-function coverage states: worst margin reported, UNCHECKED never hidden as green.

```tsx
<picture>
  <source srcSet="/images/visuals/iso15066-safety-envelope-and-coverage-states.webp" type="image/webp" />
  <img src="/images/visuals/iso15066-safety-envelope-and-coverage-states.png" alt="Isometric cobot workspace with ISO/TS 15066 envelopes and coverage matrix of six explicit states including UNCHECKED." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge verifies five physical envelopes including ISO/TS 15066 protective separation with worst-margin reporting via POST /v1/machine/verify, and exposes six coverage states (CURRENT, STALE, FAILING, UNCHECKED, INCOMPLETE, NEVER DONE) without collapsing unmeasured items into pass.

### 14. zero-account-auditor-insurer-verification

![Trust-boundary handoff: manufacturer exports portable bundle; auditor verifies free at neuralbridge.io/verify with no account.](../../public/images/visuals/zero-account-auditor-insurer-verification.png)

**Route:** `/verify` — Check an evidence file
**Alt:** Trust-boundary handoff: manufacturer exports portable bundle; auditor verifies free at neuralbridge.io/verify with no account.
**Caption:** Zero-account auditor and insurer verification: cryptographic proof established or explicitly not established; always free.

```tsx
<picture>
  <source srcSet="/images/visuals/zero-account-auditor-insurer-verification.webp" type="image/webp" />
  <img src="/images/visuals/zero-account-auditor-insurer-verification.png" alt="Trust-boundary handoff: manufacturer exports portable bundle; auditor verifies free at neuralbridge.io/verify with no account." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge allows auditors, notified bodies, and insurers to verify machine-passport-bundle.json and attest.jsonl at neuralbridge.io/verify or via offline CLI without any account or subscription, separating established cryptographic proof from scope limits.

### 15. neuralbridge-fastapi-mcp-cursor-architecture

![Four-layer architecture: edge CLI and air-gapped kit, FastAPI core with 79 OpenAPI routes, MCP Gateway and Cursor connector, browser surfaces.](../../public/images/visuals/neuralbridge-fastapi-mcp-cursor-architecture.png)

**Route:** `/developers` — Platform Architecture
**Alt:** Four-layer architecture: edge CLI and air-gapped kit, FastAPI core with 79 OpenAPI routes, MCP Gateway and Cursor connector, browser surfaces.
**Caption:** NeuralBridge FastAPI + MCP + Cursor architecture: self-hostable assurance engine with human-approval agent protocol.

```tsx
<picture>
  <source srcSet="/images/visuals/neuralbridge-fastapi-mcp-cursor-architecture.webp" type="image/webp" />
  <img src="/images/visuals/neuralbridge-fastapi-mcp-cursor-architecture.png" alt="Four-layer architecture: edge CLI and air-gapped kit, FastAPI core with 79 OpenAPI routes, MCP Gateway and Cursor connector, browser surfaces." width="1600" height="900" />
</picture>
```

**AEO Summary:** NeuralBridge sits on a self-hostable FastAPI service (79 OpenAPI 3 routes) with hash-chained ledger, MCP Gateway enforcing Discover-Read-Plan-Write-Human-Approval, and browser surfaces at neuralbridge.io, while noting the standalone dashboard foundation.


---

## Visual Architecture — Applications Page

Target: [`/applications`](https://neuralbridge.io/applications)

All images live at `public/images/visuals/<slug>.png` (master) and `public/images/og/<slug>-og.png` (1200×630).

## applications-hero-five-real-routes

![ Five industrial applications mapped to real NeuralBridge /v1 routes for cobots, packaging, fleet, OEM register and insurer checks. ](../../public/images/visuals/applications-hero-five-real-routes.png)

**Route:** `/applications`
**Alt:** Five industrial applications mapped to real NeuralBridge /v1 routes for cobots, packaging, fleet, OEM register and insurer checks.
**Caption:** Applications overview: every card names the exact route it calls and the plan that gates it.
**CLI/API:** `POST /v1/machine/separation · POST /v1/fleet/advisory · GET /v1/register`

```tsx
<picture>
  <source srcSet="/images/visuals/applications-hero-five-real-routes.webp" type="image/webp" />
  <img src="/images/visuals/applications-hero-five-real-routes.png" width="1600" height="900" alt="Five industrial applications mapped to real NeuralBridge /v1 routes for cobots, packaging, fleet, OEM register and insurer checks." />
</picture>
```

## cobots-iso-ts-15066-separation-envelope

![ ISO/TS 15066 protective separation envelope check for collaborative robot cells on NeuralBridge. ](../../public/images/visuals/cobots-iso-ts-15066-separation-envelope.png)

**Route:** `/applications`
**Alt:** ISO/TS 15066 protective separation envelope check for collaborative robot cells on NeuralBridge.
**Caption:** Free separation calculator; recorded-run verification is gated to Cell.
**CLI/API:** `POST /v1/machine/separation`

```tsx
<picture>
  <source srcSet="/images/visuals/cobots-iso-ts-15066-separation-envelope.webp" type="image/webp" />
  <img src="/images/visuals/cobots-iso-ts-15066-separation-envelope.png" width="1600" height="900" alt="ISO/TS 15066 protective separation envelope check for collaborative robot cells on NeuralBridge." />
</picture>
```

## cobots-free-calc-vs-gated-verify

![ Free ISO/TS 15066 calculator versus Cell-gated machine verification run on NeuralBridge. ](../../public/images/visuals/cobots-free-calc-vs-gated-verify.png)

**Route:** `/applications`
**Alt:** Free ISO/TS 15066 calculator versus Cell-gated machine verification run on NeuralBridge.
**Caption:** Calculator is free; verifying a recorded run requires the Cell plan.
**CLI/API:** `POST /v1/machine/verify`

```tsx
<picture>
  <source srcSet="/images/visuals/cobots-free-calc-vs-gated-verify.webp" type="image/webp" />
  <img src="/images/visuals/cobots-free-calc-vs-gated-verify.png" width="1600" height="900" alt="Free ISO/TS 15066 calculator versus Cell-gated machine verification run on NeuralBridge." />
</picture>
```

## packaging-staleness-join-signoff-vs-change

![ Staleness join showing a prior sign-off dated against a later change on a packaging line. ](../../public/images/visuals/packaging-staleness-join-signoff-vs-change.png)

**Route:** `/applications`
**Alt:** Staleness join showing a prior sign-off dated against a later change on a packaging line.
**Caption:** What safety software is on the line and who touched it, dated against the change.
**CLI/API:** `POST /v1/machinery/coverage`

```tsx
<picture>
  <source srcSet="/images/visuals/packaging-staleness-join-signoff-vs-change.webp" type="image/webp" />
  <img src="/images/visuals/packaging-staleness-join-signoff-vs-change.png" width="1600" height="900" alt="Staleness join showing a prior sign-off dated against a later change on a packaging line." />
</picture>
```

## packaging-safety-software-manifest-coverage

![ Safety software manifest and coverage status for a packaging and palletising line. ](../../public/images/visuals/packaging-safety-software-manifest-coverage.png)

**Route:** `/applications`
**Alt:** Safety software manifest and coverage status for a packaging and palletising line.
**Caption:** Manifest lists safety-relevant software items; coverage states per function.
**CLI/API:** `POST /v1/machinery/manifest`

```tsx
<picture>
  <source srcSet="/images/visuals/packaging-safety-software-manifest-coverage.webp" type="image/webp" />
  <img src="/images/visuals/packaging-safety-software-manifest-coverage.png" width="1600" height="900" alt="Safety software manifest and coverage status for a packaging and palletising line." />
</picture>
```

## fleet-advisory-hash-matched-fanout

![ Supplier advisory fanned out across enrolled machine serials matched by exact hash. ](../../public/images/visuals/fleet-advisory-hash-matched-fanout.png)

**Route:** `/applications`
**Alt:** Supplier advisory fanned out across enrolled machine serials matched by exact hash.
**Caption:** One advisory matched by SHA-256, never by version-range arithmetic.
**CLI/API:** `POST /v1/fleet/advisory`

```tsx
<picture>
  <source srcSet="/images/visuals/fleet-advisory-hash-matched-fanout.webp" type="image/webp" />
  <img src="/images/visuals/fleet-advisory-hash-matched-fanout.png" width="1600" height="900" alt="Supplier advisory fanned out across enrolled machine serials matched by exact hash." />
</picture>
```

## fleet-exact-hash-never-version-range

![ Exact SHA-256 hash matching shown as the only accepted method; version-range arithmetic is rejected. ](../../public/images/visuals/fleet-exact-hash-never-version-range.png)

**Route:** `/applications`
**Alt:** Exact SHA-256 hash matching shown as the only accepted method; version-range arithmetic is rejected.
**Caption:** Deterministic by hash; version ranges are never flattened into a boolean.
**CLI/API:** `POST /v1/fleet/advisory`

```tsx
<picture>
  <source srcSet="/images/visuals/fleet-exact-hash-never-version-range.webp" type="image/webp" />
  <img src="/images/visuals/fleet-exact-hash-never-version-range.png" width="1600" height="900" alt="Exact SHA-256 hash matching shown as the only accepted method; version-range arithmetic is rejected." />
</picture>
```

## oem-article14-register-deadline-clocks

![ OEM Article 14 register showing both 24-hour and 72-hour deadline clocks over a hash-chained ledger. ](../../public/images/visuals/oem-article14-register-deadline-clocks.png)

**Route:** `/applications`
**Alt:** OEM Article 14 register showing both 24-hour and 72-hour deadline clocks over a hash-chained ledger.
**Caption:** Both clocks computed correctly; hash-chained ledger with verifiable export.
**CLI/API:** `GET /v1/register`

```tsx
<picture>
  <source srcSet="/images/visuals/oem-article14-register-deadline-clocks.webp" type="image/webp" />
  <img src="/images/visuals/oem-article14-register-deadline-clocks.png" width="1600" height="900" alt="OEM Article 14 register showing both 24-hour and 72-hour deadline clocks over a hash-chained ledger." />
</picture>
```

## oem-register-verifiable-export-unmetered

![ Verifiable export of the Article 14 register with cases marked as not metered. ](../../public/images/visuals/oem-register-verifiable-export-unmetered.png)

**Route:** `/applications`
**Alt:** Verifiable export of the Article 14 register with cases marked as not metered.
**Caption:** Cases are not metered — no per-case cap or charge.
**CLI/API:** `GET /v1/cases`

```tsx
<picture>
  <source srcSet="/images/visuals/oem-register-verifiable-export-unmetered.webp" type="image/webp" />
  <img src="/images/visuals/oem-register-verifiable-export-unmetered.png" width="1600" height="900" alt="Verifiable export of the Article 14 register with cases marked as not metered." />
</picture>
```

## insurer-unmetered-evidence-check

![ unmetered evidence verification path for insurers and auditors; no account required. ](../../public/images/visuals/insurer-unmetered-evidence-check.png)

**Route:** `/applications`
**Alt:** unmetered evidence verification path for insurers and auditors; no account required.
**Caption:** The buyer or auditor is never the paying customer.
**CLI/API:** `POST /v1/machine/bundle/check`

```tsx
<picture>
  <source srcSet="/images/visuals/insurer-unmetered-evidence-check.webp" type="image/webp" />
  <img src="/images/visuals/insurer-unmetered-evidence-check.png" width="1600" height="900" alt="unmetered evidence verification path for insurers and auditors; no account required." />
</picture>
```

## insurer-declaration-bundle-attestation-verify

![ Three free verification paths: Declaration check, bundle re-verification and attestation verify. ](../../public/images/visuals/insurer-declaration-bundle-attestation-verify.png)

**Route:** `/applications`
**Alt:** Three free verification paths: Declaration check, bundle re-verification and attestation verify.
**Caption:** What can be established from the file alone, and what cannot.
**CLI/API:** `POST /v1/ledger/attest/verify`

```tsx
<picture>
  <source srcSet="/images/visuals/insurer-declaration-bundle-attestation-verify.webp" type="image/webp" />
  <img src="/images/visuals/insurer-declaration-bundle-attestation-verify.png" width="1600" height="900" alt="Three free verification paths: Declaration check, bundle re-verification and attestation verify." />
</picture>
```

## applications-route-to-plan-gating-matrix

![ Matrix mapping the five applications to their exact /v1 routes and the plan that gates each. ](../../public/images/visuals/applications-route-to-plan-gating-matrix.png)

**Route:** `/applications`
**Alt:** Matrix mapping the five applications to their exact /v1 routes and the plan that gates each.
**Caption:** Every row is gated in code; if it is not gated, it is free.
**CLI/API:** `openapi.json`

```tsx
<picture>
  <source srcSet="/images/visuals/applications-route-to-plan-gating-matrix.webp" type="image/webp" />
  <img src="/images/visuals/applications-route-to-plan-gating-matrix.png" width="1600" height="900" alt="Matrix mapping the five applications to their exact /v1 routes and the plan that gates each." />
</picture>
```

## applications-cli-local-to-optional-hosted

![ Offline-first CLI that can later call a hosted deployment; kit and watch never leave the machine. ](../../public/images/visuals/applications-cli-local-to-optional-hosted.png)

**Route:** `/applications`
**Alt:** Offline-first CLI that can later call a hosted deployment; kit and watch never leave the machine.
**Caption:** Same code the hosted API calls, runnable on your own machine first.
**CLI/API:** `python -m assurance`

```tsx
<picture>
  <source srcSet="/images/visuals/applications-cli-local-to-optional-hosted.webp" type="image/webp" />
  <img src="/images/visuals/applications-cli-local-to-optional-hosted.png" width="1600" height="900" alt="Offline-first CLI that can later call a hosted deployment; kit and watch never leave the machine." />
</picture>
```

## applications-change-assurance-case-lifecycle

![ Change-assurance case lifecycle from drift detection through human decision gate to close, reject or defer. ](../../public/images/visuals/applications-change-assurance-case-lifecycle.png)

**Route:** `/applications`
**Alt:** Change-assurance case lifecycle from drift detection through human decision gate to close, reject or defer.
**Caption:** A named person owns the case; the product never decides.
**CLI/API:** `assurance change assess-drift`

```tsx
<picture>
  <source srcSet="/images/visuals/applications-change-assurance-case-lifecycle.webp" type="image/webp" />
  <img src="/images/visuals/applications-change-assurance-case-lifecycle.png" width="1600" height="900" alt="Change-assurance case lifecycle from drift detection through human decision gate to close, reject or defer." />
</picture>
```

## applications-workspace-investigate-one-place

![ Single workspace view of one enrolled machine showing configuration hash, evidence timeline and intervention history. ](../../public/images/visuals/applications-workspace-investigate-one-place.png)

**Route:** `/applications`
**Alt:** Single workspace view of one enrolled machine showing configuration hash, evidence timeline and intervention history.
**Caption:** Configuration, evidence and intervention history in one place.
**API:** `POST /v1/check/fleet-machine`

```tsx
<picture>
  <source srcSet="/images/visuals/applications-workspace-investigate-one-place.webp" type="image/webp" />
  <img src="/images/visuals/applications-workspace-investigate-one-place.png" width="1600" height="900" alt="Single workspace view of one enrolled machine showing configuration hash, evidence timeline and intervention history." />
</picture>
```


---

## Visual Architecture — Product Lifecycle

Target: [`/product/industrial-autonomous-assurance`](https://neuralbridge.io/product/industrial-autonomous-assurance)

## lifecycle-hero-end-to-end-assurance

![End-to-end Industrial Autonomous Assurance lifecycle from enrolment through hash-chained ledger to passport and signed head.](../../public/images/visuals/lifecycle-hero-end-to-end-assurance.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** End-to-end Industrial Autonomous Assurance lifecycle from enrolment through hash-chained ledger to passport and signed head.
**Caption:** Evidence that notices when the machine changed.
**CLI/API:** `POST /v1/machinery/enrol · assurance machinery passport · assurance attest sign`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-hero-end-to-end-assurance.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-hero-end-to-end-assurance.png" width="1600" height="900" alt="End-to-end Industrial Autonomous Assurance lifecycle from enrolment through hash-chained ledger to passport and signed head." />
</picture>
```

## lifecycle-enrolment-named-person-seals-manifest

![A named person enrols a machine, sealing a baseline configuration manifest and receiving a receipt with the configuration hash.](../../public/images/visuals/lifecycle-enrolment-named-person-seals-manifest.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** A named person enrols a machine, sealing a baseline configuration manifest and receiving a receipt with the configuration hash.
**Caption:** Enrolment seals the baseline; the receipt carries the configuration hash.
**CLI/API:** `POST /v1/machinery/enrol`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-enrolment-named-person-seals-manifest.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-enrolment-named-person-seals-manifest.png" width="1600" height="900" alt="A named person enrols a machine, sealing a baseline configuration manifest and receiving a receipt with the configuration hash." />
</picture>
```

## lifecycle-manifest-anatomy-hashes-sources

![Anatomy of a sealed safety software manifest showing items, functions and hash sources (machine, vendor or declared).](../../public/images/visuals/lifecycle-manifest-anatomy-hashes-sources.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Anatomy of a sealed safety software manifest showing items, functions and hash sources (machine, vendor or declared).
**Caption:** Each item is marked as read from the machine, supplied by the vendor, or declared.
**CLI/API:** `POST /v1/machinery/manifest`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-manifest-anatomy-hashes-sources.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-manifest-anatomy-hashes-sources.png" width="1600" height="900" alt="Anatomy of a sealed safety software manifest showing items, functions and hash sources (machine, vendor or declared)." />
</picture>
```

## lifecycle-hash-chained-ledger-append

![Evidence records appended to a per-account hash-chained ledger that can be verified.](../../public/images/visuals/lifecycle-hash-chained-ledger-append.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Evidence records appended to a per-account hash-chained ledger that can be verified.
**Caption:** The ledger catches mid-chain edits; only an off-host counter-signature protects the head.
**CLI/API:** `GET /v1/ledger/verify`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-hash-chained-ledger-append.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-hash-chained-ledger-append.png" width="1600" height="900" alt="Evidence records appended to a per-account hash-chained ledger that can be verified." />
</picture>
```

## lifecycle-drift-detection-machinery-diff

![Configuration drift detection comparing the sealed baseline manifest against the current machine state.](../../public/images/visuals/lifecycle-drift-detection-machinery-diff.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Configuration drift detection comparing the sealed baseline manifest against the current machine state.
**Caption:** A differing manifest is a change; silent re-enrolment is refused.
**CLI/API:** `assurance machinery diff`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-drift-detection-machinery-diff.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-drift-detection-machinery-diff.png" width="1600" height="900" alt="Configuration drift detection comparing the sealed baseline manifest against the current machine state." />
</picture>
```

## lifecycle-change-assurance-case-opened

![A change-assurance case opened from drift, intervention or supplier advisory, owned by a named person.](../../public/images/visuals/lifecycle-change-assurance-case-opened.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** A change-assurance case opened from drift, intervention or supplier advisory, owned by a named person.
**Caption:** The product records the case; a named person decides to close, reject or defer.
**CLI/API:** `assurance change assess-drift`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-change-assurance-case-opened.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-change-assurance-case-opened.png" width="1600" height="900" alt="A change-assurance case opened from drift, intervention or supplier advisory, owned by a named person." />
</picture>
```

## lifecycle-verification-against-safety-envelope

![Recorded machine run verified against the declared safety envelope with tiered results.](../../public/images/visuals/lifecycle-verification-against-safety-envelope.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Recorded machine run verified against the declared safety envelope with tiered results.
**Caption:** Unchecked is a valid outcome; the product does not invent a pass.
**CLI/API:** `POST /v1/machine/verify`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-verification-against-safety-envelope.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-verification-against-safety-envelope.png" width="1600" height="900" alt="Recorded machine run verified against the declared safety envelope with tiered results." />
</picture>
```

## lifecycle-coverage-states-current-stale-unchecked

![Coverage states per safety function: current, stale, failing, unchecked, incomplete or never done.](../../public/images/visuals/lifecycle-coverage-states-current-stale-unchecked.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Coverage states per safety function: current, stale, failing, unchecked, incomplete or never done.
**Caption:** Coverage answers whether a prior verification still applies after a change.
**CLI/API:** `assurance machinery coverage`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-coverage-states-current-stale-unchecked.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-coverage-states-current-stale-unchecked.png" width="1600" height="900" alt="Coverage states per safety function: current, stale, failing, unchecked, incomplete or never done." />
</picture>
```

## lifecycle-intervention-recording-dates-inapplicable

![Technician intervention recorded with the software items touched, dating when prior verifications become inapplicable.](../../public/images/visuals/lifecycle-intervention-recording-dates-inapplicable.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Technician intervention recorded with the software items touched, dating when prior verifications become inapplicable.
**Caption:** The intervention names what was touched so coverage can be updated.
**CLI/API:** `assurance machinery record-change`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-intervention-recording-dates-inapplicable.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-intervention-recording-dates-inapplicable.png" width="1600" height="900" alt="Technician intervention recorded with the software items touched, dating when prior verifications become inapplicable." />
</picture>
```

## lifecycle-passport-sealed-evidence-position

![Sealed machine passport that captures the current evidence position for external re-check.](../../public/images/visuals/lifecycle-passport-sealed-evidence-position.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Sealed machine passport that captures the current evidence position for external re-check.
**Caption:** A passport is re-checked with assurance machinery check or POST /v1/machinery/passport/check.
**CLI/API:** `assurance machinery passport`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-passport-sealed-evidence-position.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-passport-sealed-evidence-position.png" width="1600" height="900" alt="Sealed machine passport that captures the current evidence position for external re-check." />
</picture>
```

## lifecycle-signed-ledger-head-attestation

![Signed ledger head that attests the current head of the hash-chained evidence ledger.](../../public/images/visuals/lifecycle-signed-ledger-head-attestation.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Signed ledger head that attests the current head of the hash-chained evidence ledger.
**Caption:** The counter-signature protects the head; the chain itself detects mid-ledger edits.
**CLI/API:** `assurance attest sign`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-signed-ledger-head-attestation.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-signed-ledger-head-attestation.png" width="1600" height="900" alt="Signed ledger head that attests the current head of the hash-chained evidence ledger." />
</picture>
```

## lifecycle-external-verification-no-account

![External verification of a passport or evidence file that requires no account and stores nothing.](../../public/images/visuals/lifecycle-external-verification-no-account.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** External verification of a passport or evidence file that requires no account and stores nothing.
**Caption:** What can be established from the file alone is stated plainly; what cannot is also stated.
**CLI/API:** `POST /v1/machinery/passport/check`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-external-verification-no-account.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-external-verification-no-account.png" width="1600" height="900" alt="External verification of a passport or evidence file that requires no account and stores nothing." />
</picture>
```

## lifecycle-artefacts-relationship-diagram

![Relationship diagram of core NeuralBridge artefacts: sealed manifest, receipt, verification bundle, passport, signed ledger head and case export.](../../public/images/visuals/lifecycle-artefacts-relationship-diagram.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Relationship diagram of core NeuralBridge artefacts: sealed manifest, receipt, verification bundle, passport, signed ledger head and case export.
**Caption:** Each artefact is re-checkable by anyone who holds the file.
**CLI/API:** `manifest · receipt · passport · attestation`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-artefacts-relationship-diagram.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-artefacts-relationship-diagram.png" width="1600" height="900" alt="Relationship diagram of core NeuralBridge artefacts: sealed manifest, receipt, verification bundle, passport, signed ledger head and case export." />
</picture>
```

## lifecycle-offline-kit-to-optional-hosted

![Offline enrolment kit that runs locally with a process-level socket guard, with optional later push to a hosted ledger.](../../public/images/visuals/lifecycle-offline-kit-to-optional-hosted.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Offline enrolment kit that runs locally with a process-level socket guard, with optional later push to a hosted ledger.
**Caption:** kit and watch never contact a deployment by design.
**CLI/API:** `python -m assurance kit`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-offline-kit-to-optional-hosted.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-offline-kit-to-optional-hosted.png" width="1600" height="900" alt="Offline enrolment kit that runs locally with a process-level socket guard, with optional later push to a hosted ledger." />
</picture>
```

## lifecycle-full-operator-pipeline

![Full operator pipeline from baseline seal through continuous monitoring, change cases and coverage updates to final attestation.](../../public/images/visuals/lifecycle-full-operator-pipeline.png)

**Route:** `/product/industrial-autonomous-assurance`
**Alt:** Full operator pipeline from baseline seal through continuous monitoring, change cases and coverage updates to final attestation.
**Caption:** Continuous evidence that shows which checks still apply after a change.
**CLI/API:** `assurance watch · assurance change`

```tsx
<picture>
  <source srcSet="/images/visuals/lifecycle-full-operator-pipeline.webp" type="image/webp" />
  <img src="/images/visuals/lifecycle-full-operator-pipeline.png" width="1600" height="900" alt="Full operator pipeline from baseline seal through continuous monitoring, change cases and coverage updates to final attestation." />
</picture>
```


---

## NeuralBridge Role Pages Visual Architecture

Light premium visuals for the six solution / role pages.

### 01. manufacturer-declaration-of-conformity-evidence-gap
![Light premium NeuralBridge role visual: manufacturer declaration of conformity evidence gap](../../public/images/visuals/manufacturer-declaration-of-conformity-evidence-gap.png)

### 02. system-integrator-verifiable-evidence-chain
![Light premium NeuralBridge role visual: system integrator verifiable evidence chain](../../public/images/visuals/system-integrator-verifiable-evidence-chain.png)

### 03. plant-operator-air-gapped-workstation
![Light premium NeuralBridge role visual: plant operator air gapped workstation](../../public/images/visuals/plant-operator-air-gapped-workstation.png)

### 04. compliance-officer-cra-article-14-dual-clocks
![Light premium NeuralBridge role visual: compliance officer cra article 14 dual clocks](../../public/images/visuals/compliance-officer-cra-article-14-dual-clocks.png)

### 05. insurer-auditor-zero-account-verification
![Light premium NeuralBridge role visual: insurer auditor zero account verification](../../public/images/visuals/insurer-auditor-zero-account-verification.png)

### 06. ai-ops-mcp-gateway-human-approval
![Light premium NeuralBridge role visual: ai ops mcp gateway human approval](../../public/images/visuals/ai-ops-mcp-gateway-human-approval.png)

### 07. six-roles-overview
![Light premium NeuralBridge role visual: six roles overview](../../public/images/visuals/six-roles-overview.png)

### 08. change-assurance-case-human-gate
![Light premium NeuralBridge role visual: change assurance case human gate](../../public/images/visuals/change-assurance-case-human-gate.png)

### 09. iso15066-coverage-for-operators-manufacturers
![Light premium NeuralBridge role visual: iso15066 coverage for operators manufacturers](../../public/images/visuals/iso15066-coverage-for-operators-manufacturers.png)

### 10. fleet-advisory-deterministic-fanout
![Light premium NeuralBridge role visual: fleet advisory deterministic fanout](../../public/images/visuals/fleet-advisory-deterministic-fanout.png)

### 11. offline-enrolment-kit-for-plant
![Light premium NeuralBridge role visual: offline enrolment kit for plant](../../public/images/visuals/offline-enrolment-kit-for-plant.png)

### 12. unmetered-verify-for-insurers-auditors
![Light premium NeuralBridge role visual: always free verify for insurers auditors](../../public/images/visuals/unmetered-verify-for-insurers-auditors.png)

### 13. pricing-tiers-aligned-to-roles
![Light premium NeuralBridge role visual: pricing tiers aligned to roles](../../public/images/visuals/pricing-tiers-aligned-to-roles.png)

### 14. hash-chained-ledger-anatomy-all-roles
![Light premium NeuralBridge role visual: hash chained ledger anatomy all roles](../../public/images/visuals/hash-chained-ledger-anatomy-all-roles.png)

### 15. role-to-capability-mapping
![Light premium NeuralBridge role visual: role to capability mapping](../../public/images/visuals/role-to-capability-mapping.png)
