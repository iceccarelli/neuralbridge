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
