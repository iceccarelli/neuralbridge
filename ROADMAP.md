# NeuralBridge Roadmap — ordered by the path to recurring revenue

Same honesty standard as the rest of this repository: nothing is marked done
unless it is gated in code and covered by `python -m pytest tests/ -q`. Current
state, with the verification that backs it, is `HANDOFF.md` §0.

**Standing facts (until `HANDOFF.md` says otherwise with evidence):** zero
revenue, zero customers, zero pilots, nothing deployed, Stripe has never
processed a payment. The prices are unvalidated. The single most important
unproven assumption is that a machine builder or integrator will pay a
recurring fee to keep safety-evidence applicability current instead of relying
on vendor change-detection plus an engineer's checklist
(`docs/pmf/PILOT-PROGRAMME.md`). Features do not answer that question; a paid
pilot does.

## How work is chosen
Working backwards from a paying customer, an item earns a place only if it does
one of three things, and says which number it moves:

1. **Shortens time to first useful result** for a customer who has paid or will.
2. **Protects revenue already earned** — entitlement matches payment; evidence
   stays trustworthy; the product keeps working while nobody is watching.
3. **Removes a blocker to a paid transaction** (deployability, billing,
   procurement objections).

Everything else waits, however interesting. Operating practice borrowed from
large-scale services, applied to this size of company: every guarantee has a
measured indicator (an SLI such as entitlement drift count, failed-observation
rate); every release passes the same automated gates; independent adversarial
review before anything that touches tenancy, billing or closure logic;
toil that recurs gets automated; changes are small and reversible.

## Shipped
- [x] Industrial Autonomous Assurance: Art. 14 register, hash-chained ledger,
      offline enrolment kit, machine safety verification, Annex III manifests,
      fleet advisory fan-out, signed supplier feeds, counter-signed head
      attestation
- [x] Continuous Machine Change Assurance: `ChangeAssuranceCase`s opened by
      Watch from drift, advisories and interventions; evidence-bound
      re-verification; human-only closure; ledger replay
- [x] Per-account tenancy (assurance ledgers, `/ai` control plane, audit log)
- [x] Billing hardening: identity-bound accounts, idempotent ordered webhooks,
      key lifecycle, enforced plan catalogue with parity test
- [x] `/assurance` customer workspace; offline bundle verifier; volume
      backup/verify tool

## Next — on the money path, in this order
- [x] **Watch reporting** (moves: time to first useful result; renewal risk).
      Opt-in `assurance watch push` + `POST /v1/watch/report` +
      `GET /v1/fleet/observations`: a paying customer sees, per machine, the last
      successful observation, failed or incomplete attempts and staleness in
      their workspace. The kit and `watch run` stay offline (a CI job proves it
      from a bare checkout). **What it is not:** the report is client-declared
      (cadence and `observed_at` come from the customer's own Watch) and the
      workspace says so; it is not independent observation. Not yet covered:
      advisory findings and Art. 14 drafts in the report, an MCP tool.
- [x] **Entitlement reconciliation** (moves: revenue protected).
      `python -m assurance.billing.reconcile` compares Stripe subscription state
      with the account store, reports drift by category (the drift count is the
      SLI), and with `--apply` corrects existing accounts only. **Verified
      against a fake Stripe transport only; it has never run against real
      Stripe. Run it with a test-mode key first.** Never creates accounts or keys.
- [ ] **Staging deployment on test-mode Stripe** (blocker; needs founder
      credentials). Real webhooks, real restore rehearsal, a real
      `scripts/e2e-assurance.sh` against a hosted URL. Checklist:
      `DEPLOY_NOW.md`, `deploy/assurance/README.md`.
- [ ] **Paid-pilot conversion path**: first-run guide that gets a customer from
      kit output to a populated workspace in one sitting; pilot metrics
      captured from the ledger (`docs/pmf/PILOT-PROGRAMME.md` §6).

## Then — only on customer pull
- [ ] Supplier-to-fleet advisory distribution at scale (the two-sided
      network effect). Build the supplier price and directory only after
      integrators are paying.
- [ ] Additional supported collection sources (structured vendor exports),
      each with proven parsing, diff and missing-data behaviour. No claim of
      universal vendor support.
- [ ] CRA lifecycle evidence (SBOM / support period association) where a
      paying customer asks for it. Not another scanner.
- [ ] Auditor/insurer acceptance of the evidence format — test acceptance
      before building feeds or certificates.

## Gated on the founder (not engineering)
Deploying anything; setting production secrets or Stripe live prices; sending
outreach or accepting a pilot; the open-source licence decision (`HANDOFF.md`
§4.4); retiring the stale `neuralbridge.vercel.app` project.

## Explicitly not building now
Adapter marketplace; broad adapter ecosystem; serverless targets; LangChain /
AutoGPT toolkits; per-incident pricing; new SKUs; `src/dashboard/` (Vite admin
UI, not wired to the assurance API — `/assurance` is the customer surface).
Treat anything not checked off as not built, whatever older copy elsewhere in
this repository's history claimed.
