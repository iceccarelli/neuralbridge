---
hide:
  - navigation
  - toc
---

# Industrial Autonomous Assurance

**Evidence infrastructure for machines whose software can hurt someone.**

A robot cell ships with a Declaration of Conformity, a risk assessment, and a
CE mark. Then somebody updates the safety controller firmware, reshapes a
scanner zone, or patches a PLC project — and every one of those documents
quietly stops describing the machine that is actually on the floor. Nothing
says so. The paperwork still looks correct, which is worse than looking wrong.

Two regulations turned that from a quality problem into a legal one:

| | |
|---|---|
| **Reg. (EU) 2024/2847** — Cyber Resilience Act, Art. 14 | Applies since **11 Sep 2026**. An actively exploited vulnerability means **24 hours** to file an early warning. |
| **Reg. (EU) 2023/1230** — Machinery Regulation, Annex III 1.1.9 | Applies **20 Jan 2027**. The machine must identify its safety-relevant software and record evidence of intervention. |

Neither is satisfiable from a spreadsheet. Both are satisfiable from a
hash-chained record of what is on each machine, what was verified against it,
and when. That record is what this builds.

## Start here

```bash
pip install -e '.[assurance-attest]'
python -m assurance kit init plant/            # a runnable kit
python -m assurance kit check plant/kit.json    # what it would open. Reads only
python -m assurance kit run  plant/kit.json --out plant/out
```

Your ledger, your disk. No account, no API key, no upload. See
[Getting started](getting-started.md) for the full walkthrough, or the
[Assurance engines](assurance/index.md) for what each command actually does.

## Pricing

| | Price | Includes |
|---|---|---|
| **Validator** | free | Article 14 draft validation, ISO/TS 15066 separation calculator, manifest diff, advisory check, Declaration check, bundle re-verification, attestation verification, offline enrolment kit |
| **Register** | €390 / month | The Article 14 register for one manufacturer: unlimited cases, both deadline clocks, hash-chained ledger with verifiable export, 25 product families |
| **Cell** | €1,290 / month | Everything in Register, plus machine safety verification, Annex III manifests and passports, fleet advisory fan-out, counter-signed head attestation |

Verification is free at every tier, always — see [Pricing](pricing.md) for
the full comparison, or [neuralbridge.io](https://neuralbridge.io/#pricing)
for the live, purchasable version of this same table.

## The platform underneath

This product is built on NeuralBridge, a smaller integration layer with its
own honest status page: see [Platform status](platform.md) for what is
actually supported today versus still evolving.
