# The fleet layer

`assurance machine` answers for one run. `assurance machinery` answers for one
machine. This answers for everything an integrator is on the hook for at once —
and it is the part that gets more valuable with every machine enrolled.

```bash
assurance fleet list      --ledger register.db
assurance fleet advisory  advisory.json --ledger register.db
assurance fleet declare   manifest.json --doc-id DOC-0412 --issued-by "..." \
                          --legislation "Regulation (EU) 2023/1230" --out doc.json
assurance fleet declaration doc.json --manifest manifest.json --ledger register.db
```

## Monday morning

```
machine                      site                   worst             stale  fns  config
-----------------------------------------------------------------------------------------
Grimaldi/AR-7#0501           Plant 7, Cell A        stale                 1    2  9c4dbacf06a9
Grimaldi/AR-7#0733           Plant 9, Line 1        never_verified        0    2  b050efe446c3
Grimaldi/AR-7#0412           Plant 2, Line 4        current               0    2  4d77ffb0f71b

5 machine(s): 3 covered, 2 with gaps
```

Worst first, because that is the order somebody reads it in. Every row comes
from the same `assess_coverage` that answers one machine — this is aggregation,
not new inference, and that is deliberate.

## The choke point

A supplier publishes an advisory. Today it lands in an inbox and the integrator
who carries the CE liability for forty cells cannot answer the only question
that matters. The mailing list does not know what is installed anywhere. The
plant does not know what its cells are made of. The supplier does not know who
bought what.

The manifest fleet does — and because the manifest already maps item → safety
function → verification check → coverage, the advisory does not stop at *you
have four affected machines*:

```
CTRL-2026-11 (ControlCo, safety_relevant) — EXPOSED
  4 of 5 machine(s) match; 3 safety function(s) newly in question

  Grimaldi/AR-7#0412   Plant 2, Line 4   [confirmed] ITM-FW 3.8.2
      the artefact on this machine is byte-identical to one ControlCo named
      as affected (111111111111).
      SF-01  Protective stop on zone intrusion, verified 2026-02-09  → NOW IN QUESTION
      SF-02  Speed limit in collaborative operation, verified 2026-02-09  → NOW IN QUESTION
```

## Matching: a label is not an artefact

`assurance.machinery` already proves a firmware can be replaced without the
version string moving. So an advisory is matched on the strongest available
evidence and the basis is always reported, never flattened to a boolean:

| basis | confidence | meaning |
|---|---|---|
| `hash` | confirmed | the artefact is byte-identical to one the supplier named |
| `hash_mismatch` | **contradictory** | the label matches and the artefact does not |
| `version` | probable | the label matches; the supplier published no hash |
| `name_only` | possible | same component, version unknown or unlisted |

`hash_mismatch` is the finding no other system on the market can produce:

```
  Grimaldi/AR-7#0418   Plant 2, Line 6   [contradictory] ITM-FW 3.8.2
      this machine reports version '3.8.2', which the advisory names, but the
      artefact hashes to 222222222222, which is not among the hashes ControlCo
      published for that version. Either the supplier's figure is wrong or this
      machine is not running what it says it is running. Both need a person.
      SF-01  → UNRESOLVED (coverage: current)
```

It is counted in **neither** column. Not affected, not clear.

**No version-range arithmetic.** Vendor version schemes are not semver, parsing
them as if they were is how a cell gets cleared that should have been stopped,
and an advisory that means "everything before 3.9" can enumerate the versions it
means.

## Already-lapsed is not newly in question

A machine whose coverage was already `stale` is reported and is **not** counted
as newly in question. An advisory does not make a lapsed function worse, and
mixing the two hides the machines that were fine until this morning — which are
the ones somebody has to go and look at today.

## The Declaration of Conformity

A DoC has never named the software configuration it was signed against, because
until there was a configuration hash there was nothing to name. So it goes on
describing a machine that stopped existing the day a technician updated the
firmware, and nobody can point at the moment it stopped being true.

```
DOC-AR7-0412 — CONFIGURATION CHANGED
  declaration DOC-AR7-0412, issued 2026-01-20 by Grimaldi Engineering, covers
  configuration 108b15f43f26. Grimaldi/AR-7#0412 currently runs 6acb6ee2e14e.
  The declaration does not describe this machine.
```

Two questions, reported separately because they have different remedies:

- **`configuration_changed`** — the declaration is about software that is no
  longer installed.
- **`configuration_intact_evidence_lapsed`** — the software is right and the
  demonstration behind it has lapsed.

`assurance fleet declare` binds a declaration to the configuration in front of
you, so every later manifest either matches it or does not.

**This makes no legal judgement and says so in every output.** Whether a changed
configuration amounts to a substantial modification requiring a new conformity
assessment is a question for the manufacturer and their notified body. What this
establishes is the fact that question rests on.

## What is free, and why

`POST /v1/fleet/advisory/check` — one advisory, one machine, no account, 10/day.
A bulletin landed this morning; an integrator can answer *is this cell one of
them* before finishing their coffee.

`POST /v1/fleet/declaration/check` — free for anyone, forever. **The person who
most needs to know a declaration has stopped describing a machine is the buyer,
not the seller.** Gating it behind an account with the people who sold them the
machine would make it worthless.

The fan-out across an enrolled fleet is the paid product, because it requires
the manifests to be in the ledger — which is exactly the thing worth paying for.
