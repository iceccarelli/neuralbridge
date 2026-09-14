# The 24-hour field

CRA Article 14(2)(a): a manufacturer who becomes aware of an actively exploited
vulnerability has **24 hours** to file an early warning indicating the Member
States in whose territory it is aware the product has been made available.

Everything else on that form can be written under pressure. **That list cannot.**
It is an inventory question, the answer lives in four spreadsheets and somebody's
memory, and the clock does not stop while it is assembled.

The fleet already knows.

```bash
assurance bridge art14 advisory.json --ledger register.db \
  --received-by a.integrator --open
```

```
CASE-CTRL-2026-11 — intake drafted from CTRL-2026-11
  2 affected machine(s) in 2 Member State(s): DE, IT
  product  Grimaldi AR-7 3.8.2  (2 unit(s))
  !! 1 machine(s) are neither confirmed affected nor confirmed clear.
```

`member_states_available` — field 5 — assembled from the enrolled machines, with
the serial numbers it was built from as its evidence. Exits non-zero when it
cannot be completed, because **a filing with a wrong field 5 is worse than a late
one.**

## What it refuses to do

The bridge does the inventory. It does not do the judgement, and the prefill is
deliberately partial:

```json
{
  "title": "ControlCo advisory CTRL-2026-11: ...",
  "summary": "...",
  "member_states_available": ["DE", "IT"],
  "product_name": "Grimaldi AR-7",
  "product_version": "3.8.2"
}
```

`notification_type` is **absent**: an advisory naming a watchdog defect is not by
itself an actively exploited vulnerability, and the track decides which clock
runs. `awareness_datetime` is **absent**: awareness is a determination made after
an initial assessment (C(2026) 5252 Annex §213), not the moment an email
arrived. A prefill that guessed either would put a manufacturer's name on a
statement nobody made.

Instead it produces the list a person must work through:

```
  still to be decided by a person:
    - Whether this is an actively exploited vulnerability, a severe incident,
      or neither.
    - Whether and when awareness was established. The advisory's publication
      time is when a document arrived, not when anyone understood it.
    - Whether the affected component is part of the product as placed on the
      market, or was integrated by somebody else downstream.
    - What is actually running on AR-7#0418: the version label and the artefact
      disagree, so it is in neither column.
```

`--open` records the signal and the product availability in the Article 14
register. **The register then refuses a filing until somebody records a track
and an awareness timestamp.** That is the point, and it is tested.

## Only confirmed machines count

A machine matched by artefact hash counts. A machine matched by version label,
or whose label and artefact contradict the supplier's published hash, does
**not** contribute a territory and is listed separately. The Member State list
on a regulatory filing is not the place to include a machine nobody has looked
at yet.

## Why `country` is on the machine

`MachineIdentity.country` is ISO 3166-1 alpha-2, recorded explicitly or not at
all. A site string is not a country: "Plant 2, Line 4" tells nobody where the
machine is, and inferring one from free text is exactly how a wrong Member State
ends up on a regulatory filing. A malformed code is refused at the manifest
rather than carried to the form.

Record it at collection:

```bash
assurance collect run plan.json --root exports/ --serial 0412 \
  --actor a.person --site "Plant 2, Line 4" --country DE
```

Every machine enrolled without it is one that will block a filing at 03:00 on
the day it matters.
