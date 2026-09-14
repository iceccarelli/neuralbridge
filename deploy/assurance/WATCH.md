# The watch

Everything else here is invoked by somebody who already suspects something. This
is the component that finds a change on the day it happened rather than the day
somebody remembered to look — and it is what makes €1,290/month a subscription
rather than a tool licence.

```bash
assurance watch run watch.json --ledger register.db
assurance watch status watch.json --ledger register.db
```

```cron
0 6 * * 1  assurance watch run watch.json --ledger register.db || mail -s "fleet" ...
```

**Exit codes are the interface.** `0` quiet, `1` something changed since the last
pass, `2` the watch could not see part of the fleet. *"I could not look"* and
*"nothing moved"* must never share an exit code.

## Four judgements that decide whether anybody reads it

**Seal only on change — but record every look.** A weekly watch over forty
machines that sealed forty identical manifests would add two thousand records a
year saying nothing, and the real changes would drown. But a ledger with *no*
record cannot tell "we looked and it was the same" from "we never looked", and
those are opposite facts. So every run seals one lightweight **observation**
naming what was seen, and a full manifest only when the configuration moved.

**New is not the same as outstanding.** A watch that reports the same stale
function every week trains its reader to skim. Each run diffs against the last:

```
  [DRIFT] 0501  configuration moved 849a1dd1a879 → e3881c29e874: ITM-ZONES content_changed
           still uncovered (reported before): SF-01, SF-02
  [ok   ] 0412  unchanged at 492476c2676e
```

`NEWLY UNCOVERED` leads. `still uncovered (reported before)` is demoted. A
function that came back is reported as `recovered`.

**A machine that could not be collected is not unchanged.** A missing export
folder is an absence of observation, not an observation of absence:

```
  [BLIND] 0501  could not be collected: ...
           ! an absent export is not an unchanged machine.
```

**Silence expires.** A watch that stopped running looks exactly like a fleet that
stopped changing, and the second is the comfortable reading. `max_age_hours`
declares the cadence, and any machine whose last successful look is older becomes
a finding in itself:

```
  NOT LOOKED AT RECENTLY ENOUGH: 0501
  A watch that stopped running looks exactly like a fleet that stopped changing.
```

## A real three weeks

```
=== week 1 — first look ===
  [NEW  ] 0412  first observation; configuration 492476c2676e, 4 item(s)
           NEWLY UNCOVERED: SF-01, SF-02

=== week 2 — only the export headers moved ===
WATCH-PLANT2 — QUIET — every machine was looked at and nothing moved
  [ok   ] 0412  unchanged at 492476c2676e
  [ok   ] 0501  unchanged at 849a1dd1a879

=== week 3 — somebody reshaped 0501's protective zone ===
  [DRIFT] 0501  ITM-ZONES content_changed   affects SF-01
  [ok   ] 0412  unchanged at 492476c2676e
```

Week 2's export headers moved on **both** machines — new timestamp, new operator,
new sequence number, on four items each. Zero reported. That is the
`assurance.collect` normalisation doing its job, and it is why week 3 gets read.

## The configuration

```json
{
  "watch_id": "WATCH-PLANT2",
  "max_age_hours": 168,
  "targets": [
    {"serial": "0412", "plan": "plan.json", "root": "exports/0412",
     "site": "Plant 2, Line 4", "country": "DE"}
  ]
}
```

Plan and root are resolved relative to the config file, because a watch outlives
whatever directory it was first run from. A target missing a serial, plan or
root is **refused** rather than skipped — a silently skipped target reads exactly
like a machine that never changes.

`country` is flagged on every machine that lacks it, because a unit with no
territory recorded cannot be named in a CRA Article 14 filing's Member State
list, and 03:00 on the day the clock starts is not when to find that out.

## What it will not tell you

A machine not listed in the configuration is not watched, and its silence means
nothing. The configuration is compared against the last manifest **sealed** for
that machine, so a change made and reverted between two runs leaves no trace.
And the watch reports that verification evidence is in doubt after a
safety-relevant drift — it cannot re-run the verification, and it says so.
