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


---

# Watching the suppliers, not just the machines

The machine watch answers *"did anything on my floor change"*. Add `feeds` to
the configuration and it answers the other half — **did the world change
underneath machines that did not** — which is the half that wakes somebody up.

A supplier publishes a signed advisory at 09:00. Nothing on the plant floor
moved. Every manifest still matches. The machine watch reports QUIET, correctly,
and the integrator learns about it when their insurer asks.

```json
{
  "watch_id": "plant-1",
  "targets": [ ... ],
  "feeds": [
    {
      "supplier_id": "controlco",
      "feed": "feeds/controlco.jsonl",
      "public_key": "keys/controlco.pub",
      "notes": "fingerprint confirmed against the 2025 supply contract"
    }
  ]
}
```

The key is a separate file on purpose. A feed that carries its own key
authenticates nothing — the forged feed will carry one too. It has to be a file
the operator put there, obtained from the supplier by a route the advisories do
not travel on. See `SUPPLIER.md`.

## What one run looks like when it matters

```
plant-1 — FINDINGS — something changed since the last run
  [ok   ] CELL-0412  unchanged at e0045e0e1110
  [ok   ] CELL-0501  unchanged at 6ec7ca52368e

  suppliers: 1 STOP-USE advisory(ies) match this fleet; 1 new

  ** STOP USE ** CTRL-2026-11 (controlco) — Authentication bypass in safety controller firmware
       machines: Grimaldi/AR-7#CELL-0412, Grimaldi/AR-7#CELL-0501
       remedy:   Update to 3.9.1.
       source:   https://controlco.example/psirt/CTRL-2026-11
```

Both machines are *unchanged*. That is the point.

## Four judgements, and each is a way this is normally built wrong

**New is not the same as outstanding.** Run it again and the same advisory does
not reappear as new — but it has not been forgotten either; it is carried as
`outstanding` until the fleet stops matching it or the supplier withdraws it. A
watch that re-reports everything trains the reader to skim by the third Monday,
at which point it has become an expensive way to generate silence.

**A feed that cannot be checked is DEGRADED, never quiet.**

```
  suppliers: 1 feed(s) could not be checked
    !! controlco: absent — feeds/controlco.jsonl does not exist. The watch is
       blind to this supplier; that is not the same as this supplier having
       nothing to say.
```

Exit 2, not 0. This is where a signed-advisory mechanism most easily turns into
decoration: the fetch fails, verification is skipped, the run reports quiet, and
the absence of alarms is read as the absence of danger. A feed that fails
signature verification is treated the same way, and **nothing in it is acted
on** — an advisory that cannot be authenticated must not drive a change to a
safety system.

**A withdrawal is a finding.**

```
    WITHDRAWN  CTRL-2026-11     Authentication bypass in safety controller firm
               reason: 3.9.0 is not affected; the range was wrong
               You were told about this one. If somebody changed a machine
               because of it, that change now rests on a retracted advisory.
```

Announced exactly once, and only to a fleet that was actually told about the
original — an advisory published and retracted between two runs is not
mentioned, because nothing here was acted on. Nothing else in this industry
tells an integrator that the bulletin they acted on in March has been retracted.

**Stop-use is said first and alone.** An advisory the supplier marked
`stop_use` against a machine that matched is not one line among forty.

## Order of operations

The advisory pass runs **after** the machine pass, against the manifests this
run has just sealed. Asking first would report yesterday's fleet against today's
advisories, which is the one combination guaranteed to be wrong.

## What it does not establish

Carried in `checks_skipped` on every run:

* That the key belongs to the supplier. Confirm the fingerprint by the route in
  `SUPPLIER.md` — not by a link in an advisory.
* That the advisories are correct, complete or timely. A supplier who has not
  noticed a vulnerability publishes nothing, and no amount of signing detects
  silence.
* **That the feed on disk is current.** This watch learns of an advisory when
  the subscribed file changes. Whatever puts the supplier's feed there is
  outside this system, and a sync that silently stopped looks exactly like a
  supplier with nothing to report. Make the thing that fetches it fail loudly.
