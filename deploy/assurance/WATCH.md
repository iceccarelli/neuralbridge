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
  the subscribed file changes. Whatever puts the supplier's feed there must
  fail loudly, never silently stop and look like a supplier with nothing to
  report. For a feed hosted at `GET /v1/supplier/feed/{account_id}`,
  `assurance supplier fetch <url> --out <path> --public-key <key>` is that
  thing: it refuses to write a feed that does not verify (leaving the
  previous good copy in place), and a network failure or a bad HTTP status
  exits non-zero rather than being read as an empty feed. Run it on a cron
  ahead of `watch run`, or wire it into whatever schedules this watch.


---

# From an advisory to a drafted filing

The watch finds a stop-use advisory against a still machine at 09:00. Then what?
Without this: somebody reads the output, opens a spreadsheet, and starts working
out which Member States the affected serial numbers went to. That is field 5 of
the ENISA form, and it is the reason a 24-hour deadline is hard rather than
merely short.

Declare the duty — **explicitly, because it is a legal question about your role
and not something a fleet can imply**:

```json
{
  "watch_id": "plant-1",
  "targets": [ ... ],
  "feeds":   [ ... ],
  "article_14": {
    "as_manufacturer": true,
    "received_by": "product.security@yourcompany.example"
  }
}
```

Only a manufacturer placing the product on the Union market carries the Art. 14
duty. While `article_14` is absent, **no intake is drafted at all** — the safe
direction to be wrong in.

## What a run produces

```
  Article 14: 1 newly drafted
    drafted    CTRL-2026-11  received 2026-09-14T18:45:36Z
               0 confirmed affected (matched by hash)
               2 machine(s) in NEITHER column — a person has to look:
                 Grimaldi/AR-7#CELL-0412
                 Grimaldi/AR-7#CELL-0501
               field 5: CANNOT BE COMPLETED
               still to be decided by a person:
                 - Whether this is an actively exploited vulnerability, a severe
                   incident, or neither...
                 - Whether and when awareness was established, per C(2026) 5252
                   Annex §213...
```

Confirmed and unconfirmed are printed separately and always. **`0 machines` on
its own reads as "you are fine"**, and here it means ControlCo published no
artefact hashes, so nothing is confirmed and field 5 cannot be completed — the
opposite of fine. This is the same argument `SUPPLIER.md` makes to suppliers,
arriving from the other end.

## What it refuses to decide

Awareness is a determination; the track is a decision. **This makes neither.**

Art. 14(2)(a) runs twenty-four hours from *awareness*, not from receipt. A tool
that quietly equated the two would either start a manufacturer's clock early —
inventing a filing obligation — or start it late, which is worse. C(2026) 5252
Annex §213 defines awareness as a reasonable degree of certainty after an
initial assessment; §214 requires that assessment to be prompt. The word
"prompt" is doing the work, and only a person can be prompt.

So `srp_prefill()` still omits `notification_type` and `awareness_datetime`, and
always will.

## What it watches instead: the signal nobody assessed

```
  ** UNASSESSED 39h ** CTRL-2026-11
       Art. 14(2)(a) runs 24 hours from AWARENESS, not from receipt — but
       C(2026) 5252 Annex §214 requires the initial assessment to be prompt,
       and this has been outstanding since 2026-09-14T18:45:36Z.
```

Nobody is told they are late. They are told what is outstanding, how long it has
been, and the provision that makes it matter. That is the alarm worth paying
for: not "you have a deadline", which everybody knows, but *"this one has been
sitting for thirty-nine hours and nobody has made the determination."*

Deliberately not called a breach: the window runs from awareness and awareness
has not been established, so nothing is late yet.

**Receipt is measured from the run that first saw the advisory**, carried
forward between runs. Resetting it each run would turn the one number a market
surveillance authority asks about first — the interval from receipt to awareness
— into a number that is always small.

**The prompt stops when a person records awareness.** From that moment the
register holds the clock, and a second system nagging about a decision already
taken is how people learn to close the tab.


---

# From a finding to a case

A finding that is only printed is a finding somebody has to remember. Since the
change-assurance layer (`deploy/assurance/CHANGE.md`), a watch run with sealing
on opens and keeps the **case** itself, so what it found is already a row in the
queue when the Monday mail arrives.

```
  [DRIFT] 0501  configuration moved 849a1dd1a879 → e3881c29e874: ITM-ZONES content_changed
           case case-5b2e0c91a7d4f336 [open]
```

| The run found | It does | Where it shows |
|---|---|---|
| A safety-relevant drift | opens (or finds) the machine's drift case, **before** sealing the new manifest | `MachineOutcome.case_id`, `sealed: case …` |
| An advisory, `new` or `outstanding`, that exposes the fleet | opens one case for the advisory naming every exposed machine; a standing advisory is folded in and writes nothing unless the exposure grew | `AdvisoryFinding.case_id` (sealed with the run) |
| A withdrawal of an advisory with a case | adds a question to the owner ("decide whether the work still stands"); closes and rejects nothing | the case's `human_decisions_required` |
| A recorded intervention nobody has a case for, that invalidated evidence | opens an intervention case, unless an open case on that machine already owns the same functions | `MachineOutcome.intervention_case_ids` |
| A dry run (`--dry-run`) | nothing. No case is opened, because nothing is sealed | `case_id` is empty |

**The case is opened first, then the manifest is sealed.** The manifest becomes
the next run's baseline, so sealing it first would let a crash between the two
swallow the drift: the next run would compare the new manifest with itself and
report `observed`. In this order a crash leaves the old baseline in place, the
next run sees the same drift, and `assess_drift` lands on the same case without
writing a duplicate. Both directions of the failure are tested.

**Running it twice writes nothing the second time.** A run over an unchanged
configuration reports `observed` and touches no case. A run that does re-assess
a case (a standing advisory, a recovered crash) leaves the ledger as it was
unless the reading actually differs. A case already past review is never
re-inflated by a later look.

**A machine that could not be collected never moves a case.** An uncollectable
machine is `BLIND`, the run is `degraded`, and no case on it advances, closes or
is touched; its open cases are named in the warning so that is not left to be
inferred. Silence is not progress.

**The watch opens; it never decides.** It runs as an `automation` actor, which
`decide`, `resume` and `resolve-decision` refuse. Nothing the watch does can
close a case.

What this does not do: the watch runs where the exports are, in the customer's
kit or from their cron, against their ledger. The hosted API does not run it and
cannot collect from a machine; it can only serve and work the cases that ledger
holds.

**A partial look is not a configuration.** If a run does not find or read every
item the plan names, the manifest it seals is marked `[collection incomplete: …]`
and the observation records `complete: false` with the missing item ids. The
drift it shows can still open a case, with the existing warning, but it can never
make a closed case look as if the machine "left" its configuration and came back.


---

# Reporting to your hosted workspace (`watch push`)

Watch runs where the exports are — your kit, your cron, your ledger. The hosted
API cannot collect from a machine and never sees a run, a failed run or a machine
nobody has looked at lately, so the `/assurance` workspace of a paying customer
would show nothing unless somebody posted manifests by hand. `watch push` is the
explicit, opt-in way to change that:

```bash
read -rs NB_ASSURANCE_KEY && export NB_ASSURANCE_KEY   # paste your Cell-plan key; it stays out of shell history
assurance watch run  watch.json --ledger register.db      # offline, as always
assurance watch push watch.json --ledger register.db \
    --api-url https://<your-api-host> --key-env NB_ASSURANCE_KEY
assurance watch push watch.json --ledger register.db \
    --api-url https://<your-api-host> --key-env NB_ASSURANCE_KEY --dry-run
```

Exit codes: `0` reported, `1` the server refused part of it (or something could
not be put in a report), `2` it could not run — no run in the ledger, no key, the
network or a 5xx. **A 2 is safe to answer by running the same command again**:
the server records each observation once (below).

## It is separate on purpose

`watch push` is `src/assurance/watch/push.py`. The offline kit, `assurance watch
run`, `watch status` and `collect` never import it or any HTTP client; a test
walks their import graph (and runs `watch run` in a fresh interpreter) and fails
if that changes. The airgap guard tests are untouched. Nothing leaves the plant
unless an operator types `watch push` with an explicit `--api-url` **and** the
*name* of an environment variable that holds the key. The key is never an
argument (a mistyped `--key …` is refused without echoing it), never printed,
never written. `--api-url` must be https; plain http is accepted only for
localhost. Redirects are never followed, so the key goes to the host you named
and no other.

## What is sent

From the latest sealed run in your local ledger:

* the watch id, the run's start time and verdict, and the `max_age_hours`
  cadence from your configuration (accepted range 1 to 720 hours);
* per machine: serial, machine key, status — `unchanged`, `changed`,
  `uncollectable` or `incomplete` — when it was observed, whether the collection
  was complete, a one-line detail, and the ids of plan items an incomplete look
  did not find;
* for a machine that was collected, its **SafetyManifest**: item ids, names,
  versions, content hashes, supplier names, safety-function ids, site, country,
  and the collection provenance (`method`, `notes`, who or what took it);
* for an unchanged machine whose sealed manifest is older than the look, **also the
  earlier local look at which that manifest was first sealed** (its own date, its
  own manifest, not marked relayed), so the hosted ledger can hold the manifest the
  relayed entry points at; it is the same manifest sent twice, not new information;
* for a machine that is `uncollectable` or `incomplete`, **also the last
  observation that did succeed** (with its manifest), so the workspace can say
  how long the machine has been unobserved instead of "never".

## What is not sent

Any export file, program, firmware image or configuration. The collection plan.
Local file system paths (the collection root and the plan path are blanked in
the hosted record). The *reason* a collection failed — it can contain a path —
which stays in your local ledger; the hosted record says only that the look
failed. The ledger itself. Supplier advisory findings and Article 14 drafts from
your run: use `POST /v1/change/assess/advisory` for an advisory, and awareness
and the Art. 14 track remain human decisions.

`--dry-run` prints exactly the request bodies (formatted for reading; compact on
the wire, same content) and opens no socket. It does not need the key.

A large fleet is split: each request stays under `--max-body-bytes` (default
900,000, below the server's 1 MiB cap) and at most 200 machines; `push` says how
many requests it made and why. A single machine report too large for any request
is named and not sent.

## What the hosted side does with it

`POST /v1/watch/report` (Cell plan, the same `Machine` gate as `/v1/change`: 401
with no or an invalid key, 402 when authenticated but not entitled) writes to
**your own per-account ledger and nowhere else**.

* It **records the manifest** with `record_manifest` and calls the same
  `assess_drift` that `/v1/change/assess/drift` and `watch run` use, over the
  divergence `compare()` computes against the manifest *this ledger* holds. It
  derives no safety finding of its own, and it does not trust the `changed` /
  `unchanged` you send: it compares, and records what it computed beside what
  you claimed. A machine with no earlier manifest there gets a baseline, not a
  finding.
* The case is opened before the manifest is sealed — the order `run_watch` uses —
  so a crash between the two leaves a retry landing on the same case.
* Each observation is sealed as the same `watch.observation` record the runner
  seals, so `_last_observation_at` and the stale logic read the hosted ledger
  unchanged. `plan` and `root` are empty there. It also records `received_at`,
  the **server's** clock when the report arrived, beside the reporter-declared
  `observed_at`, and `basis: "client_reported"`.
* **A failed look is recorded as a failed look.** `uncollectable` and
  `incomplete` are never a successful observation, never advance or close a case
  (the open ones are named in the response and left exactly where they were), and
  never make a machine current. A failed look may not carry a manifest. A
  positive look must carry one, and it is refused if the manifest says its
  collection was incomplete. Cases are only ever opened by this route, as an
  `automation` actor; nothing a report does can close one.
* **Idempotent.** Every machine entry has a digest; one already held writes
  nothing (`already_recorded`), so a retry after a timeout opens no second case
  and no second record. An entry **older** than what is recorded for that machine
  is ignored (`superseded_by_newer_observation`), so a delayed report cannot
  rewind the record; a *different* observation at an instant already recorded is
  refused. An `observed_at` more than 60 seconds ahead of the server's clock is
  refused, and one inside that margin is read as no later than the moment the
  server received it (`received_at`) or wrote it, so it cannot outrank a real
  failure that follows it and cannot make a machine look fresher than the server's
  clock allows. When `observed_at` and `received_at` differ by more than 24 hours
  (`OBSERVED_AT_SKEW_BOUND`) the observation is flagged `observed_at_skew`. The
  flag is a warning, not a refusal (a Watch that was offline and then pushed is
  late, not necessarily lying), and a skewed look is never read as *later* than
  the reporter said or than the server received it. Entries are
  applied in order of the instant they name, whatever offset they are spelled in.
* **A failure never creates a machine.** A failed look is recorded only against a
  machine the account has already enrolled (a successful look with a manifest):
  it carries the full `manufacturer/model#serial` key, or a bare serial that
  matches exactly one enrolled key. Otherwise it is refused
  (`unenrolled_machine`, `ambiguous_serial`), so a typo cannot leave a ghost row
  while the real machine reads current. A machine blind from its very first run
  is therefore not shown until one look succeeds, and `watch push` exits 1 saying
  so.
* **Bounded.** An account tracks at most 1000 machines and a report may introduce
  at most 200 new ones. The route runs in the threadpool, and ingest into one
  ledger is serialised across threads and processes by an advisory file lock
  beside the ledger (POSIX), so overlapping retries from several workers still
  write once. The wait for that lock is bounded (30 s, per ledger): past it the
  route answers `503 ingest_busy` with `Retry-After: 5` and has written nothing,
  and `watch push` retries 5xx. The assurance image runs one worker by design; the repository's
  root `Dockerfile` serves `neuralbridge.main`, not this API.

The response says, per machine, `recorded` / `already_recorded` / `refused` and
why, which case a drift opened or found, and a `limitations` list.

## What the workspace shows

`GET /v1/fleet/observations` (Cell): per machine, the last **successful**
observation, the last attempt and its status, how old the last success is,
`consecutive_failed_attempts`, open case ids, `cadence_hours` and `stale`. A
machine is stale when its last *successful* observation is older than its
cadence, or when it has never been reported — an enrolled machine nobody
reported is stale, not current. The cadence is **per machine**: the one declared
with the latest successful look of that machine by each watch that reported it,
the shortest if several did, and 168 h if none declared one. A cadence comes only
from a successful look of the machine it applies to; a report of failures, or of
other machines, can never lengthen it. An account
that has never pushed sees "No Watch report received", not a green list.

The age of a look is measured from the later-bounded instant described above (never
later than `received_at`, the server's clock). Each row carries `basis`
(`client_reported`), the reporter's own `last_successful_observed_at_declared`,
`last_successful_received_at` and `last_successful_observed_at_skew`.

A positive look must also rest on a manifest that is not older than that same
window at the moment of the look (`observed_at` minus the manifest's `taken_at`;
the declared cadence, 168 h if none). Older, it is recorded as `manifest_stale`:
an attempt that does not count, opens no case and does not move the baseline, and
for a machine the account has not enrolled it is refused rather than creating
one. The row shows `last_attempt_manifest_age_hours` and
`last_successful_manifest_age_hours`. `watch push` sends the manifest sealed when
an unchanged machine's configuration last changed, so it marks that entry
`manifest_relayed: true`. **That mark is a claim, and the server honours it only
for a manifest this account's own ledger already holds** (the same content hash,
which includes the manifest's own `taken_at`, for that machine). For a held
manifest the look counts, and the age and the mark are recorded and shown
(`last_successful_manifest_relayed`) instead of judged. For any other manifest
the mark is not accepted: an older-than-window manifest is recorded as
`manifest_stale` with reason `relayed_manifest_not_held` and a remedy (a machine
the account has not enrolled is refused, not created). So that an honest first
push can be accepted, `watch push` also sends the local look at which that
manifest was first sealed, as its own entry with its own date, ahead of the
relayed one; the server reads it as already recorded on every later push. If
the local ledger holds no such look, the relayed entry is not made current.

Remedy for a refused relay: report a manifest taken inside the freshness window.
A machine whose configuration has not changed seals no new manifest locally, so
until the local Watch seals a fresh one, a machine this account has never
received a manifest for cannot become current from an old manifest alone.

One behaviour change in the local watch, made so both sides agree: an
`incomplete` look (the plan named items it did not find) no longer counts as a
look for `stale_observations`. It never was an observation of the whole machine.

## What this does not establish

* The hosted service **cannot tell a true report from a false one**. These are
  observations reported by the holder of your key; it did not watch any machine.
  Every observation `GET /v1/fleet/observations` serves, and the `/assurance`
  workspace, carries `basis: "client_reported"` and is shown as *reported by the
  customer, not independently observed*. `observed_at` and the cadence are
  declared by the client.
* **A compromised Watch, or anyone holding the account key, can replay a genuine
  earlier manifest of a machine as a look at it, and this service cannot tell
  that from an honest look at a machine that did not change. Nothing here
  prevents it.** What the checks do: a `manifest_relayed` mark on a manifest this
  account has never held is not accepted; the reporter's `observed_at` is never
  read as later than the server's `received_at`; a large gap between them is
  flagged; and the age of the manifest stays visible. A manifest freshly
  fabricated, or a held one re-presented, defeats all of that. It is a stated
  limit of an opt-in reporting channel, not a proof of observation.
* It is as good as the export and the plan, exactly as the local watch is.
* A machine omitted from a report is not reported as anything; its silence shows
  as staleness once the cadence has passed.
* Hosted Watch — scheduled collection run for you — does not exist. Watch still
  runs in your kit or cron; the workspace shows what you choose to report.
