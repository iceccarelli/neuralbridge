# Machinery Regulation Annex III 1.1.9

Machinery Regulation (EU) 2023/1230 applies from **20 January 2027**. Annex III
1.1.9 requires a machine to identify its safety-relevant software and to record
evidence of intervention in it.

Doing either by hand is hard. The safety PLC program may be on a laptop, the
scanner zones in a vendor tool, the robot's safety parameters in the controller,
and the only record that a technician changed any of them may be that
technician's memory.

## The three verbs

```bash
assurance machinery record-manifest manifest.json --ledger register.db
assurance machinery record-change   intervention.json --ledger register.db
assurance machinery coverage        manifest.json --ledger register.db
```

`coverage` exits non-zero when any declared safety function is not currently
covered, so it is a gate, not a report.

## What a manifest is

One machine, one moment, one list of safety-relevant software. The field the
whole product turns on is `hash_source` per item:

| `hash_source` | what it means | tier ceiling |
|---|---|---|
| `read_from_machine` | hashed off the controller | `validated` |
| `supplied_by_vendor` | hashed from a file the supplier sent | `community` |
| `declared` | somebody typed a version number | `profile` |

One declared item among fifty read from the machine drags the whole manifest to
`profile`, and that is correct: the manifest is a statement about the machine's
configuration as a whole.

An item with no hash is reported as **uncomparable**, never as unchanged.

A comparison answers `matches` only when every item has a hash on both sides, every
observed hash was read from the machine, and the observed manifest is `as_found`.
Otherwise a comparison with no visible change is `unverifiable` (exit status 1,
sealed as indeterminate): nothing that could be seen moved, and some of it could
not be seen.

The fleet treats the latest `as_found` manifest of a machine as the machine; a
baseline (`as_declared`) filed later does not replace it, a plan (`as_intended`)
is never current, and a `taken_at` later than the moment the manifest was filed is
not believed.

A comparison answers `matches` only when every item has a hash on both sides, every
observed hash was read from the machine, and the observed manifest is `as_found`.
Otherwise a comparison with no visible change is `unverifiable` (exit status 1,
sealed as indeterminate): nothing that could be seen moved, and some of it could
not be seen.

The fleet treats the latest `as_found` manifest of a machine as the machine; a
baseline (`as_declared`) filed later does not replace it, a plan (`as_intended`)
is never current, and a `taken_at` later than the moment the manifest was filed is
not believed.

## Drift

```bash
assurance machinery diff \
  --baseline examples/machinery/manifest-baseline.json \
  --observed examples/machinery/manifest-as-found.json
```

```
Grimaldi/AR-7#0412: SAFETY-RELEVANT DRIFT — a safety-bearing item has changed
  !! ITM-FW: the artefact changed: aaaaaaaaaaaa → dddddddddddd,
             with the version still reported as '3.8.2'
       affects SF-01, SF-02
```

The grading is deliberately narrow. A version string moving while the artefact
stays byte-identical is `administrative` — reporting that as a safety finding
trains people to ignore the report. A hash moving on an item that implements a
safety function is the finding. A firmware swap that did **not** bump the
version string, as above, is the one nobody catches by hand.

Free and unmetered-by-account at `POST /v1/machinery/diff`, 10 per day.

## The join — the part that needs both halves

`assurance.machine` says: *on this run the cell met its declared separation,
speed and workspace limits.* `assurance.machinery` says: *on 14 March a
technician replaced the safety controller firmware.* Separately, each is a file.

```
Grimaldi/AR-7#0412 — GAPS
  [STALE ] SF-01 [PL d]  Protective stop on zone intrusion
           last verified by c0f9dcda3cd6 on 2026-02-09; invalidated by INT-0007
           on 2026-03-14, which changed ITM-FW and re-ran nothing with sealed evidence.
           running 183 day(s) without valid evidence for this function.
  [n/a   ] SF-03 [PL d]  Emergency stop
           this function declares no verification check, so no verification can cover it.
```

The inference is mechanical, not clever, and every link is declared by the
customer so a reviewer can point at the one they disagree with:

1. an intervention names the **item** it touched
2. the manifest says which **safety functions** that item implements
3. each function declares the **verification checks** that exercise it
4. a verification whose run started before that intervention (or at the same
   instant) no longer describes the machine

A function is **covered** only when *every* check it declares has been verified,
each judged by the newest run that exercised it. Verifying one check of two is not
cover; a newer failing run ends the cover an older passing run gave; a run in
which a check was `not_applicable` says nothing for or against it. Cover that
rests on a verification below the `validated` tier (a simulated trace, a datasheet
figure) is labelled as such in the report.

A verification is dated by **when the run happened** (the start of its trace), not
when the bundle was filed: a run captured in February and filed in June is evidence
about February. That date is the filer's word, so it is bounded by the ledger's own
clock:

- a run can never describe a moment later than the ledger says it was filed; a start
  ahead of the filing time is read as the filing time;
- a start that is unreadable, or more than a day ahead of the filing time, cannot be
  trusted (`date_suspect`, with a stated reason in the report). A *passing* result in
  such a record is read as the earliest possible time: every recorded change counts as
  after it, and with none to blame the function is `stale` rather than `current`, naming
  `undatable:<hash>` as the reason. A *failing* result in it is dated when it was filed,
  the latest it can have run, so an older pass cannot outrank it; a run that started after
  that failure was filed does supersede it, as for any failure;
- two things at the same second are ordered by the ledger: a verification filed after the
  manifest that showed a change, in the same second, is read as having come after it.

## What counts as a change

A function is disturbed by a change in three ways, and the report names which:

1. **A recorded intervention.** It disturbs the functions it names (read against the
   manifest's own spelling: `sf-1` is `SF-1`) **and** every function the manifest says the
   changed item implements, so a blank or mistyped list cannot make a change vanish. A
   function id that matches nothing is reported in `checks_skipped`. The route and
   `record-change` refuse a unit with no manifest sealed under exactly that key (`409
   unknown_machine`; a key that differs by case or by a digit is a different unit) and a
   function the manifest does not declare (`422 unknown_function`, named).
2. **A change the ledger's own manifests show and nobody recorded** (`implied:<hash>:<item>`).
   Each `as_found` manifest is compared with the latest earlier look or declaration for the
   unit (a plan, `as_intended`, says nothing about the machine). A safety-bearing item
   (one that implements a declared function) whose hash differs, that appeared or that
   vanished, or whose version moved when it carries no hash to compare, is a change. An
   intervention for the same item, dated after the earlier look and no later than the
   filing of the later manifest, explains it (for a changed hash its `to_hash` must be the
   hash now found); an unexplained change is dated when the manifest that showed it was
   **filed**, not its own `taken_at`, which is the filer's word. Verify *after* sealing the
   manifest. This is the smallest sound rule, not the whole truth: a first look has nothing
   to differ from, an item with no hash and an unchanged version is invisible, and the
   conservative direction is `stale`.
3. **A change record the reader cannot use** (`unreadable:seq-<n>`). One whose seal no longer
   matches, whose body is not an intervention, or whose stored row is not JSON is never
   dropped: what it recorded is unknown, so it is taken to have touched every function,
   dated when the ledger says it was filed. Verifications that began after that stand. The
   report names it and says why.

## Coverage states

| state | meaning |
|---|---|
| `current` | a passing verification exists and nothing since has disturbed it |
| `stale` | it was verified, and a later intervention invalidated that verification |
| `failing` | the newest run of one of its checks did not pass it |
| `never_verified` | at least one check it declares has never been verified |
| `not_demonstrable` | the function declares no checks, so nothing could cover it |

Only `current` counts as covered. `not_demonstrable` is not a pass — it is the
system telling you it has nothing to say.

## Intervention records

A record that names only *what* changed is a log. A record that also names *who
authorised it* and *what was re-run* is evidence. An intervention is recorded
either way — refusing an undocumented change would push it back to where it
lives now, which is nowhere — and its own findings travel with the sealed
record:

```
    authorised: NO
    revalidated: NO
    !! a safety-bearing item was changed and nothing was re-run. Every
       verification of SF-01, SF-02 that predates this change no longer
       describes the machine.
    !! a safety-bearing item was changed with no recorded authorisation.
```

`kind: reconstructed` marks a record written after the fact, and says in its
findings that the times and attribution are somebody's recollection.

## The passport

```bash
assurance machinery passport manifest.json --ledger register.db \
  --actor a.person --out passport.json
```

Identity, configuration, change history, and the coverage position for every
declared safety function — sealed as one object. To re-check somebody else's:

```bash
assurance machinery check passport.json --ledger register.db
```

`POST /v1/machinery/passport/check` does the seal and internal-consistency half
over HTTP, free and unmetered for anyone, for the same reason the verification
bundle checker is free: a passport only its vendor can verify is a certificate,
not evidence.

Checking a passport with no ledger returns `ok` **with** a stated limitation, not
a clean pass. The seal proves the file was not edited. It does not prove the
machine is safe.

The seal covers the evidence object only; the manifest, coverage and intervention
list printed beside it are what a reader looks at, so the checker compares each
with the sealed body (an edited coverage block, a removed intervention, or a
manifest that is not the one the seal names is rejected), and checks the sealed
claim is coherent without the ledger: a function recorded `current` must name the
verification that made it so, a `stale` one the intervention that did, and the
validation state and confidence must agree with the verdict. A file that cannot be
read is reported, never raised.

## What it will not tell you

It does not confirm the manifest is complete. A safety-relevant item nobody
listed is covered by nothing here and reported by nothing here. That sentence is
in the `checks_skipped` of every coverage assessment, because it is the limit
that matters and it is the one a customer will otherwise assume away.
