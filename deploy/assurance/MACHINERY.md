# Machinery Regulation Annex III 1.1.9

Machinery Regulation (EU) 2023/1230 applies from **20 January 2027**. Annex III
1.1.9 requires a machine to identify its safety-relevant software and to record
evidence of intervention in it.

Doing either by hand is hard. The safety PLC program may be on a laptop, the
scanner zones in a vendor tool, the robot's safety parameters in the controller,
and the only record that a technician changed any of them may be that
technician's memory.

## Step one: enrol the machine

```bash
assurance machinery enrol manifest.json --ledger register.db --actor "a.integrator" \
    [--site "Plant 2" --owner "Example GmbH"] [--json]
```

`POST /v1/machinery/enrol` (`{manifest, actor, role?, site?, owner?}`, gated like
`POST /v1/machinery/manifest`) does the same through the same domain function
(`assurance.machinery.enrol.enrol_machine`); there is no MCP tool, because enrolment is a named
person's declaration. It seals the manifest, seals one `machinery.enrolment` record under the
machine key, and returns a **receipt**: machine key, configuration hash, the manifest and
enrolment entry numbers, item counts (items carrying no hash are listed as uncomparable), the tier
ceiling (a ceiling, not a result), functions that declare no check, every function's coverage
(`never_verified` until a verification is recorded), what enrolment does **not** establish, and
the next steps.

| outcome | what happens | CLI exit | HTTP |
|---|---|---|---|
| `enrolled` | manifest and enrolment sealed | 0 | 200 |
| `already_enrolled` | same key, same configuration: nothing written | 0 | 200 |
| `configuration_differs` | same key, changed configuration: that is drift, not an enrolment; nothing written, the receipt points at `machinery diff` / `change assess drift` | 1 | 409 |
| `identity_conflict` | the key is enrolled with different declared attributes (site, owner, year, country): nothing written, a person decides | 1 | 409 |
| refused input | no actor, an automation actor, a site that contradicts the manifest, an unreadable file, a ledger chain that does not verify | 2 | 422 / 409 |

Enrolment does not establish that the machine is verified safe (it runs no verification), that the
manifest is complete, or that the serial is the serial of a physical unit: identity is as declared.

### Changing the site or owner after enrolment

An enrolment record is sealed and never rewritten. When a machine moves or is sold, a named person
amends the declaration as a **new** record:

```bash
assurance machinery amend-enrolment --ledger register.db --machine "Grimaldi/AR-7#0412" \
    --actor "a.integrator" --reason "moved to Plant 3 on 2026-10-01" [--site "Plant 3"] \
    [--owner "Example AG"] [--json]
```

`POST /v1/machinery/enrol/amend` (`{machine, actor, role?, reason, changes: {site?, owner?}}`,
gated exactly like `POST /v1/machinery/enrol`) calls the same domain function
(`assurance.machinery.amend.amend_enrolment`). There is no MCP tool: it is a named person's
declaration of identity.

* The amendment (`machinery.enrolment_amendment`) names the enrolment entry hash and the previous
  amendment's hash, so each machine has one amendment chain, oldest first. The enrolment record and
  earlier amendments stay in the ledger byte for byte; the previous value is shown beside the new.
* The **effective identity** is the enrolment followed by its amendments in order. Re-reading by
  `machinery enrol` (receipt) and `GET /v1/fleet/machines` (site) show the effective values and that
  they were amended: who, when, why, from -> to (`identity_amended`, `amendments`,
  `original_declared`; fleet rows add `declared_site`, `identity_amendments`).
* Only `site` and `owner` are amendable (an attribute never declared can be added). Year and country
  are not; the machine key (manufacturer / model / serial) and the configuration are not attributes:
  a different key is a different machine (`machinery enrol`), a changed configuration is drift
  (`machinery diff`, `change assess drift`).
* **Re-enrolling after an amendment** compares the claim with the *effective* identity. Enrolling
  again with the original site or owner is an `identity_conflict` (nothing written), as is a
  manifest that still carries the original site. The amendment wins until a named person amends again.
* Concurrent amendments are serialised by the ledger's compare-and-swap on the machine's newest
  enrolment/amendment entry: both are recorded in one order, or one is refused. The chain never forks.
* The ledger chain must verify first; an amendment chain that does not link to the enrolment, or whose
  `from` is not the value then in force, stops the effective identity at that point and is reported.
* An amendment does not establish that the identity is authenticated to a physical unit, that the
  reason is true, or anything about verification: the configuration hash and every function's coverage
  are as they were.

| outcome | what happens | CLI exit | HTTP |
|---|---|---|---|
| `amended` | amendment sealed | 0 | 200 |
| `no_change` | same values as in force: nothing written | 0 | 200 |
| `not_enrolled` | no enrolment under this key: enrol first; nothing written | 1 | 409 |
| `unknown_attribute` | not `site` / `owner`; nothing written | 1 | 409 |
| `key_change_refused` | key or configuration named; nothing written, points at enrol / diff | 1 | 409 |
| refused input | no actor, an automation actor, no reason, an empty value, nothing to amend, a ledger that does not exist (CLI never creates one), a chain that does not verify | 2 | 422 / 409 |

## Onboarding a fleet from an inventory export

`machinery enrol` takes one machine. A plant that already has a list (an asset-management or CMDB
export, a spreadsheet) enrols it in one command:

```bash
assurance machinery import-inventory export.csv --mapping mapping.json --ledger register.db \
    --actor "a.integrator" [--dry-run] [--max-rows 500] [--json]
```

**This is a file importer.** It is not a live CMDB connector, not an integration with SAP PM,
Maximo or any other product, and not a supported adapter; nothing in it talks to another system.
Each row goes through `enrol_machine` (the one front door: no sealing is reimplemented), with the
named actor, so the outcomes are enrol's own.

**Input.** CSV (RFC 4180, UTF-8, a header row, delimiter `,` or `;`, a BOM is tolerated, quoted
fields may contain newlines) or a JSON array of objects. At most `--max-rows` data rows (default
500) are processed. A file over 25 MB, not UTF-8, or containing a NUL byte is refused.

**Mapping** (`mapping.json`; unknown keys are refused). A synthetic example is in
`tests/fixtures/inventory/` (`mapping.synthetic.json`, `sap-pm-export.synthetic.csv`):

```json
{
  "source_system": "sap-pm-export",
  "export_date": "2026-10-15",
  "columns": {"manufacturer": "Hersteller", "model": "Typ", "serial": "Seriennr",
              "site": "Standort", "owner": "Eigentuemer", "year": "Baujahr", "country": "Land"},
  "items": [
    {"name_column": "SPS Firmware", "version_column": "SPS Version", "sha256_column": "SPS SHA256",
     "supplier": "ControlCo", "kind": "firmware", "implements": ["SF-01"]},
    {"name": "Safety scanner zone set", "version_column": "Scanner Version",
     "kind": "safety_configuration", "implements": ["SF-01"]}
  ],
  "functions": [
    {"function_id": "SF-01", "description": "Protective stop on zone intrusion",
     "required_performance": "PL d", "verified_by": ["ssm_separation", "stop_characterisation"]}
  ]
}
```

* `columns`: `manufacturer`, `model`, `serial` are required; `site`, `owner`, `year` (four digits),
  `country` (ISO 3166-1 alpha-2) are optional.
* `items`: each is a literal `name` or a `name_column`, plus `version_column`; optional
  `supplier` / `supplier_column`, `sha256_column`, `kind` (default `firmware`), `implements`. An item
  whose name cell is empty is not listed; one with a name and no version is not listed and the row
  says so. A row with no items is rejected.
* `functions`: safety functions the **mapping** declares for every machine in the batch, with the
  checks that exercise them (`verified_by`). The export itself says nothing about safety functions;
  without `functions` the manifests declare none. With them, every function reads `never_verified`
  after the import, because no verification has been run.
* `source_system` (a label) and `export_date` (`YYYY-MM-DD`, when the customer's system produced the
  export) are required and are recorded.

**What each row becomes.** One manifest: source `as_declared`, every item's hash source `declared`
(the existing vocabulary; no new trust tier). A `sha256` cell, when present, must be exactly 64
hexadecimal characters or the **row** is rejected: it is never repaired, truncated or guessed. An item
with no digest is `uncomparable`, as in any enrolment. The sealed manifest carries its provenance
(importer version, source system, export date, the file's SHA-256, the row number) and says that the
entry is customer-provided and not collected from the machine.

**Outcomes** (per row; one bad row never aborts the batch; nothing is hidden):

| outcome | meaning | written |
|---|---|---|
| `enrolled` | manifest and enrolment sealed | yes |
| `already_enrolled` | same key, same configuration | no |
| `configuration_differs` | same key, changed items: drift, not an enrolment; the row carries the pointer to `machinery diff` | no |
| `identity_conflict` | same key, different declared site / owner / year / country | no |
| `rejected` + reason | unreadable row, empty required value, bad digest, bad year or country, control character, over-long field, `duplicate in file` (the second occurrence of a machine key), or an error from enrol | no |

Rows past `--max-rows` are **not processed** and are reported as `N rows not processed`; they are
never dropped silently, and they make the exit code 1. The summary lists the count per outcome and
every row that is not enrolled with its reason.

**Safety of the cells.** A cell that begins with `=`, `+`, `-` or `@` is kept as text (the row notes
it) and is never evaluated. Control characters, invisible format characters (zero-width, bidi
overrides) and fields over 200 characters are refused for that row. Only whitespace controls (tab,
newline) are accepted and collapse to a single space.

**Before and after the write.** The file, mapping and actor are checked in full before the ledger is
opened for writing: a header that lacks a mapped column, a bad mapping, a non-UTF-8 file or an
automation actor is refused with exit 2 and nothing is written. The ledger is created on first use,
like `enrol`; its chain is verified first. After a run that enrolled at least one machine, one
`machinery.inventory_import` record is sealed: file SHA-256, mapping SHA-256, source system, export
date, the counts, the actor, and per row the row number, machine key and outcome. It holds no
other row contents (no owner, site, version or digest). A re-run that enrolls nothing writes nothing,
including that record.

**`--dry-run`** runs every validation and shows the outcomes the import would produce, including
`already_enrolled` against the real ledger. The real ledger is only read (its bytes are copied to a
temporary directory and the import runs on the copy); it is never opened for writing and, if absent,
never created.

**Exit codes.** 0: every processed row is `enrolled` or `already_enrolled` and none was left
unprocessed. 1: some row is `rejected`, `configuration_differs`, `identity_conflict`, or not
processed. 2: usage or I/O error, a refused file, mapping, actor or ledger (including a chain that
does not verify).

**What the import does not establish.** The inventory is as declared by the customer's own system:
nothing was read from a machine, no verification was run, identity is not authenticated to a physical
unit, and the export's completeness is unknown (a machine or software item absent from the file is
absent from the record). Items without a digest cannot be compared later.

**API.** `POST /v1/machinery/enrol/batch` (`{rows, source_system, actor, role?, file_sha256?,
export_date?, functions?}`, gated exactly like `POST /v1/machinery/enrol`) takes **canonical machine
dicts** (`manufacturer, model, serial, site?, owner?, year?, country?, items: [{name, version,
supplier?, sha256?, kind?, implements?}]`), at most 200 per request (more is `413 too_many_rows`,
nothing processed), and calls the same domain function. It answers 200 with the per-row outcomes
whenever the batch was processed (some rows may have been written; read `counts`). `file_sha256` is
the caller's claim and is recorded as asserted, not checked. CSV parsing and column mapping stay in
the CLI on purpose: a server that parses arbitrary uploaded files is a larger attack surface than one
that takes canonical rows. There is no MCP tool: it is a named person's declaration of identity.

## The three verbs

```bash
assurance machinery record-manifest manifest.json --ledger register.db
assurance machinery record-change   intervention.json --ledger register.db
assurance machinery coverage        manifest.json --ledger register.db
```

`coverage` (and `passport`) is a gate, not a report. Exit codes:

| exit | verdict | meaning |
|---|---|---|
| 0 | `covered` | every declared function is current on evidence at `validated` or better |
| 3 | `covered_at_community` | every function reads current, but on evidence whose provenance the filer only declared (`community`): the recorded evidence stands, it was not a demonstration on the machine |
| 1 | `gaps`, `no_functions_declared` | at least one function is not current |
| 2 | | could not vouch: an error (an unreadable file or ledger), or the ledger's chain does not verify (`coverage` assesses nothing and says why on stderr; a passport sealed from such a ledger has verdict `ledger_chain_not_verified`, INDETERMINATE, never covered) |

**Passport format.** A passport is `assurance.machinery.passport/1` when an older verifier can
express its verdict (`covered`, `gaps`, `no_functions_declared`) and
`assurance.machinery.passport/2` when it carries `covered_at_community` or
`ledger_chain_not_verified`. `machinery check` of this release accepts both and still accepts a
passport written by the previous release; an older `machinery check` refuses a `/2` passport by name
("schema is ..., expected ...passport/1") instead of calling its verdict a tamper. Re-verify a `/2`
passport with this release or newer. Fixture: `tests/fixtures/passport_a135c0e_covered_at_community.json`.

Per function, `coverage` is one of `current`, `stale` (verified, then a recorded intervention
disturbed it), `failing` (a check's newest run VIOLATED it), `unchecked` (the newest run left the
function's checks unchecked, so nothing was shown and nothing failed), `incomplete` (some checks
verified, others left unchecked), `never_verified` or `not_demonstrable`. Only `current` is cover.

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
           running 183 day(s) without a standing verification for this function.
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
clock, and the two outcomes are dated in the two opposite safe directions:

- a *pass* is dated by its start, which can only make it look older than it is. A run can
  never describe a moment later than the ledger says it was filed (a start ahead of the
  filing time is read as the filing time). A start that is unreadable, or more than a day
  ahead, cannot be trusted (`date_suspect`): the pass is read as the earliest possible
  time, every recorded change counts as after it, and with none to blame the function is
  `stale` rather than `current`, naming `undatable:<hash>`;
- a *failure* is dated by when it was **filed**, whatever start it claims: a logger with a
  dead clock (1970, year 1) must not sort its failing run under an older pass. A pass
  supersedes a failure only if it **began after the failure was filed**;
- "when the ledger says it was filed" is the **filing clock**: the latest `at` among the
  unit's records at or before it in the chain. Clocks step backwards (NTP, DST, a restored
  VM); time as the chain saw it never does. The assumption is that the machine writing the
  ledger does not jump far *forward* and back: a record stamped far ahead pulls every later
  record of that unit with it, in the safe (stale) direction;
- two things at the same second are ordered by the ledger: a verification filed after the
  manifest that showed a change, in the same second, is read as having come after it.

## What counts as a change

A function is disturbed by a change in three ways, and the report names which:

1. **A recorded intervention.** It disturbs the functions it names (read against the
   manifest's own spelling: `sf-1` is `SF-1`) **and** every function the manifest says the
   changed item implements, so a blank or mistyped list cannot make a change vanish. A
   function id that matches nothing is reported in `checks_skipped`. `record_intervention`
   (and so the route and `record-change`) refuses a unit with no manifest sealed under
   exactly that key (`409 unknown_machine`; a key that differs by case or by a digit is a
   different unit) and a function the manifest does not declare (`422 unknown_function`,
   named). Functions are checked against the newest look and the newest declaration
   together; a plan (`as_intended`) never narrows them.
2. **A change the ledger's own manifests show** (`implied:<hash>@<seq>:<item>`). Each
   `as_found` manifest is compared with the latest earlier look or declaration for the unit
   (a plan says nothing about the machine; a look marked incomplete is never the earlier
   side and the items it did not collect are not read as removed). A safety-bearing item
   (one that implements a declared function) whose hash differs, that appeared or that
   vanished, or whose version moved when it carries no hash to compare, is a change. It is
   dated when the manifest that showed it was **filed**, not its `taken_at`, which is the
   filer's word. An intervention for the same item, dated after the earlier look and no
   later than that filing (for a changed hash its `to_hash` is the hash now found),
   **explains** it: the change is marked `explained_by` that record and dated no later than
   the record was **filed**. An explanation never removes the change, because the date in
   it is also the filer's word and a record back-dated to before the last verification
   would otherwise erase it in one call. Verify *after* sealing the manifest (and after
   filing the record): the report says so. This is the smallest sound rule, not the whole
   truth: a first look has nothing to differ from, and an item with no hash and an
   unchanged version is invisible.
3. **A record the reader cannot use** (`unreadable:...`). An intervention, manifest or
   verification bundle whose seal no longer matches, whose body has the wrong shape, or
   whose stored row is not JSON is never dropped. A damaged intervention or manifest is
   assumed to have touched every function; a damaged bundle is assumed to have failed
   every check. Each is dated when the ledger says it was filed, so a run that began
   afterwards stands. The report names it and says why.

A ledger whose chain does not verify is never `covered`: the coverage route answers
`409 ledger_chain_unverified`, `assurance machinery coverage` exits 2, and the fleet reads
every machine as `gaps` with `chain_verified: false`.

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
