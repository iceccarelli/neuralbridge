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

5 machine(s): 3 covered, 0 covered at community, 2 with gaps
```

`covered` counts machines whose every declared function is current on evidence at `validated`
or better. A machine current only on weaker evidence (a trace whose provenance the filer
declared) is counted as `covered at community`, never as covered or as having gaps; `fleet list`
exits 0 only when every machine is covered, 1 when any has gaps, 3 when none has gaps but some
is covered only at community, 2 when the ledger chain does not verify. Each row carries
`evidence_tier_floor`.

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

`hash_mismatch` is the finding that a label and an artefact disagree with the
supplier's own figures:

```
  Grimaldi/AR-7#0418   Plant 2, Line 6   [contradictory] ITM-FW 3.8.2
      this machine reports version '3.8.2', which the advisory names, but the
      artefact hashes to 222222222222, which is not among the hashes ControlCo
      published for that version. Either the supplier's figure is wrong or this
      machine is not running what it says it is running. Both need a person.
      SF-01  → UNRESOLVED (coverage: current)
```

It is counted in **neither** column. Not affected, not clear.

Names and version labels are compared as the same string in different dress:
Unicode compatibility-normalised, case-folded, whitespace collapsed — so a composed
and a decomposed `ü`, `ß` and `SS`, or a trailing tab from a spreadsheet, match.
That is identity, not similarity: `ControlCo` and `Control Co GmbH` do not match.
Hashes are compared as whole values, case-insensitively, never by prefix. Only a
hash **read from the machine** counts: one from a vendor file or typed in says what
should be there, so the label decides. When an advisory lists several entries for a
component, the strongest basis any of them supports wins (hash, then
hash_mismatch, then version, then name_only), so the order the supplier listed
them in cannot change the answer. An item that records no supplier but carries the
advisory's component name is `name_only`: neither affected nor clear.

A fleet read from a ledger whose chain does not verify is never `clear`: records
may have been dropped, so the report is `needs_review`. A report over an empty
fleet says no machine was assessed.

Names and version labels are compared as the same string in different dress:
Unicode compatibility-normalised, case-folded, whitespace collapsed — so a composed
and a decomposed `ü`, `ß` and `SS`, or a trailing tab from a spreadsheet, match.
That is identity, not similarity: `ControlCo` and `Control Co GmbH` do not match.
Hashes are compared as whole values, case-insensitively, never by prefix. Only a
hash **read from the machine** counts: one from a vendor file or typed in says what
should be there, so the label decides. When an advisory lists several entries for a
component, the strongest basis any of them supports wins (hash, then
hash_mismatch, then version, then name_only), so the order the supplier listed
them in cannot change the answer. An item that records no supplier but carries the
advisory's component name is `name_only`: neither affected nor clear.

A fleet read from a ledger whose chain does not verify is never `clear`: records
may have been dropped, so the report is `needs_review`. A report over an empty
fleet says no machine was assessed.

**No version-range arithmetic.** Vendor version schemes are not semver, parsing
them as if they were is how a cell gets cleared that should have been stopped,
and an advisory that means "everything before 3.9" can enumerate the versions it
means.

## Importing a CSAF advisory (unsigned, inspect-only, possibly partial)

```bash
assurance fleet import-csaf vendor-advisory.json --out advisory.json
assurance fleet advisory advisory.json --ledger register.db        # inspect
assurance change assess-advisory --advisory advisory.json --ledger register.db \
        --accept-unsigned --actor "a.integrator" --reason "checked against the publisher's page"
```

Vendors and CERTs publish CSAF 2.0. `import-csaf` translates one into this product's
advisory format so nobody retypes it. **What it is:** unsigned third-party content. Nothing
here checks a signature, pins a key, opens a case or decides anything is affected.

**What it imports:** the header (tracking id, publisher, release date, title, reference,
summary, CVE ids); each affected product from the product tree as supplier + component +
version; the first `vendor_fix` remediation as the remedy.

**What it records in the advisory itself** (`import_record`, covered by the content hash; it is
an advisory-level label, not a seal: whoever deletes it turns the file into a hand-written
advisory that belongs to whoever edited it. Two fail-safes therefore also live in the data:
every affected component carries a note, so a version the advisory does not list is "a person
has to look" even without the record, and the title and summary begin with
`[unsigned CSAF import]` or `[unsigned CSAF import, partial: not imported B]`, which is what
`fleet advisory` prints beside its verdict. Data cannot make a stripped partial file say
"incomplete" by itself; the label is what a reader sees): origin `csaf_import`; trust `unsigned_inspect_only` (the only value
that loads); `partial` and the products dropped, each with the reason; where the severity came
from (`defaulted_by_importer` or `operator_flag`); the document's TLP label, tracking status,
category and release date; and the importer's notes. A file with no `import_record` (anything
written by hand or published in a signed feed) loads exactly as before and its hash and
signature do not change.

**What it drops, and what that means.** An affected product the importer cannot map to a
vendor, product name and version (it is only in `full_product_names` or `relationships`, its
branch lacks a version, its id is defined twice with different content) is *dropped*. The
advisory is then **partial**. A partial advisory is never `clear`: `fleet advisory`,
`change assess-advisory`, the free check, the report and the Article 14 draft all say
"incomplete translation" and name the dropped ids. `fleet advisory` exit codes: 0 clear;
1 a finding; 2 the command could not run; **3 incomplete** (nothing matched, but the
advisory is partial).

**Versions are never interpreted.** A `product_version` that is one plain token (`V2.001`)
is an exact label. Anything else (`All versions < V3.1`, `V2.x`, `2.0 and earlier`), every
`product_version_range` and the `first_affected` / `last_affected` boundaries are kept as
text, and the matcher answers "a person has to look" for any other version of that component.
For an imported advisory a version label it does not list (including a spelling difference such
as `2.001` for `V2.001`) is also "a person has to look", not "unaffected". A "fixed" version is
listed per component but **never used to clear** an import: a version fixed for one
vulnerability is not thereby fixed for another that affects the same component. `known_not_affected`
is ignored.

**Names are matched exactly, with one exception for imports.** For an import, the same
component name under a supplier string that differs ("Example Controls" for "Example Controls
GmbH", a different legal form, a hyphen) is "a person has to look" (`supplier differs`), never
a clear. This is engineering's stricter default for content a third party wrote, chosen
because a false clear is the worse mistake; the founder may relax it. A product name that
differs is not detected. When an import matches nothing, the report lists the (supplier /
component) pairs it looked for ("no component name matched exactly"), so a misspelling can be
seen; a product that is truly absent from the fleet is still clear (exit 0).

**Other things that make an import partial:** a vulnerability with no `product_status`
(`vulnerabilities[i] has no product_status`), and a product named only in `remediations`,
`threats`, `flags` or `scores` of a vulnerability (its status is not stated, so it is dropped
and named).

**What it never claims.** That the advisory is authentic; that the severity came from the
publisher (CSAF has no such field, so the importer defaults to `safety_relevant` and says
so); that nothing else is affected; that a machine is safe because nothing matched.
`draft` / `interim` documents are refused unless `--allow-draft`, and then marked partial.
Control, invisible and direction-changing characters are removed from display text (and
said); in a vendor, product or version name, where removing them would change what matches,
the document is refused. Wrong-typed fields, a tree deeper than 64 levels, more than 100,000
products or a file over 8 MiB are a message and exit 2, never a traceback. `--out` may not
be the input file.

**Signing one.** `assurance supplier publish` refuses an advisory that carries an `import_record`: a vendor signs what it wrote and checked itself, not a translation nobody here authenticated. And a signed feed cannot upgrade one: the watch and `fleet advisory` treat an import inside a verified feed as inspect-only.

**Opening a case on one.** `change assess-advisory` (and `POST /v1/change/assess/advisory`)
refuse an unsigned import unless a **named person** passes `--accept-unsigned` (API:
`accept_unsigned: true` with `actor`) and a `--reason`. On the command line that name is whoever
owns the shell and the ledger file (recorded as `declared_locally`). On the hosted API the
override is a human decision like closing a case: it needs an **operator key with the decider
role** (an account-level key is refused with 403), and the case records how the name was
established (`advisory_accepted_basis`). The case then
carries `advisory_trust`, `advisory_origin`, `advisory_partial`, `advisory_dropped_products`,
`advisory_severity_source`, `advisory_tlp`, who accepted it and why, in its provenance and
its export, and it opens with a human decision to confirm the advisory against the
publisher. An imported advisory has its own case id (advisory id, issuer and trust class), so
it can never merge into, or rewrite, a case opened from a signed advisory. A hand-written bare
advisory file or request body needs a named person too (a declared name suffices; no flag) and
is marked `unauthenticated_file` / `unauthenticated_input`. A bare file with the same advisory
id as a case that carries no such marker (opened by the watch or from a signed feed) does not
update it: the command says so and exits non-zero.

**Article 14.** `assurance bridge art14 --open` on an import needs the same override: a named
person as `--actor` or `--received-by`, `--accept-unsigned` and `--reason`. An import's default
case id is `CASE-<advisory id>-<8 hex of its change-case id>`, so opening it can never take the
`CASE-<advisory id>` a trusted advisory with the same tracking id will need.

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

Two more verdicts say what was *not* established, and neither is a pass:

- **`configuration_matches_coverage_not_assessed`** — the configuration is the declared one and
  the evidence was never looked at: no coverage was supplied (the free route's default, and what
  an account without a plan that reads the ledger gets), the manifest declares no safety
  function, or the coverage is for another machine or configuration. `evidence_assessed` is
  `false`; `assurance fleet declaration` exits 2.
- **`configuration_intact_evidence_below_validated`** — every declared function reads current,
  but only on evidence below `validated`; `assurance fleet declaration` exits 3.

`describes_the_machine` (exit 0) means the configuration is the declared one **and** a coverage
assessment of this machine, over at least one declared function, found every one current at
`validated` or better.

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
