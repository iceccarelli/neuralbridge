# Collection: getting a real machine into the system

Everything else here assumes a manifest exists. Without this, that means
hand-writing JSON.

```bash
assurance collect check-plan plan.json
assurance collect probe      plan.json --first mon/ --second tue/
assurance collect run        plan.json --root tue/ --serial 0412 \
                             --actor a.person --ledger register.db
```

That order is the method, and it is not optional. Write the plan once for a
machine **type**, probe it until it says STABLE, then run it for every unit. An
integrator with forty AR-7 cells writes one plan; every cell after that is a
two-minute job.

## The problem this solves

A safety PLC export, a scanner configuration, a robot parameter dump: almost
none of them are byte-stable. They carry the time of export, the name of the
engineer who pressed the button, a sequence number, a checksum of themselves.

Export the same unchanged machine twice and the bytes differ. Hash the file as
it is and **every weekly collection reports drift on every machine**. A report
that always cries wolf gets ignored, and the one week the firmware really did
change is then the week nobody looks.

## The probe

```
plan PLAN-AR7 — VOLATILE — these rules will report drift that did not happen
  [MOVE] ITM-ZONES  (raw)
          the digest moved between two exports of an unchanged machine.
          ~ # Exported 2026-09-14T07:12:03Z by m.tech
          ~ # Export sequence no: 4181
          suggest: \d{4}-\d{2}-\d{2}   (a date)
          suggest: (?i)\b(serial|sequence|session|run)[_ ]?(no|number|id)\b   (a sequence number)
  [MOVE] ITM-PLC  (raw)
          ... The file is not text, so the differing bytes cannot be shown;
          a zip_members rule is usually the answer for an archive.
  [ok  ] ITM-FW  (raw)
```

Three of four items would have produced false drift every week. The probe found
all three, showed the lines that moved, and the exclusion pattern writes itself.
`probe` exits non-zero while any rule is volatile, so it belongs in whatever
reviews a change to a plan.

## The four rules

| rule | for | what it does |
|---|---|---|
| `raw` | firmware images, opaque blobs | hashes the bytes as they are |
| `text_excluding` | exports with a stamped header | drops lines matching declared patterns |
| `json_excluding` | exports with an export-metadata block | removes dotted keys, canonicalises |
| `zip_members` | project archives | hashes named members, ignores archive metadata |

Three constraints keep them honest:

- **A rule that drops bytes must say why.** An unexplained exclusion cannot be
  told apart from hiding a change, so `note` is required and the rule is refused
  without it.
- **A declared pattern that matched nothing is a warning.** Either the rule is
  wrong or the vendor changed their format; both mean the digest is not what the
  author intended.
- **The rule is part of the identity.** Each item records the normalisation
  fingerprint that produced its hash, so a digest taken under a changed rule is
  visibly a different measurement rather than an invisible change of machine.
  The `note` does not affect the fingerprint — wording is not measurement.

## Hostile and broken exports

A folder of exports is data from a laptop that has been through a vendor tool and
a USB stick. The collector may report a digest or report that it could not; it
never reports a digest of part of a file. An item that could not be read is
`unreadable`, the collection is **INCOMPLETE**, the exit status is 1, and nothing
reads as unchanged.

- a rule that drops bytes needs a non-blank `note`; a `raw` rule takes no
  patterns, keys or members; an unknown encoding or an archive member name that is
  absolute or contains `..` is refused when the plan is read
- archives are never extracted. A declared member listed twice, a symbolic link, a
  directory, an encrypted or corrupt member, an archive over the entry cap, or a
  member whose declared size is over the cap (a zip bomb) is refused before it is
  inflated. A declared member that is absent makes the item unreadable
- text and JSON are read only up to 64 MiB; raw files are streamed up to 4 GiB; a
  single text line over 1 MiB, JSON nested too deep, a JSON repeated key, a NaN or
  Infinity constant, or a file that hashes to nothing (empty, or every line
  dropped) is refused
- text lines end at CR, LF or CRLF only; other separators stay inside the line
- a link that leaves the collection root is not followed; more than 10,000 files
  or 4 GiB for one item, or running past the time budget (`max_seconds`, default
  30 minutes), makes the item unreadable
- a version is read only from a file under 8 MiB, and a JSON `null`, boolean or
  non-integer number is not a version label
- `collect run --ledger` does **not** seal an incomplete collection unless
  `--seal-incomplete` is given: a sealed manifest becomes the machine's current one
  with the missing items absent from every later comparison
- `probe` is `stable` only if every rule ran on both exports and held; a rule whose
  files were in neither export, or which could not be read, makes it `incomplete`

These limits are sanity limits, not figures from a standard, and Python's `re` has
no timeout: a pathological pattern in a plan can still run for a long time on a
long line.

## What collection refuses to do

**A required item that is not there is not in the manifest.** It is a loud
warning and a non-zero exit instead. A manifest listing an item nobody hashed
would assert the machine has software that was never seen, and every comparison
made from it afterwards would be wrong in the safest-looking direction.

**It does not guess what is safety-relevant.** There is no scanner mode. A tool
that guesses will guess wrong in both directions: it will miss the parameter set
that implements the protective stop, and it will fill the manifest with noise
that makes the real findings invisible. A human who knows the machine says what
matters, once.

**It does not invent a version.** `version: unknown` is the default and a
first-class answer. A plan that invents a label produces a manifest that will
later match a supplier advisory on a version nobody ever read off the machine.

**A multi-file item is the set, not the first match.** A safety PLC project is a
directory; its identity is the digest of every member's digest keyed by relative
path, so adding a file to the project changes the item.

## What it delivers

```
Grimaldi/AR-7#0412 — COMPLETE
  plan PLAN-AR7 (7caded60db89)  root tue/
  configuration c67b502e01e4fb3d
  tier ceiling  validated
  [ok  ] ITM-ZONES   521c177197fe  (version unknown)  1 file(s)
  [ok  ] ITM-PARAMS  e07850c516b7  v3.8.2             1 file(s)
  [ok  ] ITM-PLC     829608aefc80  (version unknown)  1 file(s)
  [ok  ] ITM-FW      5b2d0285aa4a  (version unknown)  1 file(s)
```

`tier ceiling validated` because every digest was read from the machine — which
is what `--ledger` then seals, and what `assurance machinery` and
`assurance fleet` consume without any further work.

The proof it is worth having:

```
Grimaldi/AR-7#0412: SAFETY-RELEVANT DRIFT
  !! ITM-ZONES: the artefact changed: 521c177197fe → 8e2de1351359
       affects SF-01

items compared: 4   changes found: 1
```

The protective zone was reshaped from 1500 mm to 1200 mm. The export header
moved on that collection too, on all four items. One change reported.
