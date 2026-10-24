# Machine safety verification

Two commands. The first is what you put in front of a prospect; the second is
what they buy.

## The thirty-second demonstration

```bash
python -m assurance machine separation \
  --envelope examples/machine/envelope.json --speed 750
```

```
  Sh human travel         560 mm
  Sr robot reaction        75 mm
  Ss robot stopping       270 mm  (extrapolated_quadratic)
  C  intrusion            850 mm
  Zd human uncert.        100 mm
  Zr robot uncert.         50 mm
  --------------------------------
  S  required            1905 mm
```

Compare it with what the scanner is actually set to. If the two differ, look
first at C, Zd and Zr (terms a hand calculation can leave out) and at whether Sh
was computed over the stop time alone instead of reaction + stop — a shortfall
of `v_h * Tr`. This tool does not know which, if any, applies to a given cell.

The same calculation is at `POST /v1/machine/separation`, free, no account, 20
per day per address.

## The product

```bash
python -m assurance machine verify \
  --envelope envelope.json --trace run.json \
  --actor a.person --role "safety engineer" \
  --ledger register.db --out bundle.json
```

Exit code is non-zero on any violation, so it belongs in a commissioning
pipeline. Checks run:

| check | what it establishes |
|---|---|
| `workspace_containment` | the TCP stayed inside the declared box |
| `speed_limit` | speed stayed under the declared limit for the mode in force |
| `ssm_separation` | measured separation met the separation distance computed by the formula in `ssm.py` from the envelope's declared figures, at every sampled instant (the formula and constants are not verified against a licensed copy of the standard) |
| `stop_characterisation` | the cell never relied on a stopping distance outside the speed range it was measured over |
| `pfl_contact` | contact force and pressure stayed inside the body-region limits |
| `mode_consistency` | nobody was detected during unrestricted automatic operation |
| `trace_coverage` | the trace is long enough and exercised a safety regime (sanity floor of `MIN_TRACE_SAMPLES` samples and `MIN_TRACE_DURATION_S` seconds, not a standard) |
| `input_dates` | the trace start and the envelope's figure dates are not after the verification clock |

A check that could not run reports `unchecked`, never `verified`. The verdict
is `incomplete` when anything is unchecked, and `incomplete` is not a pass.

Three ways a trace can look clean and is not allowed to:

- **A gap beside a separation-controlled sample.** If the recording goes silent
  for more than two sample periods and either neighbouring sample was in a mode
  where separation is the protective measure, `ssm_separation` is `unchecked`
  (a violation elsewhere still wins). "At every instant" cannot be established
  across an interval nobody recorded. Gaps are measured against the shorter of
  the declared sample period and the one the data shows, and a declared rate more
  than a factor of two from the data's own is stated as a limitation.
- **Contact where contact is not permitted.** A nonzero contact force recorded in
  a mode that does not permit contact is not evaluated against any limit table,
  and `pfl_contact` is `unchecked` rather than `not_applicable` or `verified`.
- **Contact that was not evaluated.** A power-and-force pass needs every contact
  sample checked against both force and pressure. A sample with a force and no
  contact area, or credited to a body region the limits table does not cover (or
  to none), was not evaluated, and `pfl_contact` is `unchecked` — unless some
  other sample violated a limit, which wins. "Force alone does not establish a PFL
  claim" is what the verdict does, not only what a code comment says.

One thing it cannot tell apart: a separation of `None` means "the sensing system
detected nobody". Those samples are not checked and are counted in the stated
limitations (and if *every* separation-controlled sample is `None`, the check is
`unchecked`), but a CSV cell left blank, or a dropped value, reads the same. That
is why a column named `separation_m` (or any other unit variant of a field this
package reads) is refused instead of loading as "nobody detected".

Engine version 3 adds to these rules: a sample in a mode with no declared speed
limit, a separation-controlled sample with no separation measured, or a contact
sample with no force each make their check `unchecked`; every "stayed within"
check goes `unchecked` beside a recording gap; a trace below the sanity floor or
that exercised no regime is `unchecked`, not a pass; a PFL table the envelope
does not pin by hash is not evaluated; reaction time, stop time, stop distance
and intrusion distance must be strictly positive; and a human approach speed the
envelope does not declare is reported as a default. Version 2 was the first with
the gap and contact rules; a bundle records its engine
version and `machine check` will not call a re-run under a different engine a
reproduction.

## Inputs: units, ranges, and what is refused

Everything is millimetres, millimetres per second, seconds, newtons and square
centimetres. **Nothing is converted anywhere in this package**: the unit is in
the field name (`stop_time_s`, `measured_at_speed_mm_s`, `separation`) and a value
in other units is wrong by a factor nothing here can see unless it falls outside
the plausibility rails.

Every physical number goes through one function and is refused, not repaired, if
it is:

- a string or a boolean (`"750"`, `true`),
- NaN or an infinity — every comparison with NaN is false, which is how a NaN
  separation used to read as "not short" and pass,
- negative where a magnitude is required, or zero where a divisor or rate is,
- past a **plausibility rail**: 1e7 mm, 1e6 mm/s, 1e7 s, 1e7 N, 1e6 cm², 1e6 Hz.
  These rails are sanity limits, not physics and not from any standard; they exist
  so that `1e308` cannot overflow into `inf` and a gross unit slip is more likely
  refused than believed. They are rejected, never clamped.

| quantity | field(s) | unit | accepted | validated in |
|---|---|---|---|---|
| reaction time Tr, stop time Ts | `stop.reaction_time_s`, `stop.stop_time_s` | s | 0 … 1e7 | `StopPerformance` |
| stopping distance Ss | `stop.stop_distance_mm` | mm | 0 … 1e7 | `StopPerformance` |
| speed the stop was measured at | `stop.measured_at_speed_mm_s` | mm/s | > 0 … 1e6 | `StopPerformance` |
| position uncertainty Zd, Zr | `uncertainty.*_position_mm` | mm | 0 … 1e7 | `SensingUncertainty` |
| intrusion distance C | `intrusion_distance_mm` | mm | 0 … 1e7 | `SafetyEnvelope` |
| declared closing speed v_h | `human_approach_speed_mm_s` | mm/s | > 0 … 1e6 | `SafetyEnvelope` |
| speed limit per mode | `max_tcp_speed_mm_s[mode]` | mm/s | 0 … 1e6 | `SafetyEnvelope` |
| workspace corners | `workspace.minimum/maximum` | mm | −1e7 … 1e7, max > min | `Workspace` |
| trace time, TCP position | `t`, `tcp` | s, mm | ±1e7 | `Sample` |
| TCP speed, sensed closing speed | `tcp_speed`, `human_speed` | mm/s | 0 … 1e6 | `Sample` |
| measured separation | `separation` | mm | 0 … 1e7, or `None` = nobody detected | `Sample` |
| contact force, contact area | `contact_force`, `contact_area` | N, cm² | 0 … 1e7; area > 0 … 1e6 | `Sample` |
| sample rate | `sample_rate_hz` | Hz | > 0 … 1e6 | `Trace` |
| body-region limits, transient multiplier | `max_force_n`, `max_pressure_n_cm2`, `transient_multiplier` | N, N/cm² | > 0 … 1e7 (multiplier ≤ 1000) | `LimitsTable` |

An envelope field the schema does not define is refused too: a misspelt
`human_approach_speed_m_s` used to be ignored and the 1600 mm/s default used. A
trace is also refused with duplicate or non-increasing timestamps, no samples, or
more than two million samples (the hosted endpoint caps far lower).

## What this package does not establish

- **The formula is not the standard's text.** The terms are `S = Sh + Sr + Ss + C +
  Zd + Zr` with `Sh = v_h (Tr + Ts)`, `Sr = v_r Tr`, and `Ss` the measured
  stopping distance. The repository contains no copy of ISO/TS 15066 or ISO 13855,
  so that these are the standard's definitions, that 1600 / 2000 mm/s are the
  right closing speeds for the situations they are used in, and that C = 850 mm is
  the right intrusion distance for a given sensing arrangement, are all
  **UNVERIFIED** here. The tests establish that the arithmetic is the formula's
  structure, in independent SI units, monotone and dimensionally consistent.
- **`Sr` uses the whole TCP speed**, not its component toward the person. That is
  conservative; it is not the standard's directed-speed term.
- **C and the declared approach speed carry no evidence basis.** The tier is the
  floor of the stopping figures, the sensing figures, the trace provenance and the
  limits table. A weak C or an optimistic declared walking speed does not lower it;
  when the declared speed is used, the bundle says so.
- **Reaction and stop times are taken from the envelope.** They are not re-measured
  from the trace.

## What the tier means, and why it is computed

The tier on a bundle is the floor of every input the verdict rests on:

- a **simulated** trace caps at `community` and can never claim physical behaviour
- a trace whose provenance (`bench` / `field`) is only **declared by whoever filed
  it** caps at `community` and cannot claim physical behaviour either (engine 5;
  see below). Every trace is in this case unless a recorder attestation is accepted
  under the verifier's own trust list (engine 6)
- a **datasheet** stopping distance or sensor uncertainty caps at `profile`
- an **unverified** transcription of a body-region limits table caps at `community`
- `validated` therefore needs, in addition to **measured** figures, a provenance
  that something other than the filer vouches for: a signed recorder attestation
  accepted under a recorder trust list **the verifier holds and the filer cannot
  supply** (below). The tier is the `min()` of that, the envelope's figures and the
  limits review; an accepted attestation is necessary for `validated` and never
  sufficient
- `certified` is not reachable from a file at all

You cannot pass a tier in. That is deliberate: a tier a caller can assert is a
tier that will be asserted.

### Why a declared provenance does not count

`provenance` and `source_system` are fields in the trace the caller files. Nothing
here signs a recording or binds it to a recorder, so a file that says `field` and
`source_system: "python range() generator on my laptop"` is indistinguishable, to
this engine, from one cut from a controller. Until a recorder attestation can be
verified, the declared provenance is **recorded and sealed but not believed**: the
bundle carries `provenance_basis: declared_by_filer` (in the sealed body, the API
result as `provenance_basis` / `provenance_note`, the JSON of `machine verify`, and
the stated limitations), the tier is capped at `community`, and
`may_claim_physical_behaviour` is false. What a pass still tells you is that the
recorded samples stayed inside the declared envelope; not that they came from a
machine.

The route above that cap is the recorder attestation below. It is built like the
limits review: `machine/provenance_trust.py:assess_provenance` decides the ceiling;
`LIFTING_BASES` names the basis (`recorder_attested`) that *may* lift it, but a
bundle's recorded basis is believed only if the **checker's own re-assessment**
reproduces it (it is no longer a static empty set).

**Engine 5 and older bundles.** Engines 4 and earlier let a declared `field` or
`bench` trace reach `validated`; engine 5 capped it and could not yet verify an
attestation. `machine check` and `POST /v1/machine/bundle/check` reject a bundle
that records `validated` without a coherent `recorder_attested` basis, reject
`recorder_attested` on an engine before 6, and refuse to re-run an engine 5 bundle
under engine 6 (a different engine). Re-verify the original inputs with engine 6 to
get a bundle that says what it can support. Changing the `engine_version` field of a
resealed body in either direction is caught: down, the claim is rejected as
impossible for that engine; up, a re-run reports a different engine.

## Recorder attestation: what it proves and what it does not

A **recorder attestation** (`assurance.machine.recorder-attestation.v1`, module
`machine/recorder_attestation.py`) is a signed statement by the holder of an Ed25519
key. A verification may be lifted above the declared-provenance cap only when one is
**accepted under the verifier's own trust list**.

**Proved by an accepted attestation.** The holder of a key that *this verifier* trusts,
has not revoked and permits for this provenance class, signed, on the stated date, a
statement binding these exact trace bytes (the trace content hash, which covers the
trace id, the declared provenance, the source system, the start time, the sample rate,
the conditions and every sample) to a recorder key and to a machine reference
(product, version, optionally a serial) the recorder says it was attached to.

**NOT proved.** That the sample values are true physical measurements; that the
recorder or its sensors were calibrated, installed correctly or uncompromised; that
the machine reference is the physical machine in front of anyone; who holds the key
(the recorder's own label, `recorder_id`, is signed but never trusted: only the key
is); that the machine is safe. **Cryptographic integrity is not recorder
authenticity, and recorder authenticity is not physical safety.** No standard for
recorders, no accreditation and no certification is claimed or implied; `certified`
remains unreachable from a file.

### The signed payload

The signed bytes are the fixed prefix `assurance.machine.recorder-attestation.v1\n`
followed by the canonical JSON (`core/identity.py:canonical_json`: sorted keys, no
whitespace) of the body below, which carries `format` and every field except
`signature`. The prefix is a domain separator: a limits-review or ledger-head
signature (a bare canonical document) never verifies as a recorder attestation, nor
the reverse.

```json
{
  "format": "assurance.machine.recorder-attestation.v1",
  "attestation_id": "9f2c…  (8-128 chars of A-Za-z0-9._:-, unique per statement)",
  "trace_hash": "64 hex = Trace.content_hash()",
  "trace_id": "RUN-2026-09-12-A",
  "provenance": "field",
  "window": {"started_at": "2026-09-12T04:31:00Z", "sample_count": "20",
             "sample_rate_hz": "50.000000", "duration_s": "0.380000"},
  "recorder_id": "Cell 4 recorder, serial 17  (the recorder's own text)",
  "machine_ref": {"product": "Cell", "product_version": "1.0.0", "machine_serial": ""},
  "attested_on": "2026-09-12",
  "expires_on": "",
  "key_fingerprint": "16 hex = first 16 of SHA-256 over the raw public key",
  "signature": "base64 Ed25519 over the signed bytes"
}
```

Every key is required (`machine_serial` and `expires_on` are empty strings when
absent). Numbers in `window` are strings in a fixed form, so no float rendering can
be reinterpreted. Unknown fields, repeated JSON keys, `NaN`, wrong types (a number
where text is required, a boolean for an integer), malformed dates and `format`
versions other than `v1` are refused; nothing unsigned can ride along. A file or
value that contains a private key is refused unread.

### Trust is a verifier input

`assurance.machine.recorder-trust.v1`, a file **you** keep, obtained independently of
the trace and the bundle (read the fingerprint aloud to the recorder's operator):

```json
{"format": "assurance.machine.recorder-trust.v1",
 "recorders": [{"label": "Cell 4 bench recorder",
                "public_key_pem": "-----BEGIN PUBLIC KEY-----…",
                "fingerprint": "optional; if given it must equal the computed one",
                "provenance": ["bench", "field"],
                "revoked": false, "revoked_on": ""}]}
```

- Each key lists the provenance classes it may attest. A key trusted for `bench`
  cannot lift a trace that declares `field`; `simulation` is never liftable and a
  trust file naming it refuses to load. Unknown fields refuse to load.
- The CLI reads trust only from `--recorder-trust FILE`. The hosted sealing path
  (`POST /v1/machine/verify`) reads only the server-configured
  `ASSURANCE_RECORDER_TRUST` file; a request cannot supply trust. A caller may supply
  its own list only to `POST /v1/machine/bundle/check` (`recorder_trust`) and
  `POST /v1/evidence/verify` (header `X-Recorder-Trust`), to check *as themselves*;
  that never changes what the server sealed. A trust list inside a bundle is ignored.
  With no list configured **no attestation can be accepted**.
- **Rotation.** Add the new key, then revoke (`"revoked": true` or a `revoked_on`
  date) or remove the old one. **A revoked key rejects all of its attestations,
  including ones dated before the revocation**, because the signer chooses the
  `attested_on` date, so a date earlier than `revoked_on` proves nothing about when the
  signature was made. Removing a key has the same effect. Re-attest a recording under
  the new key if it must stay `validated`. A verification sealed earlier still says
  what it was worth when sealed; a checker with the updated list reports it
  `not_reproduced`.
- `machine recorder-trust --trust trust.json --public-key rec.pub --label … --provenance
  bench,field` appends a public key to a trust file.

### What is assessed

`assess_recorder_attestation(trace, attestations, trust, machine_ref=, now=)` examines
at most 8 attestations and returns a status per attestation and a headline:
`accepted`, `malformed`, `unsupported_version`, `untrusted_key` (no list, or the key
is not in it), `revoked_key`, `bad_signature`, `duplicate` (the same id or statement
twice), `trace_mismatch` (trace hash, id, provenance, start, sample count, rate or
duration differ), `machine_mismatch` (product or version differs from the envelope's;
a serial the verification names, or the one in a `maker/model#serial` subject, differs
or is absent from the attestation), `provenance_not_permitted` (the key may not attest
this class), `expired`, `not_yet_valid` and `stale` (dated before the recording began,
or more than 90 days after it; the bound exists so a key cannot be used to vouch,
years later, for a recording nobody signed at the time). Anything but `accepted`
leaves the basis `declared_by_filer` and the tier capped at `community`, with the
statuses in the explanation. A serial the recorder names is not required of a
product-line verification (no serial given); it is checked as soon as the verification
names one.

Reusing an attestation for a *different* trace is impossible (the trace hash is
signed); reusing it for the same trace is the same fact. Nothing here detects the
same attestation being submitted to two different accounts.

### Sealing, replay and the checker

The sealed body (engine 6) records the assessment (`recorder_attestation`: statuses,
findings, the accepted attestation hash and key fingerprint, `assessed_on`) **and the
attestations as supplied**, and `machine_serial`. It never records a trust list.

A checker never believes the recorded basis or tier. `machine check` /
`POST /v1/machine/bundle/check` re-assess the recorded attestations under the
checker's own list and today's date (`--as-of` to pick the day):

| checker has | result |
|---|---|
| a list that accepts the attestation | `provenance_reassessed: reproduced`, `believed_tier` as recorded; with the original envelope and trace the engine is re-run and every sealed field must match |
| a list that does not | rejected (`not_reproduced`), `believed_tier: community` |
| no list | `ok` at `integrity_only` with a `NOT CHECKED` limitation, `provenance_reassessed: unverifiable`, `believed_tier: community`: the claim is **not believed**, never rejected silently and never passed as valid |
| nothing to claim (`declared_by_filer`) | `not_applicable` |

Without the original trace the attestation is still re-assessed from the bundle's own
description of the trace (its hash, id, provenance and start); the recording window is
then not compared, and the result says so. `ok` is still only "no inconsistency found",
never recorder authenticity.

### Using it

```bash
# on the recorder operator's side, offline; the private key never leaves that side
python -m assurance attest keygen --out recorder.pem
python -m assurance machine recorder-sign --key recorder.pem --trace run.json \
  --product Cell --product-version 1.0.0 --machine-serial 0412 \
  --recorder-id "Cell 4 recorder" --out run.attestation.json

# on the verifier's side, with a trust file the verifier built from the recorder's PUBLIC key
python -m assurance machine recorder-trust --trust recorder-trust.json \
  --public-key recorder.pem.pub --label "Cell 4 recorder" --provenance bench,field
python -m assurance machine verify --envelope e.json --trace run.json --actor v.grimaldi \
  --recorder-attestation run.attestation.json --recorder-trust recorder-trust.json \
  --out bundle.json
python -m assurance machine check bundle.json --envelope e.json --trace run.json \
  --recorder-trust recorder-trust.json
```

Over HTTP: `POST /v1/machine/verify` accepts `recorder_attestations` (at most 8) and
`machine_serial`; the response carries `provenance_basis`, `provenance_note` and
`recorder_attestation` (status, findings, key fingerprint). There is no signing route:
a private key is never sent to this service, and one found in anything a caller
supplies is refused unread (422 `private_key_refused`). The `/verify` page and
`EvidenceVerifier` show the recorded basis, the re-assessed one when a trust list is
supplied, and the sentence "integrity is not recorder authenticity, and recorder
authenticity is not physical safety".

**Who is recorded as the actor.** `POST /v1/machine/verify` attributes the sealed
bundle to the credential, as `/v1/change` does: a key issued to an individual
operator seals that operator (`attribution=authenticated_operator`), and a request
naming anyone else is refused 403 `actor_mismatch`; an account-level key records
the name sent as declared (`attribution=declared_by_account_key`); open mode and the
CLI keep the label given. This is attribution to a credential, not identity-proofing.

## Body-region limits

This package ships **no** power-and-force limit values. They belong to the
standards body, they are revised, and a notified body may require a specific
edition or a project's own biomechanical study. `examples/machine/limits.template.json`
is the schema. Fill it from your licensed copy, then:

- `verified_by` / `verified_on` in the file are the **author's own claim** and never
  lift the tier. A PFL pass reaches `validated` only with a signed review
  (`assurance.machine.limits-review.v1`: Ed25519 over the table's content hash,
  edition, date and a stated basis) from a key in a reviewer trust list that you
  obtained independently of the table: `machine verify --limits-review r.json
  --limits-trust trust.json`. Missing, expired, revoked, untrusted, mismatched
  (table edited after review) or malformed reviews leave the tier at `community`
  and the bundle says which in words. The API seals only against the reviewer
  list the server is configured with (`ASSURANCE_LIMITS_REVIEW_TRUST`), never one
  sent in the request. A review attests that a key holder checked those exact
  bytes; it does not show the values are correct. `machine check --limits-trust`
  re-assesses a sealed review under *your* trust list; without one the validated
  tier is not reproduced. Bundles from engine 3 or earlier may have reached
  `validated` on the free-text claim alone and are flagged as such. (Independently
  of this, a trace's declared provenance caps every tier at `community` unless a
  recorder attestation is accepted, above; a limits review is necessary for
  `validated` and not sufficient.)
- pin the table into the envelope via `pfl_limits_hash` so a later silent edit
  makes the mismatch visible instead of changing the answer

## The bundle, and why the checker is free

```bash
python -m assurance machine check bundle.json \
  --envelope envelope.json --trace run.json
```

`POST /v1/machine/bundle/check` does the same over HTTP, free and unmetered,
for anyone — no account, forever.

That is a commercial decision, not an oversight. A customer's auditor, their
insurer, and their notified body must be able to check a bundle without a
subscription. A bundle only a paying customer can verify is a vendor
certificate, which is the thing this package exists to replace. Giving the
checker away is what makes the sealed bundle worth buying.

Four separate things are checked and the caller is told which failed:

1. the sealed evidence hashes to the hash it carries — catches post-seal edits
2. the claim is coherent on its own: the verdict agrees with the check outcomes, a
   violated check lists its violations, a simulation does not hold a `validated`
   tier, no `validated` tier rests on a provenance the filer merely declared (a `recorder_attested` claim must carry a coherent accepted attestation), no file holds `certified`, the validation state and confidence are
   consistent with the verdict and tier, and **the envelope and result printed
   beside the seal repeat what the seal says** (the seal covers the evidence only;
   those two blocks used to be unchecked). The seal is a content hash, not a
   signature — anyone with this package can edit a bundle and recompute it — so
   this step is what stops a re-sealed edit
3. with the original envelope and trace supplied, their hashes match and
   re-running the engine reproduces **every check**, the verdict, the tier and the
   stated limitations
4. if the bundle used a limits table, supply it (`--limits`); without it the re-run
   cannot be performed and the checker says so instead of calling the difference
   an edit
5. if the bundle records `provenance_basis: recorder_attested`, supply your own
   recorder trust list (`--recorder-trust`); without it the attestation is not
   assessed, the claim is not believed (`believed_tier: community`) and the checker
   says so

Supplying neither envelope nor trace returns `ok` **with** a stated limitation,
never a clean pass: integrity alone does not make a claim true.

`ok` means *no inconsistency found*, and a seal is not a signature, so a bundle
someone built by hand and sealed again can be `ok`. The answer therefore carries
`level`: `integrity_only` (seal and coherence only — the CLI prints `NOT
REPRODUCED`, exit status still 0), `reproduced` (the engine was re-run on the
original envelope, trace and, if needed, limits table, and every sealed field
matched) or `rejected`. Over HTTP, `POST /v1/machine/bundle/check` takes an
optional `limits` table and each flag under `checked` is true only if that check
ran and passed. The coherence step also requires the recorded checks to be exactly
the set the engine produces, and a tier no higher than the ceiling of the envelope
printed beside the seal.

## Regulatory context

Machinery Regulation (EU) 2023/1230 applies from **20 January 2027**. Annex III
1.1.9 requires a machine to identify its safety-relevant software and to record
evidence of intervention. Article 14 of the CRA has applied since **11 September
2026**. The register in `assurance.security.art14` answers the paperwork
question; this package answers the question underneath it.
