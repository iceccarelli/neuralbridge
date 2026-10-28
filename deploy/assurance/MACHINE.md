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
statement binding these exact trace bytes to a recorder key and to a machine
reference (product, version, optionally a serial) the recorder says it was attached
to. "Exact" is twofold: the trace content hash (which covers the trace id, the declared
provenance, the source system, the start time, the sample rate, the conditions and
every sample) **rounds every number to six decimals**, so the body also carries
`exact_samples_digest` (`Trace.exact_digest()`: every value as its exact binary float,
`float.hex()`, plus the start time to the second and the type-tagged conditions).
A trace that differs from the attested one by less than the rounding (a failing
separation of S-4e-7 swapped for a passing S+4e-7) shares the hash but not the digest
and is `trace_mismatch`. The global content-hash semantics are unchanged.

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
  "trace_hash": "64 hex = Trace.content_hash()  (numbers rounded to 6 decimals)",
  "exact_samples_digest": "64 hex = Trace.exact_digest()  (every value at full precision)",
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
absent); a v1 attestation without `exact_samples_digest` is `malformed`. The
`signature` must be the one canonical base64 spelling of its 64 bytes (re-encoding the
decoded bytes must give back the text): the same signature written another way is
refused rather than read as the same attestation. Numbers in `window` are strings in a fixed form, so no float rendering can
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
  With no list configured **no attestation can be accepted**. No list is configured in a
  default deployment.
- **The server's trust is in one of three states**, reported by `POST /v1/machine/verify`
  as `recorder_trust.status`: `unset` (the variable is not set: nobody is trusted),
  `configured`, or `unreadable` (the variable is set but its file is missing, malformed
  or holds a key this service cannot use). `unreadable` **fails closed** and is an
  operator fault, not a way to trust more: nobody is trusted, sealing yields
  `community`, and the problem is logged once (the error class, never the file's path)
  and returned without the path. A public key of an algorithm this service does not know
  is an ordinary refusal (422 `invalid_recorder_trust` when a caller supplies it; an
  `unreadable` server file), never a 500.
- **Hosted readers apply the server's list or an empty one.** Everything that reads
  sealed verifications back out of the ledger over HTTP (machinery coverage and passport,
  the change routes, the fleet routes and declaration check, the watch report, the
  value position and the fleet report) re-assesses a recorded `validated` tier against
  the server's list: a key the operator has revoked or removed, or no usable list at all,
  reads as `community`. They never read with *no* list, which would believe whatever
  the sealing verifier recorded. Offline commands reading their owner's own ledger keep
  the explicit `--recorder-trust` semantics (no list: the ledger is the reader's own).
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
twice), `trace_mismatch` (trace hash, exact sample digest, id, provenance, start, sample
count, rate or duration differ), `machine_mismatch` (product or version differs from the
envelope's; a serial the verification names, or the one in a `maker/model#serial`
subject, differs or is absent from the attestation), `provenance_not_permitted` (the key may not attest
this class), `expired`, `not_yet_valid` and `stale` (dated before the recording began,
or more than 90 days after it; the bound exists so a key cannot be used to vouch,
years later, for a recording nobody signed at the time). Anything but `accepted`
leaves the basis `declared_by_filer` and the tier capped at `community`, with the
statuses in the explanation. A serial the recorder names is not required of a
product-line verification (no serial given); it is checked as soon as the verification
names one.

**Expiry.** An attestation with no `expires_on` never expires: its bound is revocation or
removal of its key in the verifier's trust list (and the 90-day rule above, which bounds
only how long after the recording it may be *dated*). There is deliberately no default
maximum validity: a silent age-out would downgrade sealed evidence on a date nobody
chose. Set `--expires-on` when signing if an attestation should lapse; the accepted
sentence in the report says "with no expiry date" when none is set, and a later
`expires_on` is judged on the **checker's** day.

### One serial per verification: the subject grammar

A unit's ledger key is `maker/model#serial` (`MachineIdentity.key`). It is read one way
by the library, CLI, API and MCP (`machine/bundle.py:resolve_machine_serial`):

- the serial is everything after the **first** `#`. It must be present, must not itself
  contain `#`, and must not start or end with a space or hold a control character. A
  subject such as `Mk/Md#`, `Mk/Md#B#` or `Mk/Md#X#A` is refused (HTTP 422
  `invalid_subject`, CLI exit 1), never read as "no unit" or as unit `A`;
- an explicit `machine_serial` that differs from the key's is refused with a remedy
  (omit it, or give the key of the unit the recorder was attached to). It is what let an
  attestation made on unit A be sealed under unit B's key and read as B's by coverage,
  re-verification and the passport;
- a subject with no `#` (`product@version`, or none given) names a product line, not a
  unit. It requires no serial of the attestation (a serial the recorder names is then
  ignored and the bundle records `machine_serial: ""`); an explicit `machine_serial` is
  matched against the attestation.

Reusing an attestation for a *different* trace is impossible (the trace hash is
signed); reusing it for the same trace is the same fact. Nothing here detects the
same attestation being submitted to two different accounts.

### The whole unit key is bound, by the service (not by the recorder's signature)

The recorder key signs `(product, product_version, machine_serial)` and the recording. It
cannot name a maker or model: `machine_ref` has no such field and **the attestation format is
not changed by this**. A serial alone does not identify a unit (`Acme/AR-7#0001` and
`Beta/XY-9#0001` share one), so the *service* binds the verification to the unit key it was
sealed for:

- when the subject is a unit key, the sealed bundle body records it as `unit_key`
  (hashed content; absent for a product line). `check_bundle_data` requires it to be a
  well-formed key whose serial is the body's `machine_serial`; replay takes the recorded value;
- every ledger reader (`VerificationRecord.from_ledger`: coverage, passport, fleet, check,
  declaration, change cases) reads a stored `validated` as `validated` under a unit-key subject
  **only if** `unit_key` equals that subject exactly. `acme/AR-7#0001`, `Acme /AR-7#0001` and a
  Cyrillic `А` are different units; the answer is `community` with the reason in
  `VerificationRecord.tier_note` and in the coverage caveats;
- **a bundle sealed before this field existed, or sealed for a product line, carries no
  `unit_key` and is `community` under a unit-key subject.** There is no silent grandfathering:
  re-seal it with the unit's key as `subject` (the recorder's attestation is unchanged);
- one recording is the validated evidence of ONE **enrolled** unit key. Only a filing that still
  reads `validated` under the reader's trust list AND sits under a unit key a manifest was sealed
  for in the same ledger holds the recording (`UnitClaims`, built once per ledger read; the first
  such filing wins). A later claimant is `community`, with the holder named in `tier_note`.
  A filing under a key nobody enrolled (a typo, `Evil/Co#0001`) holds nothing, so it cannot burn
  the recording for the real unit: seal the real unit's manifest and its bundle, and the typo's
  claim then reads `community`. `POST /v1/machine/verify` with `seal` refuses to seal a claim the
  reader would cap (422 `invalid_subject`, naming the holder and the remedy);
  `change.service.reverify` has always refused it. Because the question is the reader's, a first
  claim whose recorder key was later revoked blocks nothing;
- a stored `certified` tier (only a resealed body can carry one; the checker rejects it) is read
  as `validated` at most. Nothing in this product certifies.

**Residual, stated.** Someone who can enrol a manifest for a hostile or mistyped key and seal the
recording under it first still holds it: the ledger is append-only and has no withdrawal, so the
remedy is a new recording on the real unit with its own attestation (the refusal says so). A
decider-recorded withdrawal is not built. Where nothing is enrolled (a ledger that holds bundles
and no manifests), two unit keys can each read `validated` for one recording: the
one-recording-one-unit rule is enforced among enrolled units only.

**Concurrency.** The refusal at sealing is a check followed by the append, not one atomic step.
With several API workers, two simultaneous seals of the same recording for two enrolled units can
both return 200 `validated`; every reader still caps the later one (`tier_note`), so the fleet,
passport and cases never believe both.

**Unsealed runs.** `POST /v1/machine/verify` with `seal: false` and a unit-key subject compares
nothing with the ledger; the response says so in `unit_binding_note` and the tier shown is the
sealing engine's, not what a reader would believe if the run were filed.

**Why it is not the reader's problem.** `Fleet.from_ledger` builds the claim map once and each
machine's read asks it, so a fleet read is linear in its bundles (150 attested machines: 0.5 s on
the previous release, 16 s with the first version of this rule, under 1 s now).

**What this does not do.** The recorder trust list is the *server's* and is not scoped to a
tenant, a machine or a serial: any key it names can attest any serial for any account. The seal
is a hash, not a signature: whoever can write the ledger file can reseal a body with another
`unit_key`. An attestation proves what a key signed, not that the machine is safe.

### Sealing, replay and the checker

The sealed body (engine 6) records the assessment (`recorder_attestation`: statuses,
findings, the accepted attestation hash and key fingerprint, `assessed_on`) **and the
attestations as supplied**, and `machine_serial`. It never records a trust list.

A checker never believes the recorded basis or tier. `machine check` /
`POST /v1/machine/bundle/check` re-assess the recorded attestations under the
checker's own list and today's date (`--as-of` to pick the day):

| checker has | result |
|---|---|
| a list that accepts the attestation, **and** the original envelope and trace | the engine is re-run and every sealed field must match: `level: reproduced`, `provenance_reassessed: reproduced`, `believed_tier` as recorded |
| a list that accepts it, without the original envelope and trace | `level: integrity_only`, `provenance_reassessed: reproduced`, `reassessment_note: "attestation re-assessed; checks not re-run"`, **`believed_tier: community`**: the attestation holds, but nothing re-ran the checks, and a bundle whose verdict was flipped and resealed looks identical from here |
| a list that does not | rejected (`not_reproduced`), `believed_tier: community` |
| no list | `ok` at `integrity_only` with a `NOT CHECKED` limitation, `provenance_reassessed: unverifiable`, `believed_tier: community`: the claim is **not believed**, never rejected silently and never passed as valid |
| nothing to claim (`declared_by_filer`) | `not_applicable` |

`believed_tier` is the recorded tier only when the check is `ok`, **re-ran the engine on
the supplied envelope and trace and reproduced the whole result, and** the attestation
holds under the checker's list. A rejected bundle is never believed at `validated`, and
the re-assessed attestation is never called "the believed tier" (`POST
/v1/machine/bundle/check` and the `/verify` page show `reassessment_note` instead). The
public validator is never given the trace, so it reads `community` for a recorded
`validated`.

Without the original trace the attestation is still re-assessed from the bundle's own
description of the trace (its hash, id, provenance and start); the recording window and
the exact sample digest are then not compared (the digest needs the trace bytes), and
the result says so. `ok` is still only "no inconsistency found", never recorder
authenticity.

On replay, what is compared is what can be reproduced: the readable attestations and
what became of each (status and hash), the accepted attestation and key, and the trace
and window facts. An attestation that could not be read (malformed, an unsupported
version) is sealed as a digest placeholder, is not re-fed on replay, and is not compared:
an honest bundle that carried one unreadable attestation next to a real one reproduces.

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
`machine_serial`; the response carries `provenance_basis`, `provenance_note`,
`recorder_attestation` (status, findings, key fingerprint) and `recorder_trust` (the
server's state: `unset`, `configured` or `unreadable`). A malformed unit `subject`, or a
`machine_serial` that contradicts the subject's, is 422 `invalid_subject`. There is no signing route:
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
2. the claim is coherent on its own: the engine version is one that exists (plain ASCII
   digits, `1` to the current one: `7`, `06`, ` 6` and Arabic-Indic `٦` are refused, not
   treated as "another engine whose checks are not known" and passed), the verdict agrees with the check outcomes, a
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
