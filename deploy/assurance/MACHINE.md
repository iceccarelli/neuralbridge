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
| `ssm_separation` | measured separation met S(t0) at every instant |
| `stop_characterisation` | the cell never relied on a stopping distance outside the speed range it was measured over |
| `pfl_contact` | contact force and pressure stayed inside the body-region limits |
| `mode_consistency` | nobody was detected during unrestricted automatic operation |

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

Engine version 2 is the first with these rules; a bundle records its engine
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
- a **datasheet** stopping distance or sensor uncertainty caps at `profile`
- an **unverified** transcription of a body-region limits table caps at `community`
- only a **field or bench** trace against **measured** figures reaches `validated`
- `certified` is not reachable from a file at all

You cannot pass a tier in. That is deliberate: a tier a caller can assert is a
tier that will be asserted.

## Body-region limits

This package ships **no** power-and-force limit values. They belong to the
standards body, they are revised, and a notified body may require a specific
edition or a project's own biomechanical study. `examples/machine/limits.template.json`
is the schema. Fill it from your licensed copy, then:

- set `verified_by` and `verified_on` once somebody competent has checked the
  transcription — until then every PFL pass is capped at `community` and the
  bundle says so in words
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
   tier, no file holds `certified`, the validation state and confidence are
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
