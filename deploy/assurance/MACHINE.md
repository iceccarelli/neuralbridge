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

Ask an integrator what their scanner is set to. It is very often under 1500 mm.
The gap is usually C, Zd and Zr — the three terms most often left out — plus Sh
being computed over the stop time alone instead of reaction + stop.

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

Three separate things are checked and the caller is told which failed:

1. the sealed evidence hashes to the hash it carries — catches post-seal edits
2. the recorded verdict agrees with the bundle's own check outcomes
3. with the original envelope and trace supplied, re-running the engine
   reproduces the same verdict and tier

Supplying neither envelope nor trace returns `ok` **with** a stated limitation,
never a clean pass: integrity alone does not make a claim true.

## Regulatory context

Machinery Regulation (EU) 2023/1230 applies from **20 January 2027**. Annex III
1.1.9 requires a machine to identify its safety-relevant software and to record
evidence of intervention. Article 14 of the CRA has applied since **11 September
2026**. The register in `assurance.security.art14` answers the paperwork
question; this package answers the question underneath it.
