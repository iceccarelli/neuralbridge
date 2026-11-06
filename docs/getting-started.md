# Getting started

Every command below is checked against this repository's own CI (the
"Offline kit, from a bare checkout" job runs this exact sequence on a fresh
Python 3.11/3.12/3.13 install on every push) — not hand-typed and hoped for.

## Install

```bash
git clone https://github.com/iceccarelli/neuralbridge.git
cd neuralbridge
python -m venv .venv && source .venv/bin/activate
pip install cryptography        # the one third-party package the offline kit imports
export PYTHONPATH=src           # run from this checkout; nothing else is installed
```

`pip install -e .` from the checkout also works, and is just as small: the base install of
this project is `cryptography` and nothing else (`.[assurance-attest]` is the same install, kept so
existing commands keep working). The hosted API below needs its own extra,
`.[assurance-api]`; the NeuralBridge integration platform needs `.[platform]`. The README's
Install table lists every extra and what it adds.

## The free path: the offline enrolment kit

```bash
python -m assurance report demo --out demo/    # see a worked report first: nothing to edit (synthetic machines)
python -m assurance kit init plant/            # a skeleton: edit kit.json and plans/cell.json
python -m assurance kit check plant/kit.json   # names the placeholders left; reads only — what your IT department signs off on
python -m assurance kit run  plant/kit.json --out plant/out
```

`kit check` and `kit run` exit 2 while template values remain (`kit run` refuses to produce evidence with them). Once
they are replaced and your exports are in place, you get `plant/out/report.html`, `plant/out/evidence.db`, and
`plant/out/attestation-request.json`. The run arms a guard over the
process's own socket layer, refuses every outbound connection — including
name resolution — and seals a record of any attempt into your own ledger.

## Run the API

```bash
pip install -e '.[assurance-api]'
uvicorn assurance.api.service:app --port 8000
# http://127.0.0.1:8000/docs
```

`GET /v1/plans` returns the pricing table generated from the entitlements
the software enforces — the same table on [Pricing](pricing.md) and on
[neuralbridge.io](https://neuralbridge.io/#pricing).

## See a full worked example

```bash
python -m assurance report demo --out demo/
```

Builds a worked fleet — real collection, real normalisation, real findings —
and writes `demo/report.html`, a self-contained page with no scripts and no
network calls.

## Next

- [Assurance engines](assurance/index.md) — what each command establishes,
  and the finding nobody else produces.
- [The operator pipeline](assurance/pipeline.md) — a public vulnerability record
  to a machine passport, in the order an operator runs it.
