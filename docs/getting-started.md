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

`pip install -e '.[assurance-attest]'` also works, but it installs all 22 core
dependencies of the NeuralBridge middleware project (fastapi, sqlalchemy, asyncpg,
redis, tiktoken, ...) as well; the extra adds nothing, because `cryptography` is already
one of the 22 core dependencies. The hosted API
below needs its own extra, `.[assurance-api]`, and that one is a real install.

## The free path: the offline enrolment kit

```bash
python -m assurance kit init plant/
python -m assurance kit check plant/kit.json   # reads only — the report your IT department signs off on
python -m assurance kit run  plant/kit.json --out plant/out
```

You get `plant/out/report.html`, `plant/out/evidence.db`, and
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
- [Deploying](assurance/deploy.md) — Fly.io and Stripe in test mode first;
  nothing in this repository has been deployed.
