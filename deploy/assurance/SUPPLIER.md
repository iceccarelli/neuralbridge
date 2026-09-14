# The supplier side — signing the other half of the market

## The attack nobody has closed

A component advisory reaches an integrator today as a PDF attached to an email,
or a link in a newsletter. Nothing about it is verifiable. Which means this
works:

```
From:    security@controlco-support.example
Subject: URGENT — safety controller firmware 3.9.0 advisory
Body:    Action required within 24 hours. Flash the attached image on all units.
```

An integrator who acts on that has been induced to modify the safety system of a
machine people stand next to. That is not a data breach with a notification
attached — it is a physical safety incident delivered by email. The industry's
present defence is that the recipient recognises the sender's writing style.

Signing closes it, and the reason it is not already done everywhere is not that
it is hard. It is two commands.

## For a component supplier

```bash
assurance supplier keygen --out psirt-key.pem
```

```
publishing key 759448e260ca239c
  Give your customers this fingerprint:

      759448e260ca239c
```

**That fingerprint is the entire security model.** Put it where customers find
it *without following a link from an advisory*: the contract, the quotation, the
machine's documentation folder, the back of the CE plate. Read it aloud on the
phone. A forged advisory will happily carry its own key.

Then, for each advisory:

```bash
assurance supplier publish CTRL-2026-11.json \
    --feed psirt-feed.jsonl \
    --key psirt-key.pem \
    --identity identity.json
```

Serve `psirt-feed.jsonl` from any web server. It is a text file, one JSON record
per line, so a customer can also copy it onto a USB stick and carry it into a
plant with no network — and read it without this software installed.

### Publish the hashes

An advisory that names versions matches by **label**. An advisory that names
content hashes matches by **artefact**. The difference, on a real fleet:

| | what the integrator is told |
|---|---|
| versions only | *possible* — "this is your component, but the version on this machine is not recorded. Somebody has to look." |
| with hashes | *affected* — by hash, beyond argument. Or `hash_mismatch`, which is the finding nobody else produces: the label says 3.9.0 and the bytes are not 3.9.0's. |

Publishing the hashes is the single most useful thing a component supplier can
do for the people who install their parts, and `publish` says so every time you
omit them.

### Getting one wrong

```bash
assurance supplier withdraw CTRL-2026-11 \
    --reason "the affected version range was wrong; 3.9.0 is not affected" \
    --feed psirt-feed.jsonl --key psirt-key.pem --identity identity.json
```

**The original stays in the feed.** Your customers changed machines because of
it; deleting it leaves them holding a change nobody can explain, which is worse
than the wrong advisory was. A withdrawal is a publication.

## For an integrator

```bash
assurance supplier verify \
    --feed psirt-feed.jsonl \
    --public-key controlco.pub \
    --expect-supplier controlco
```

Then fan it across every machine you have enrolled:

```bash
assurance fleet advisory \
    --feed psirt-feed.jsonl \
    --supplier-key controlco.pub \
    --expect-supplier controlco \
    --ledger evidence.db
```

`fleet advisory` **refuses** a feed that does not verify. Not a warning — a
refusal, exit 2, nothing computed. A change to a safety system driven by an
advisory that does not verify is precisely what signing is for. `--unsigned-anyway`
exists, prints the reason in full, and records it in the output, because
sometimes you have to proceed and everyone downstream should know you did.

## Why the feed is a chain

Each record names the content hash of the one before it.

**A supplier cannot silently un-publish.** The commercial incentive on a supplier
who has published an embarrassing advisory is to make it go away. Remove a
record and the chain breaks at a named position, in every copy every customer
already holds.

**An empty feed does not verify.** A wrong path and a supplier with nothing to
report look identical, and "your fleet is unaffected" is the worst possible
wrong answer to give somebody who is exposed. The tool refuses both rather than
guessing which it was.

**One feed, one supplier.** An integrator pins one key to one feed; two
suppliers sharing a file makes that pinning meaningless.

## What a verified feed does not establish

Carried in `checks_skipped` on every verdict, and printed by the CLI:

1. **That the key belongs to the supplier.** Cryptography cannot bootstrap this.
   The fingerprint must arrive by a route the advisories do not travel on. This
   is the one thing the reader has to do themselves, and the tooling prints the
   fingerprint everywhere precisely so that it is easy.
2. **That the advisories are correct, complete, or timely.** A verified feed says
   these came from the holder of that key and were not altered. A supplier who
   has not noticed a vulnerability publishes nothing, and no amount of signing
   detects silence.
