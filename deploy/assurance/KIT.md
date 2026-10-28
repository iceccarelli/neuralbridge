# The enrolment kit — the thing you actually send a prospect

## What it is for

Everything else in this package assumes somebody has already decided to adopt
it. This is what runs *before* that decision.

A plant engineer copies a folder onto a machine that is already inside their
network, edits two files (`kit.json` and `plans/cell.json`), drops their exports in a folder, and runs one command. They get back a sealed evidence
ledger, an HTML report and an attestation request — **their** ledger, **their**
data, on **their** disk. No account. No API key. No upload. Nothing to procure
and nothing for security to review, because nothing left the building.

That last part is the whole reason this exists. The blocker on every industrial
pilot is not price and it is not features: it is the eleven weeks it takes to
get an unknown tool past a plant's IT department. This kit does not ask to be
let through. It runs on the inside and proves it stayed there.

## The three commands

```bash
python -m assurance kit init plant/            # write a runnable kit
python -m assurance kit check plant/kit.json   # what it would touch. Reads only
python -m assurance kit run  plant/kit.json --out plant/out
```

`check` is the command to put in front of whoever has to approve this. It reads
the configuration and the collection plan, lists every file the run would open,
names every plan item that matches no file, and touches nothing. Give them that
output before you ask for anything.

While template values remain, `check` still only reads: it names **every** one at
once, by file and field (`plans/cell.json still has CHANGE ME placeholders:
manufacturer, model, supplier of ITM-ZONES, ...`; `kit.json still has template
values: organisation=..., prepared_by=...`), and with `--json` returns them as
`placeholders` (`file`, `field`, `value`) beside `ready: false`. It exits `2` while
`kit.json` itself cannot be loaded (a template value there), and `1` once only the
plan or the exports are not ready.

`kit init` and the README it writes list the same four steps (they are one list in
the code): edit `kit.json`, edit `plans/cell.json`, drop the exports in, run
`check`.

Exit codes are the interface:

| code | meaning |
|-----:|---------|
| 0 | every machine enrolled, nothing tried to reach the network |
| 1 | a **finding** — a machine incomplete, a required item missing, a refused connection attempt. Evidence was still produced. Read it |
| 2 | the kit could not run |

A refused connection attempt is a 1, not a 2, deliberately: the run is still
valid — nothing got out — but somebody needs to know which line tried.

## The airgap guard

Every vendor selling software that runs inside a plant says "it works offline,
nothing leaves your network". Plant IT has heard it before, cannot check it, and
correctly treats it as worth nothing.

This run arms a guard over the process's socket layer, refuses every outbound
connection, records any attempt **with the line of code that made it**, and
seals that record into the customer's own ledger. Afterwards, "did this tool
send anything anywhere" has an answer with a hash on it, in a file the customer
holds. That is a different kind of object from a bullet point on a datasheet.

What the guard covers, stated precisely because a security reviewer will ask and
a vague answer is worse than a narrow one:

* It covers outbound connections made by this Python process through the
  `socket` module — `connect`, `connect_ex`, `create_connection`, `sendto`, and
  name resolution via `getaddrinfo`. Every Python HTTP and TLS client goes
  through that layer. Resolution alone is refused too: a tool that resolves a
  name has already told a DNS server something, which is exactly what a network
  team is asking about.
* It does **not** cover a subprocess, which has its own socket layer. The kit
  spawns none.
* It does **not** cover a C extension that opens a socket file descriptor
  without going through the `socket` module.
* It records **intent**, it does not enforce containment. Code determined to
  evade it could. Containment is a firewall's job, and the plant already has
  one. This answers whether the tool tried.

Those four sentences are in the evidence record and printed in the report. A
claim next to its limits is worth more to a reviewer than a broader claim with
none.

One implementation detail that is a decision, not an accident: the refusal is
**not** an `OSError`. Every HTTP client catches `OSError` and treats it as a
transient failure — it would retry three times, or fall back to a cache and
carry on as though nothing happened. A refusal here is not a network problem and
must not be mistakable for one, so it travels up through every library's error
handling untouched and stops the run.

## What the run writes

```
out/report.html                 open this first
out/evidence.db                 their ledger. Back it up like a drawing
out/run.json                    machine by machine, what was recorded
out/attestation-request.json    three numbers, for later
```

The order inside a run is fixed and each step is there for a reason:

1. Collection and sealing happen **inside** the guard.
2. The airgap record is sealed **after** the guard releases, because a record of
   a guard cannot be written while the guard it describes is still running.
   That sentence is in the record.
3. The run record is sealed **before** the head is read, so the attestation
   request covers it. A head taken before the last append is stale the moment it
   is written, and an attestation of a stale head looks like coverage and is
   not.

## Refusals that exist to protect a document nobody has written yet

The kit refuses to run when `organisation`, `prepared_by` or `site` still hold
a starter template value, and when the collection plan still says
`manufacturer: "CHANGE ME"`. Those values are printed at the top of a report
that goes to an auditor, an insurer or a customer, and a manifest carrying a
template manufacturer cannot be matched to a supplier advisory later. Better to
stop here than to produce a document addressed from nobody about a machine made
by nobody.

## Closing the loop: the counter-signature

`attestation-request.json` holds exactly three numbers and a note:

```json
{
  "ledger_length": 412,
  "head_seq": 412,
  "head_link_hash": "9f2c..."
}
```

POST that to `/v1/ledger/attest` with a Cell-plan key and the head is
counter-signed by a key the plant does not hold. The ledger never moves. See
`ATTEST.md` for what that buys and what it does not.

Then, back inside the plant and still offline:

```bash
python -m assurance attest verify \
    --log attestations.jsonl \
    --public-key counter-signer.pub \
    --ledger out/evidence.db
```

That command is what makes the whole thing worth having: the customer's own
administrator can no longer quietly shorten the ledger, because the removed
records were counted in a statement signed by a key nobody there holds.

## What the hash label on each item means

A folder of exported files cannot show which machine, if any, it came off. So the
kit labels every item `supplied_by_vendor` by default: the digest says what the
export holds, the manifest's tier ceiling is `community`, and the report prints
`tier ceiling community`, not `validated`. The change workflow
(`assurance.machinery.manifest.not_a_look`) and hosted watch ingest treat a
manifest like that as *not a look at the machine*: it cannot be the as-found
manifest that a re-verification stands on.

If the kit really ran **on the machine** (its exports were taken by this process
from the unit itself, not handed over), say so:

```bash
python -m assurance kit run plant/kit.json --out plant/out --read-from-machine
python -m assurance collect run PLAN --root DIR --serial S --actor A --read-from-machine
```

The items are then labelled `read_from_machine`. That flag is **the operator's
assertion**. Nothing in a folder of files proves it and this software cannot
check it, so the assertion is written into each manifest (`method` and every
item's `notes`: `OPERATOR ASSERTION ...`), into `run.json`
(`read_from_machine_asserted`), and into the report's limits. An `--as-declared`
baseline cannot carry it: a baseline built from a release is not a machine. A
`watch` target takes the same assertion as `"read_from_machine": true` in its
entry in the watch configuration; absent, it is false.

## Keeping going after the first run

`out/evidence.db` is an ordinary evidence ledger; later steps append to it, and
`coverage` reads from it. `coverage` takes the manifest as a file, so write one with
`collect run` (`--out manifest.json`, with the same plan, root and serial the kit
used):

```bash
python -m assurance machine verify --envelope env.json --trace trace.json \
    --actor a.rossi --ledger plant/out/evidence.db --subject "Maker/Model#SERIAL"
python -m assurance machinery record-change intervention.json \
    --ledger plant/out/evidence.db --actor a.rossi
python -m assurance machinery coverage manifest.json --ledger plant/out/evidence.db
```

The subject must be written **exactly** `manufacturer/model#serial`, as in the
manifest's machine identity: the plan's `manufacturer` and `model`, then the
machine's serial, e.g. `Acme/Scan-9#CELL-0412`. Coverage looks a verification up
under that key and ignores one filed under any other spelling, so a verification
filed as `AR-7 0412` is never seen. `machine verify --subject` prints a warning (to
stderr, nothing refused) when the subject is not a well-formed unit key, or when
the ledger holds no manifest under it.

## What one offline run does not establish

Printed at the end of every run and numbered in the report:

1. It recorded what was in the export folders at one moment. Nothing watches for
   the next change — a firmware update tomorrow strands every sign-off in this
   ledger and nothing says so until somebody runs it again. (`assurance watch`)
2. No supplier advisory was matched. A component with a published vulnerability
   appears in this manifest as an ordinary item. (`assurance fleet`)
3. The head is not signed. A hash chain detects editing, not deletion.
   (`ATTEST.md`)
4. No physical behaviour was verified. Nothing here says a machine stops in the
   distance its datasheet claims. (`assurance machine verify`)
5. Manifests were read from exported files, not from machines. They are
   labelled `supplied_by_vendor` (tier ceiling `community`), and the change
   workflow and hosted ingest do not accept such a manifest as a look at the
   machine. See the next section.

That list is the honest statement of the gap, and it is a better argument for
the paid product than any claim about it — every line names the thing that
closes it. A kit that pretended to cover them would be caught the first time it
mattered, which is the one time it cannot be.
