# The public-source pipeline, in the order an operator runs it

From a public vulnerability record to a machine passport, as one sequence of
`assurance` commands. Each piece has its own guide (`WATCH.md`, `CHANGE.md`,
`MACHINERY.md`, `ATTEST.md`); this page only fixes the order, the exit codes,
and who has to act. Nothing here is new behaviour.

The sequence is run end to end by `tests/test_pipeline_public_source_to_passport.py`
as real `python -m assurance` subprocesses over files in a temp directory, with
a `sitecustomize` that makes any socket connect raise. That test uses the
recorded or synthetic payloads in `tests/fixtures/intel/`, so the one networked
step (`intel refresh --live`) is **not** exercised by it.

## The sequence

| # | Command | Who | Network | Exit codes |
|---|---|---|---|---|
| 1 | `assurance intel refresh --source kev\|nvd\|epss --store intel.db --live [--cve ID]` | scheduler | yes, the only step | `0` done (an `unchanged` re-observation is done); `1` an input was rejected (recorded as a rejected observation); `2` could not run, including no `--live` |
| 1b | `assurance intel ingest --store intel.db --nvd F --csaf F --kev F --epss F` | a person or a job | no | as above. For files you already hold; the same store |
| 2 | `assurance watch run watch.json --ledger evidence.db` | scheduler | no | `0` quiet; `1` something new or changed for a person to read; `2` DEGRADED: a source or store could not be relied on, including a stale one |
| 3 | `assurance watch open-case --config watch.json --ledger evidence.db --advisory-id nvd:CVE-… --actor NAME --role ROLE` | **a named person** | no | `0` opened, or already open (nothing written); `1` refused (no named person, not a current finding, unsigned import without `--accept-unsigned` and a `--reason`, case already settled); `2` usage or I/O |
| 4a | `assurance change claim CASE --owner NAME --actor NAME` | a person | no | `0`; `1` a transition was refused; `2` could not run |
| 4b | `assurance change advance CASE --actor NAME` (twice: to `awaiting_action`, then `awaiting_reverification`) | a person | no | as 4a |
| 4c | the change itself, made on the machine; then `assurance machinery record-change --ledger evidence.db --actor NAME intervention.json` | a person (the technician) | no | `0` sealed; `2` error |
| 4d | `assurance machine verify … --subject MACHINE_KEY --ledger evidence.db`, then `assurance change reverify CASE --manifest M --verification-hash H --actor NAME` | a person | no | `0` accepted; `3` recorded but cleared nothing (the `blocked:` line says why); `1` refused; `2` could not run |
| 4e | `assurance change decide CASE --disposition closed --reason TEXT --actor NAME` | **a named decider** | no | `0`; `1` refused (not `ready_to_close`, or not a named person) |
| 5 | `assurance machinery passport --ledger evidence.db --actor NAME manifest.json --out passport.json`, then `assurance machinery check --ledger evidence.db passport.json` | a person; the check can be anyone | no | passport: `0` covered, `1` gaps, `2` error or the chain does not verify, `3` covered only on declared-provenance evidence; check: `0` matches the records it names, non-zero otherwise |
| 6 | `assurance change export CASE --ledger evidence.db --out case.json`, then `assurance evidence verify case.json` and `assurance art14 --ledger evidence.db verify` | anyone | no | evidence: `0` verified, `1` does not verify, `2` unreadable, `3` no inconsistency found but something asked for is not established; art14: `0`, `1` finding, `2` usage |
| 7 | `assurance attest keygen --out KEY.pem` (once, on the signer's host), then `assurance attest sign --ledger evidence.db --key KEY.pem --log attest.jsonl` for one ledger, or `assurance attest anchor-all --data-dir DIR --key KEY.pem` for a hosted data directory (`tenants/acc_<16 hex>.db`, logs in `attestations/`) | the key holder | no | sign: `0`, `1` finding, `2` could not run, `3` torn log; anchor-all: `0`, `1` a ledger was refused or showed an anomaly, `2` an error |
| 8 | `assurance art14 --ledger evidence.db verify --attestations LOG --public-key KEY.pub`; `assurance change export CASE … --attestations LOG --skeleton`, then `assurance evidence verify BUNDLE --public-key KEY.pub --attestations LOG` | anyone holding the public key from another channel | no | art14: `0` or `1` (a ledger shorter than its signed head fails); `2` if no key is given. evidence: as in step 6 |

`watch run` and `watch open-case` only read the store; they never fetch and
never refresh it. A refresh job that stops looks like a quiet week, so give the
subscription `"max_age_hours"` a little above the refresh interval (see the
staleness section of `WATCH.md`): a store older than that makes the run exit
`2` with `stale`. Without it, age is not checked and the run says so.

## The human acts

Software drafts and reports; these are people's acts, enforced in the domain
layer, not by convention:

* **Opening a case from a public record** (`watch open-case`). An empty name or
  one automation goes by (`automation`, `watch`, `system`, …) is refused with
  nothing written. The case records `unauthenticated_public_source` and who
  accepted it. A CSAF-derived candidate is an unsigned import and also needs
  `--accept-unsigned` and a non-empty `--reason`. A second person re-running it
  changes nothing and does not become the accepting person.
* **Claiming and advancing** a case, **recording an intervention**, and
  **submitting the re-verification**.
* **Closing** (or rejecting, or deferring). `change decide` refuses any actor
  that is not a named person, and refuses while work is outstanding. A
  re-verification can bring a case to `ready_to_close`; it never closes it.
* **Pinning a supplier key, awareness, the Art. 14 track and case closure** are
  likewise decisions; `WATCH.md`, `SUPPLIER.md` and `CHANGE.md` say how.

A person is a name on the command line. The ledger records that name as
declared; nothing here proves who typed it.

## What each step prints that it did not establish

The commands say so themselves, and the test pins the wording:

* `intel show --cve`: KEV *not listed* does not establish that a CVE is not
  exploited; EPSS with no score is `unavailable`, not 0.
* `watch run`: findings from a public store are `NOT TRUSTED` and inspect-only;
  no match is not "the fleet is unaffected"; a bounded version range is not
  matched; the run opens no case and drafts no filing.
* `watch open-case`: the advisory is not shown genuine; a listed machine is not
  shown affected, and an unlisted one is not shown unaffected; nothing has been
  verified, fixed or accepted.
* `change show`: the case's own "not established" list.
* `machinery passport`: the manifest is not confirmed complete.
* `evidence verify` (unsigned): completeness was not checked. With a signed head
  but no skeleton the result is exit `3`, not a pass.
* `art14 verify` (no attestation log): a self-recomputable chain detects
  accident, not a determined insider.

## What this pipeline does not establish

* That any public record, vendor advisory, KEV entry or EPSS score is correct,
  complete or current. A fetch that succeeded is a record of what a host said at
  that time.
* That a machine is affected or unaffected. Matching is on the labels in a
  sealed manifest (exact supplier, name and version strings); a different
  spelling, or a range the model cannot represent, is not matched.
* That a verification reflects physical reality. A verification shows a recorded
  run stayed inside a declared envelope, and at `validated` that a recorder key
  on the verifier's own trust list signed those bytes. It does not show the
  recorder, the envelope or the machine is what it claims.
* That a closed case means the machine is safe. `closed` means a named person
  decided it, for the reason they wrote.
* That a passport or any bundle is complete. Completeness needs a signed head
  from a key obtained outside the bundle, and the ledger it was read from;
  an anchor covers nothing appended after it.
* That the person named on a command is that person.
* Anything about legal or regulatory status. Nothing in this sequence decides it,
  and no step says a machine, a filing or an organisation complies with
  anything.

## Payload integrity

An intel store payload is looked up by its recorded SHA-256 and is re-hashed
every time it is read. A payload that no longer hashes to its key, including a
change that leaves it valid JSON, is treated as unreadable: the watch run is
DEGRADED (`unreadable`, exit `2`) and nothing is assessed from it. The test
`test_a_payload_bit_flip_that_stays_valid_json_is_degraded` pins this. The store
is a cache of public facts and is not hash-chained or signed, so it does not
show that a payload and its recorded observation row were replaced together:
re-create a store you did not write yourself from the source.
