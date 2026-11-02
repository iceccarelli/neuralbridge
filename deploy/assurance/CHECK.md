# The Machine Assurance Check

One question, one answer: *what does this change mean for this machine?* The check composes
engines that already exist (advisory matching, the staleness join, the fleet fan-out) into one
verdict a person can act on, and says what it did not look at.

```bash
assurance check services                                   # what can be executed, and which is free
assurance check machine manifest.json --advisory advisory.json [--json]
assurance check fleet-machine --ledger register.db --machine-key 'Grimaldi/AR-7#0412' \
                              [--advisory advisory.json] [--recorder-trust trust.json] [--json]
```

These are the CLI faces of `GET /v1/check/services`, `POST /v1/check/machine` and
`POST /v1/check/fleet-machine`, and of the MCP tools `services`, `machine_assurance_check` and
`fleet_machine_assurance`. They call the same functions; `--json` prints the response body the
API returns for the same input. Inputs are JSON files, or `-` for standard input (one of them).
Nothing here writes: no ledger is created, nothing is sealed, nothing leaves the machine.

| Verb | Reads | Notes |
|---|---|---|
| `check services` | nothing | The service catalogue, with each service's input schema, whether it is free or paid and what the API does if you are not entitled. Needs `pydantic` (the schemas are generated from the request models); without it the command says so (exit 2). |
| `check machine` | the two files | The free path. One manifest, one advisory, **no ledger**: it can say whether the change matches this manifest, and cannot say whether standing safety evidence is still valid. |
| `check fleet-machine` | an existing ledger | The machine's own interventions and verification bundles, plus the fan-out across every other enrolled machine when an advisory is given. The ledger must exist (a mistyped path is an error, not an empty ledger) and the machine must be enrolled in it. |

## Verdicts and exit codes

The verdict is the API's: `requires_human_review`, `requires_reverification`,
`insufficient_evidence`, `potentially_affected`, `cannot_determine`, `no_impact_found`,
`verified_at_community`, `verified` (worst first). The exit code follows the other offline
verbs:

* **0** the check found nothing: `no_impact_found` or `verified`.
* **1** a finding: the change matches, a function needs re-verification, the evidence is
  insufficient, or a person must review.
* **2** it could not run or could not vouch: an unreadable, empty, non-JSON or invalid input; a
  ledger that does not exist or is not a ledger; a machine that is not enrolled; or a ledger
  whose hash chain does not verify and in which nothing was found. A broken chain can hide a
  record, never invent a match, so a match still stands as a finding; a result that found
  nothing is never called clear.
* **3** not established, never a pass: `cannot_determine` (the advisory is a partial translation,
  or there is nothing to read) and `verified_at_community` (every declared function is current,
  but on evidence below `validated`).

## What it does not establish

Every result ends with a `not established:` list (the API's `checks_skipped`). A clear result is
the answer to the question asked, from the inputs given: not a statement that the machine is
safe. A vendor advisory describes a product and its versions; it does not say what firmware a
particular customer's controller runs. That is what the manifest you supply claims, and the free
check takes the manifest at its word.

`--recorder-trust` is your own trust list for recorder attestations. Without it, as for the other
offline readers of your own ledger, the verification tier sealed with each record is believed.
The hosted API applies its server's list, or none, so for evidence that rests on a recorder
attestation pass the same list to get the same answer.

See also: [Fleet](FLEET.md) (`fleet advisory-check`, the stateless one-machine form without the
verdict vocabulary, and `fleet advisory`, the fan-out) and [Machinery](MACHINERY.md).
