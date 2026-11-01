# Assurance engines

Every row below maps to code that runs — verified in this repository's own
`pytest tests/ -q` suite and the cold-start CI job that installs from
a bare checkout and runs the offline kit end to end.

| Engine | Command | The finding nobody else produces |
|---|---|---|
| [Collect](collect.md) | `assurance collect probe` | Finds the vendor tool's own volatile headers before they produce a year of false drift alarms |
| [Machine safety](machine.md) | `assurance machine verify` | ISO/TS 15066 separation with `Sh` over `Tr + Ts`; `unchecked` is a first-class outcome |
| [Machinery Annex III](machinery.md) | `assurance machinery coverage` | The staleness join — a sign-off from before a change, dated against the change itself |
| [Fleet advisory](fleet.md) | `assurance fleet advisory` | `HASH_MISMATCH` — a label that contradicts the bytes on the machine, reported as exactly that |
| [Change assurance](change.md) | `assurance change assess-drift` | A change is a case with an owner and a re-verification, closed only by a named person's decision; closure is never inferred |
| [Public-source intelligence](intel.md) | `assurance intel history` | A CVE no recorded source mentions is `unknown`, never clear; hosted routes read the operator's store and answer 503 until one is configured |
| [Watch](watch.md) | `assurance watch run` | Exit 0 quiet, 1 findings, 2 could not see — "I could not look" never shares a code with "nothing moved" |
| [Attest](attest.md) | `assurance attest sign` | A hash chain catches editing; a counter-signature is what catches deletion |
| [Key ceremony](key-ceremony.md) | `assurance attest keygen` | Prepared, not performed: the procedure for the two trust anchors, and the evidence to keep |
| [Offline kit](kit.md) | `assurance kit run` | One command inside the plant — their ledger, their disk, a socket guard that proves nothing left |
| [Supplier feeds](supplier.md) | `assurance supplier publish` | A supplier cannot silently un-publish; a withdrawal is a publication, not a deletion |
| [Bridge](bridge.md) | `assurance bridge` | Field 5 (Member States) assembled from serial numbers, never guessed |

The order an operator runs these in is [the operator pipeline](pipeline.md); the
two trust variables a hosted deployment lacks are in the
[trust runbook](trust-runbook.md). Which of the CLI, API and MCP offers each
capability is generated from the code on the on-site `/docs/capabilities` page.
See [Deploying](deploy.md) for the hosted API version, rehearsed in test mode
first: nothing here has been deployed.
