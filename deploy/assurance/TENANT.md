# Tenant export and offboarding (operator runbook)

`python -m assurance tenant export | verify-export | delete`. Operator tooling that runs on the
host with the data volume. It is not an HTTP route and not an MCP tool, it opens no socket, and
it never reads `accounts.db`, so no API key, key hash or billing identifier can enter an export.

This is the procedure the tooling supports. It is not a statement that any law, contract or
standard is satisfied by following it.

## What the product does and does not do about retention

The product deletes nothing automatically: no timer, no expiry, no cleanup job. How long a
customer's ledger, attestation log, backups and exports are kept is the operator's policy, to be
decided and written down by the operator. The only code path that removes a tenant's files is
`tenant delete --execute`, below, and it runs only when a named person asks for it.

## Layout it works on

    <data-dir>/tenants/acc_<16 hex>.db            the tenant ledger (+ -wal, -shm, -journal)
    <data-dir>/attestations/acc_<16 hex>.jsonl    the account's signed attestation log
    <data-dir>/attestations/acc_<16 hex>.jsonl.lock   its flock file
    <data-dir>/art14-register.db                  the OPERATOR ledger (receives the tombstone)

The account id must match `acc_[0-9a-f]{16}` exactly; anything else is refused before the
filesystem is touched. Symbolic links (the file, a sidecar, or the `tenants/` and
`attestations/` directories) are refused, never followed.

## 1. Export

    python -m assurance tenant export --data-dir /data --account acc_0123456789abcdef \
        --out /secure/exports/acc_0123456789abcdef-2026-11-01 --actor "Maria Example"

* The chain is verified in full first. A broken chain is refused (exit 1, nothing written).
  `--accept-damaged` keeps a record of the damaged state anyway; the manifest then says
  `accept_damaged: true` and `verify.status: damaged_accepted`, and no evidence bundle is
  written (a bundle asserts a verified chain).
* `--out` must be new or empty, and not inside the data directory. It is created `0700`; files
  are `0600`.
* Written: `ledger.db` (a consistent snapshot, WAL included), `evidence-bundle.json` (the whole
  ledger as an export bundle), `attestations.jsonl` (if the account has a log; copied under the
  log's lock), `VERIFY.txt`, and `MANIFEST.json`: account id, ledger id, record count, head
  hash, sha256 and size of every file, export time, actor, the verify result, `not_included`
  and `does_not_establish`.
* The bundle covers the whole ledger, so every record is in it; a skeleton (needed only for a
  subject-scoped bundle) is not.

Keep the printed manifest sha256 (`sha256sum MANIFEST.json`) somewhere other than the export:
the manifest itself is not signed.

## 2. Verify an export

    python -m assurance tenant verify-export /secure/exports/acc_0123456789abcdef-2026-11-01

Re-hashes every file against the manifest, rejects missing and unlisted files, re-verifies the
hash chain of the copied ledger (on a private temporary copy, so the export's bytes do not
change), compares record count, head and ledger id with the manifest, and verifies the bundle.
Exit 0 verified; 1 mismatch or damaged; 2 could not run; 3 unchecked (no manifest).

A third party without this software can use `VERIFY.txt`: `sha256sum` against the manifest, then
`python -m assurance evidence verify evidence-bundle.json --attestations attestations.jsonl
--public-key service.pub` (the public key obtained from the operator separately).

## 3. Offboarding and deletion

Before deleting, outside this tool and by the operator:

1. Close or cancel the account in the billing system. `tenant delete` never opens `accounts.db`
   and never contacts Stripe: `AccountStore` can end a manual grant, but an account that came
   from Stripe is closed by a billing event, and closing one here would diverge from Stripe.
2. Make sure the account can no longer write (its keys are revoked), so the ledger does not grow
   between export and deletion.
3. Decide what happens to backups and exports (see "Not removed").

Then:

    # a PLAN: prints exactly what would be removed and what would not; writes nothing
    python -m assurance tenant delete --data-dir /data --account acc_0123456789abcdef \
        --backup-dir /backups/latest

    # the removal
    python -m assurance tenant delete --data-dir /data --account acc_0123456789abcdef \
        --execute --confirm-account acc_0123456789abcdef \
        --export /secure/exports/acc_0123456789abcdef-2026-11-01 --actor "Maria Example"

`--execute` is refused (exit 1, nothing removed) unless all of these hold:

* `--confirm-account` repeats the id;
* `--export` passes `tenant verify-export`, is for this account, and its head hash and record
  count equal the ledger's NOW. If the ledger grew, the message says to export again;
* `--actor` is a named person (the rule the enrolment and change workflows apply; names such as
  `automation` or `bot` are refused);
* the operator ledger exists (it is never created here) and its chain verifies;
* the account's attestation-log lock can be taken, so a running `attest anchor-all` is not raced
  (otherwise exit 2, nothing removed).

It then unlinks exactly: the tenant ledger, its `-wal`/`-shm`/`-journal` if present, the
attestation log, and the log's `.lock`, each by exact name. No recursive delete and no glob.
Finally it appends a `tenant.deletion` entry to the operator ledger: account id, time, actor,
the export manifest's sha256, head hash, record count, ledger id and the names and sizes of the
removed files. It contains no customer record contents. If the tombstone cannot be appended
after the files are gone, the command exits 2 and prints what to record by hand.

A second run reports `already removed` (exit 1) and changes nothing.

A ledger whose chain is broken can be offboarded only from an export taken with
`--accept-damaged` and with `--accept-damaged` repeated on `delete`.

### Not removed

* **Backups.** `restore_check backup` copies the whole volume; every backup taken before the
  deletion still holds the tenant ledger (and `accounts.db`). Pass `--backup-dir` to the plan to
  list this account's files in one backup directory; disposing of backups is the operator's
  act.
* **Exports**, including the one used for the deletion.
* **`accounts.db`**, billing records and Stripe objects.
* **The operator ledger**, which only gains the tombstone.

### What a deletion does not establish

* That no copy exists elsewhere (backups, replicas, exports, logs, the customer's own copies).
* Storage-level remanence: files are unlinked, not overwritten.
* That the person named as actor was authorised; the name is recorded as given.
* That any legal or contractual obligation is met.

## Exit codes

0 done / verified; 1 refused, or the export mismatches or is damaged; 2 could not run (usage,
I/O, busy lock, no operator ledger); 3 `verify-export` only: no manifest, so unchecked.
