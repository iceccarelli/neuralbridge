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

The head comparison and the removal happen under the ledger's own writer lock
(`BEGIN IMMEDIATE`, the lock every API append takes), taken BEFORE the head is read and held
across every unlink. A record the API appends at the last moment therefore either lands before
the comparison (the head differs: refused with "export again", nothing removed) or cannot land
at all. Before the lock is released an `INSERT` trigger is committed to the ledger so that a
writer that was already waiting for the file fails instead of being told "stored" while writing
into an unlinked file. If the lock cannot be taken (a writer is busy) the command exits 2 and
removes nothing.

It then writes the deletion marker (below) and unlinks exactly: the tenant ledger, its
`-wal`/`-shm`/`-journal` if present, the attestation log, and the log's `.lock`, each by exact
name. No recursive delete and no glob. Finally it appends a `tenant.deletion` entry to the
operator ledger: account id, deletion time and actor (from the real clock and the `--actor`
of the delete, never from the export), the export manifest's sha256, and the head hash, record
count and ledger id that `verify-export` compared with the copied ledger (each re-checked for
type and length), plus the names and sizes of the removed files. Nothing else is copied out of
the manifest: its `exported_at` and `actor` are unbound text and are not read. The tombstone
contains no customer record contents. If the tombstone cannot be appended after the files are
gone, the command exits 2 and prints what to record by hand. If an unlink fails after the
marker is written the command exits 2 with "THE DELETION IS INCOMPLETE": the API already
refuses the account; finish by hand and record it.

A second run reports `already removed` (exit 1) and changes nothing. The plan tells the cases
apart: `already removed` means the deletion marker exists (it shows when and by whom);
`no such account data on this host` means no file and no marker, i.e. the id never existed
here or is wrong.

### The deletion marker and what the API does

`--execute` leaves `tenants/<acc>.deleted` (mode 0600; JSON with the account id, time, actor and
the export manifest's sha256, no customer data) where the ledger was. While it exists:

* every API route that opens the account's ledger answers **410**
  `{"error": "account_data_deleted", "detail": "this account's ledger was removed by an operator
  on <date>; contact the operator"}`, decided before any ledger is opened, so the ledger is
  never silently recreated empty under a new ledger id. The key still authenticates (401/402
  behave as before for everyone else, and the operator account is unaffected);
* `attest anchor-all` skips and reports the account (and never creates a ledger or log for it).
  A ledger file that reappears under a marker is reported as an anomaly (exit 1), not anchored;
* `tenant export` of the account is refused ("already removed").

There is no command to undelete. An operator lifts the marker only by deleting the file by hand
(for example after restoring the ledger from a backup); the next request opens whatever is at
the ledger path. A symlink or unreadable marker also counts as present.

The marker does not close the account: `accounts.db`, the API key, billing and Stripe are still
operator steps (close the subscription, revoke the keys) done outside this tool.

A ledger whose chain is broken can be offboarded only from an export taken with
`--accept-damaged` and with `--accept-damaged` repeated on `delete`.

The export directory is opened once without following links (`O_DIRECTORY|O_NOFOLLOW`) and
every file is created relative to that open directory, so swapping the path for a symlink
afterwards cannot redirect the export. (Where `/proc/self/fd` does not exist the export only
verifies at the end that the path is still the directory it opened.)

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
