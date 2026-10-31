# Key ceremony — creating, rotating, revoking and verifying the two trust anchors

Status: **prepared, not performed.** No production key exists, no deployment has either
variable, and nothing in this file has been done by the assistant or by CI. This is the
procedure the founder approves; the actions are the founder's (`CLAUDE.md`, "Authority").
`TRUST-RUNBOOK.md` explains what the two variables are; this file is the *workflow* and the
*evidence you keep*.

| capability on the Cell plan | needs | without it |
|---|---|---|
| counter-signed head attestation (`POST /v1/ledger/attest`) | `ASSURANCE_ATTEST_KEY_PEM` (or `ASSURANCE_ATTEST_KEY`, a path) | HTTP 503 `no_attestation_key_configured` |
| hosted `validated` verification | `ASSURANCE_RECORDER_TRUST` naming at least one recorder key, and a recorder who signs traces | every hosted trace is `community` |

Everything below uses commands in this repository. `python -m assurance attest …`:

| verb | does | exit |
|---|---|---|
| `keygen --out F [--public-out F.pub] [--json]` | Ed25519 pair; private file created `0600` exclusively; **refuses to overwrite** either file, or to sit beside the ledger; prints the public fingerprint, never the key | 0 / 2 |
| `sign … --key F` | refuses a key file readable by group or other (or a symlink) | 0 / 1 finding / 2 |
| `verify --log L --public-key P [--public-key P2 …]` | repeat `--public-key` to check a log that spans a rotation; every record must verify under the pinned key it names | 0 / 1 / 2 / 3 |
| `trust-list create \| add \| revoke \| list \| verify-file` | the recorder trust file, in exactly the format the server loads | 0 / 1 / 2 |
| `preflight [--key F] [--trust F] [--expect-fingerprint FP] [--must-be-revoked FP] [--require both\|counter-signing\|validated\|none] [--json]` | would each capability work *here*; prints the public fingerprint and what it did **not** check | 0 / 1 |

None of these is an HTTP route or an MCP tool, by design (`src/assurance/capabilities.py`:
key custody and verifier trust are not an agent's or a request's to change).

## 0. Rehearse first (staging; costs nothing; no real key)

```bash
python -m pytest tests/test_assurance_key_ceremony_rehearsal.py tests/test_assurance_attest_ceremony.py -q --no-cov
```

The rehearsal runs sections 2-5 below in a temp directory with throwaway keys, starts the real
API on a loopback socket, and shows: **not configured** → 503 and `community`; **configured** →
counter-signed head that verifies under the public key the ceremony wrote, and a `validated`
verification; **revoked** → back to `community`; **broken trust file** → fails closed. That
proves the software on invented inputs. It proves nothing about your key, host or customers.

For a staging *deployment*, repeat sections 2-5 with a separate throwaway key and trust list
and a separate account store. Never reuse a staging key in production, and never point a
staging service at the production trust list (`TRUST-RUNBOOK.md`, section E).

## 1. Decide before you generate

- **Who holds the key.** One named person accountable, plus the recovery arrangement you
  choose in section 3. Write both names in the decision record (section 9).
- **Custody option** (pick one; each is a trade, not a ranking):
  1. *Platform secret only* (e.g. `fly secrets set`). The key lives in the secrets manager and
     in the running process. Simplest. The platform operator and anyone with deploy rights can
     read it, so the counter-signature shows the head existed and that someone without that
     access could not have signed it, not that *you* could not.
  2. *Secrets manager + offline escrow.* As 1, plus an encrypted copy on removable media in a
     physical safe. Survives losing the platform account. The escrow copy is a second place the
     key can leak from.
  3. *Hardware token / KMS signing.* Not supported by this code today: the service reads a PEM
     key. Do not claim it.
- **Passphrase.** `--passphrase-env` encrypts the file. The service reads
  `ASSURANCE_ATTEST_PASSPHRASE` from its environment, so on the host the passphrase sits next
  to the key. It protects the escrow copy and a laptop, not the running service.
- **Recorder trust is server-wide.** Every account's evidence is judged against one list.
  Do not add a key for one customer's recorder unless the whole deployment may believe it.

## 2. Create the service key (operator's machine; not a shared session)

```bash
umask 077
python -m assurance attest keygen --out ./ceremony/attest-service.pem \
                                  --public-out ./ceremony/attest-service.pub
```

- Run it somewhere nothing records the screen or shell output beyond what you intend. It prints
  the 16-hex **public fingerprint** and the two paths. It never prints the key; if you ever see
  `BEGIN PRIVATE KEY` in a terminal, a log or a chat, treat the key as burned and start again.
- It refuses to run if either file exists. That is deliberate: replacing a key is a rotation
  (section 6), not a re-run.
- **Write the fingerprint down in a place the service does not control** (your site, a signed
  email, a letter) *before* deploying. This is the second route a customer compares against.

## 3. Put the key where it belongs, then remove the local copy

1. Store it: `fly secrets set ASSURANCE_ATTEST_KEY_PEM="$(cat ./ceremony/attest-service.pem)"`
   (a deployment change: founder approval). The command above puts the key in your shell's
   process arguments for an instant; prefer your platform's stdin or file form where it has one.
2. **Backup.** Put an encrypted copy (`gpg --symmetric` or your password manager's secure
   note) where you will find it in a year. Lose the key and you can no longer extend the chain of
   signed heads under that identity; existing signatures still verify against the public key.
3. **Restore drill** (do this once, on throwaway data, before relying on the backup):
   decrypt the copy to a temp directory, `chmod 600`, then
   `python -m assurance attest preflight --key <restored.pem> --expect-fingerprint <FP>`
   must exit 0 for counter-signing. Delete the restored file.
4. Delete `./ceremony/attest-service.pem`. Keep `attest-service.pub`; it is public.
5. Keep the key **off the data volume** (`preflight` fails a key file that sits under the
   ledger or attestation-log directories).

## 4. Build the recorder trust list (only when a real recorder operator exists)

The recorder operator runs `attest keygen` **on their side**, keeps the `.pem`, and sends you
`recorder.pub` and, **by another route**, its fingerprint (spoken, signed letter). If anyone
sends a private key, do not use it: `trust-list add` refuses it unread and tells them it is burned.

```bash
python -m assurance attest trust-list create --trust ./config/recorder-trust.json
python -m assurance attest trust-list add    --trust ./config/recorder-trust.json \
    --public-key recorder.pub --label "Plant 2 line 4 recorder" \
    --provenance field --fingerprint <the fingerprint you were told>
python -m assurance attest trust-list verify-file --trust ./config/recorder-trust.json
```

- `--fingerprint` is mandatory: a key that does not hash to the value you were given is refused.
- `--provenance` is the narrowest set you will vouch for (`bench`, `field`). `simulation` never lifts.
- The format has **no validity window for a key**. A key is trusted until revoked or removed. A
  *recording's* window is the attestation's own `expires_on` and the 90-day lag bound
  (`MAX_LAG_DAYS`). If you need a key to lapse on a date, that is a calendar reminder to
  revoke it, not something the file enforces.
- The file holds public keys only. `verify-file` exits 1 if group or other can write it.

## 5. Verify the configuration before anyone relies on it

Run where the service runs (same environment variables, same user):

```bash
python -m assurance attest preflight --expect-fingerprint <FP you wrote down> --require both
```

Exit 0 means: key loads, file mode is owner-only, key is apart from the data, the log directory
is writable, the trust list parses as the server parses it, at least one recorder is not revoked,
and the service key is not also a trusted recorder. It prints the fingerprint and, every time,
what it did **not** check:

- where the key is really stored and whether it was ever copied or logged;
- that a backup exists and restores;
- that the fingerprint is the one customers were told (only that it equals what you typed);
- that the deployed process sees this environment;
- that plan entitlements are in force; that a recorder's holder is who the label says; the clock.

Then, against the deployed API: `GET /v1/ledger/attest/key` answers **200** and its
`fingerprint` equals the one you wrote down. If it does not, stop; tell no customer anything is
counter-signed. Before the change the same request answers 503; keep that response as evidence
of the "before".

## 6. Rotate the service key

A rotation is a **new identity**, not a continuation.

1. `keygen` a new pair under new file names (it will not overwrite). Record the new fingerprint
   somewhere independent, then store the new secret (section 3).
2. **Keep the old public key and its fingerprint indefinitely.** Signatures made under it
   verify only against it.
3. Tell customers the new fingerprint by the independent route, and that the old one is retired
   on a stated date.
4. The signer must say so: `attest sign … --rotating` is required to sign onto a log whose last
   record names a different key; without it the sign is refused.
5. Verifying a log across the rotation: pin both keys.
   `python -m assurance attest verify --log L --public-key old.pub --public-key new.pub [--ledger …]`.
   A record signed by a key you did not pin is a finding; a key is never read from the log.
   A verifier holding only the new key sees the earlier span as unverified, on purpose.
6. Run section 5 again. The tests that pin this: `TestServiceKeyRotation`.

## 7. Revoke

**Recorder key** (compromised, retired, holder changed):

```bash
python -m assurance attest trust-list revoke --trust ./config/recorder-trust.json \
    --fingerprint <FP> --effective 2026-06-01
python -m assurance attest preflight --must-be-revoked <FP> --require none
```

- `--effective` is required and is recorded; there is no default. **The verifier does not use it
  to keep older attestations: revocation is total and immediate.** Every attestation by that
  key is rejected, including ones dated before the effective date, because the signer chooses
  the date it writes. Evidence already sealed under that key is re-read as `community`. To keep
  a recording `validated`, re-attest it under a key you trust.
- A `--effective` date in the future still revokes now; `preflight` warns about it.
- The server rereads the file named by the variable on each request in this build; confirm that
  on staging rather than assuming it, and restart if you changed the variable itself.
- Revocation does not alter an offline verifier's copy of the list. Tell every party who pinned
  that key to update theirs.

**Service key** (suspected leak): you cannot "revoke" it centrally; there is no revocation
list for attestation keys. Rotate (section 6), publish the old fingerprint as **retired and
untrusted for anything signed after the stated date**, and keep the old public key so that
signatures from before the incident remain checkable. A leaked key means signatures dated
after the leak cannot be told apart from forgeries.

## 8. What the customer-facing statement may truthfully say

Only after sections 5 and the hosted check pass, and only what is enforced in code
(`docs/claims-registry.md`: if it is not enforced it is not on the pricing page).

May say, once the key is configured and the fingerprint is published by an independent route:

- "On the Cell plan, `POST /v1/ledger/attest` counter-signs the head of your ledger with the
  service's Ed25519 key, fingerprint `<FP>`. The signature shows the head value you presented
  existed at the stated time and was not signed by anyone without the key." (The signature
  covers a head the customer declared; it does not say the chain verified.)
- "Verification against the public key is offline; you do not need our service to check it."

May say, once a trust list with a real recorder is configured:

- "A verification reaches `validated` only when a recorder attestation is accepted under the
  server's trust list, which currently names `<n>` recorder key(s), listed at `<route>`."

Must not say:

- that any customer, pilot, deployment or production use exists (standing facts:
  zero revenue, customers, pilots; `HANDOFF.md` §4.4);
- "tamper-proof", "certified", "notarised", or that the ledger contents are *true* or
  complete. The key holder and the database holder can still lie to a customer who keeps no copy;
- that a recording is physically true, that a recorder was attached to the right machine or
  calibrated, or that the recorder's operator is honest;
- that it is `validated` without saying under whose trust list; that trust is server-wide;
- anything about key custody stronger than the option you actually chose in section 1;
- that the fingerprint is "verified by us" if the only publication route is the API itself.

## 9. Decision record the founder keeps (not in this repository)

| item | value |
|---|---|
| ceremony date, place, who was present | |
| custody option chosen (section 1) and key holder / recovery person | |
| service key fingerprint, and the independent place it was published | |
| backup location, restore drill date and result | |
| recorder keys trusted: fingerprint, label, provenance, how the fingerprint was received | |
| first `preflight` output (public fields only) | |
| staging rehearsal date and result | |
| rotation / revocation log | |

## 10. Do not

- Do not generate real keys in chat, CI, a shared terminal or any session that records output.
- Do not commit `*.pem`, attestation logs, or a trust file containing anything but public keys.
- Do not reuse a staging or rehearsal key in production, or the synthetic demo recorder
  (`examples/workflow/run.py`) against a production trust list.
- Do not trust a key because it arrived with the attestation it signs.
- Do not set the variables, deploy, or charge anyone without the founder's explicit approval.

## What remains operator-only (not done, not doable from this repository)

Generating the real keys; choosing and operating custody; setting the secrets and the variable
on any deployment; backing up and drilling the restore; publishing the fingerprint by an
independent route; receiving and vetting real recorder keys; every customer statement.
