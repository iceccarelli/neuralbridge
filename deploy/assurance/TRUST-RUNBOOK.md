# Runbook — the two things a hosted deployment is missing

Two environment variables decide whether hosted evidence can ever rise above `community` and whether
the service can counter-sign a ledger. **Neither comes from a vendor, a certificate authority or a
third party.** You create both with this repository's own CLI, on a machine you control.

| variable | what it is | who creates it | secret? |
|---|---|---|---|
| `ASSURANCE_ATTEST_KEY_PEM` | the **service's own** Ed25519 private key; the hosted API counter-signs an account's ledger head with it | the operator, once | **yes — a private key** |
| `ASSURANCE_RECORDER_TRUST` | a **path to a JSON file** listing the **public** keys of recorders the deployment is willing to believe | the operator, from public keys the recorder operators send | no — public keys only, but it is a trust decision |

Without the first, every attestation route answers 503. Without the second, no attestation is
accepted, every trace stays "declared by whoever filed it", and every result is capped at
`community`. That is the safe default, not a fault.

## What each one proves — and does not

- **Service key.** A signature by this key over a ledger's length and head, at a stated time, shows
  the head existed then and that someone without the key could not have produced it. It does **not**
  show the ledger's contents are true, who wrote them, or that the clock was right. Whoever holds
  the key and the database can still lie; the protection is for a customer who keeps their own
  copy of the signed head.
- **Recorder trust list.** An attestation accepted under the list shows that *a key you chose to
  trust* signed *those exact trace bytes* for *that product, version and serial*. It does **not**
  show the recording is physically true, that the recorder was attached to the right machine, or that
  the recorder's operator is honest. Adding a key to the list is you vouching for its holder.

## A. Create the service key (once; operator)

```bash
python -m assurance attest keygen --out ./attest-service.pem --public-out ./attest-service.pub
```

- Do this on a machine you control. **Never** paste `attest-service.pem` into chat, a ticket, git,
  a log or an email. The file is created mode `600`; keep it that way.
- Keep `attest-service.pub` and read its fingerprint (printed by the command) to customers by a
  route other than the API, so they can check signatures against a key that did not arrive with them.
- The key is not passphrase-encrypted. That suits a secrets store and is wrong for a laptop; delete
  the local copy once it is in the secrets store.

Set it on the host as a secret (Fly shown; use your platform's secrets manager otherwise):

```bash
fly secrets set ASSURANCE_ATTEST_KEY_PEM="$(cat ./attest-service.pem)"
```

Keep the key **outside** the data volume, so a copy of the volume is not a copy of the key
(`deploy/assurance/README.md`, "key lives outside the data volume on purpose"). Also set
`ASSURANCE_ATTEST_LOGS` to a directory on the volume (already in `fly.toml`). Prefer the secrets
manager's own backup of the key: lose it and you can no longer extend a chain of signed heads under
one identity (see rotation below).

## B. Build the recorder trust list (per recorder; operator + recorder operator)

A "recorder" is whatever signs a trace at the machine: a controller-side logger, a gateway, a
data historian. Its operator runs, **on their side**:

```bash
python -m assurance attest keygen --out recorder.pem --public-out recorder.pub
```

They keep `recorder.pem` (private) and send you **only `recorder.pub`**, plus its fingerprint read
aloud or by another channel. If anyone sends you a private key, do not use it; tell them it is
burned.

You then add it to your trust file (creates the file on first use, extends it afterwards):

```bash
python -m assurance machine recorder-trust --trust recorder-trust.json \
  --public-key recorder.pub --label "Plant 2 line 4 recorder" --provenance bench,field
```

- `--provenance` is what you let that key vouch for: `bench`, `field`, or both. Grant the narrowest
  set. A key trusted for `field` is believed when a trace claims to be a field recording.
- Put the file where the server can read it, e.g. on the volume, and point the variable at it:

```bash
# fly.toml [env]   (a deployment change: founder approval)
ASSURANCE_RECORDER_TRUST = "/data/recorder-trust.json"
```

The list is **server-wide**: it is not scoped to a tenant, a machine or a serial
(`docs/claims-registry.md`). Every account's evidence is judged against the same list. Do not add a
key for one customer's recorder unless you are content that the whole deployment believes it.

## C. Check it took effect

1. Locally, before deploying, with the same file:

```bash
ASSURANCE_RECORDER_TRUST=./recorder-trust.json python -c "
from assurance.api.recorder_trust import server_recorder_trust_state as s
print(s().status)"        # configured
```

   `unset` = nobody trusted (the default). `unreadable` = the variable is set but the file is
   missing, malformed or holds an unusable key; the service **fails closed** and trusts nobody, and
   logs the error class once (never the path).
2. End to end on synthetic data, with your own throwaway recorder key:

```bash
python examples/workflow/run.py
```

   It exits 0 only if the whole workflow, including a `validated` result, behaves as documented.
   That proves the software on invented inputs. It says nothing about your deployment until you
   run an attestation through your deployed API with your real trust list.
3. A hosted verification response now names the tier it believes and why. If it still reads
   `community`, read its `provenance_assessment` before assuming the list is broken: a stale
   attestation (dated more than 90 days after the recording began), a different serial or product,
   or a key not trusted for that provenance are all refused by design.

## D. Revoke and rotate

- **Recorder key compromised or retired.** Edit its entry in the trust file: set `"revoked": true`
  and a `"revoked_on"` date (`YYYY-MM-DD`). A revoked key's attestations are **all** rejected,
  including ones dated before the revocation, because the signer chooses the date it writes
  (`src/assurance/machine/recorder_attestation.py`, module docstring). Evidence already sealed
  under that key is therefore re-read as `community`; that is the intended behaviour, not data
  loss. To keep a recording `validated`, re-attest it under a key you trust. Restart so the
  server rereads the file.
- **Service key rotation.** Generate a new key, set the new secret, and keep the old public key
  and its fingerprint: signatures made under it still verify against it. Tell customers the new
  fingerprint by a separate channel. A rotation is a new identity, not a continuation.
- **Lost service key.** Existing signed heads remain verifiable with the old public key. Nothing
  can be signed under that identity again.

## E. Do not

- Do not generate real keys in a shared chat, CI log or any session that records its output.
- Do not commit `*.pem`, the trust file with private material (it should hold only public keys), or
  the attestation logs.
- Do not trust a key because it "arrived with" the attestation it signs. Obtain the public key
  by a route independent of the attestations.
- Do not describe a result as "validated" to a buyer without saying under whose trust list.

## Authority

Setting `ASSURANCE_ATTEST_KEY_PEM` and `ASSURANCE_RECORDER_TRUST` on a production deployment is a
production-secret and deployment change. It needs the founder's explicit go-ahead
(`CLAUDE.md`, "Authority"); this file is the checklist, not the action.
