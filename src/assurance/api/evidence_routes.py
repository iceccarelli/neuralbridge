"""Free evidence verification: one anonymous, stateless door for the bundles.

``POST /v1/evidence/verify`` takes the raw text of a JSON file somebody handed
you and says what can and cannot be established from that file alone. It reads
no ledger, writes nothing, stores nothing and logs nothing beyond the ordinary
access line: the body is held in memory for the length of the request.

It recognises three kinds of file and calls the same domain functions the
offline CLI uses:

* a **ledger export** (``GET /v1/cases/{id}/export``, ``assurance evidence
  export``) — :func:`assurance.evidence.verify_export.verify_export`. Whether
  anything was *removed* is checked only against the export's signed ``anchor``
  and only with the caller's public key, and only an anchor over at least one
  record counts; otherwise ``completeness`` is ``not_checked`` and the answer says
  so. ``anchored_partial`` means records follow the signed head and no signature
  covers them. ``declared_head`` means the only signed head that agrees was
  ``declared_by_holder``: the signer was TOLD three numbers and never read the chain,
  so it is never ``anchored``. A one-case export made without ``?skeleton=true`` cannot
  be shown complete even with the right key: that is outcome ``not_established`` (it
  lists what could not be established), which is **not** a finding of tampering;
* a **machine verification bundle** — :func:`assurance.machine.bundle.
  check_bundle_data` (the same rules as the offline CLI, including the parts of
  the file the seal does not cover);
* a **signed head attestation log** — signatures are checked only against a
  public key the caller supplies, because the file carries a key *fingerprint*,
  not the key, and a key delivered with the signature proves nothing.

``ok`` is true when no inconsistency was found in the checks that ran and nothing the
caller asked for was left undone. It is NOT "every check this kind of file could need
was run": a ledger export checked without a key is ``ok`` with ``completeness``
``not_checked``, and a machine bundle is ``ok`` at ``level`` ``integrity_only`` (never
reproduced here). Read ``completeness`` (ledger exports), ``level`` (machine bundles) and
``anchor.basis`` beside it. An attestation log checked without the issuer's public key
is never ``ok`` (outcome ``signatures_not_checked``): nothing about a signature was
established.

The result always separates lists that must never be merged: ``verified`` (facts a
check actually established), ``assumptions`` (what a pass still takes on trust),
``not_checked`` (every limit) and, for a ledger export, ``unestablished`` (something
that was asked for and could not be established, e.g. completeness without a skeleton).
``ok`` is not a statement that the evidence is true, complete or the operator's ledger.

Metering: one unit of the free validator's daily allowance per call (scope
``evidence_verify``), per address; paid accounts are unmetered. The body cap on
this path is small (see :func:`assurance.api.deps.max_body_bytes`) for every
caller, because the whole point is that the caller has no account.

Cost control, because the caller is anonymous and the deployment has one worker:
the answer is bounded (lists are capped, every string is clipped), a file with
more than :data:`MAX_ENTRIES` entries is refused by size rather than walked, at
most :data:`MAX_ANALYSES` files are analysed at once (the rest get a 503 that
costs no allowance), and the analysis and the allowance bookkeeping run off the
event loop. The request must say ``Content-Type: application/json``: that makes a
browser send a CORS preflight, so another site cannot spend a visitor's allowance
with a simple cross-site POST. The issuer's public key travels in the
``X-Issuer-Public-Key`` header, not the URL, and anything that looks like a
private key is refused unread.
"""

from __future__ import annotations

import json
import re
import threading
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from starlette.concurrency import run_in_threadpool

from assurance.api.attest_routes import MAX_VERIFY_RECORDS
from assurance.api.deps import Anyone, get_accounts, spend
from assurance.attest.attestation import (
    AttestationError,
    HeadAttestation,
    verify_log,
)
from assurance.attest.keys import SigningKeyError, VerifyingKey
from assurance.billing.accounts import AccountStore, Principal
from assurance.core.evidence import Evidence
from assurance.core.tiers import AssuranceTier
from assurance.evidence.verify_export import verify_export
from assurance.machine.bundle import BUNDLE_SCHEMA, check_bundle_data
from assurance.machine.recorder_attestation import (
    RecorderAttestationError,
    RecorderTrust,
    loads_strict,
)

__all__ = ["evidence_router", "analyse"]

evidence_router = APIRouter(prefix="/v1/evidence", tags=["free"])

#: Nesting deeper than this is not an evidence file. It also keeps every later
#: recursive step (canonical JSON for hashing) far from the interpreter's limit.
MAX_DEPTH = 48

#: Most JSON containers (objects and arrays) a file may hold, counted before it is
#: parsed. The parse and the depth walk cost a Python call per container, so a
#: 4 MiB file of ``{},`` or of small nested lists is seconds of GIL on the single
#: worker. A real export has about 7 containers per 1,000 bytes (about 30,000 in a
#: full 4 MiB body); this leaves it several times that. The count is of ``{`` and
#: ``[`` characters, so braces inside strings count too: it can over-refuse, never
#: under-refuse.
MAX_CONTAINERS = 200_000

#: A ledger export with more entries than this is refused by size, not walked. A
#: genuine 4 MiB export holds a few thousand; this is generous.
MAX_ENTRIES = 50_000
#: Items per list in the answer, and characters per string. Attacker-controlled text
#: (a subject, a product name) is quoted in findings and must not be able to make the
#: answer larger than the question.
MAX_LIST = 50
MAX_TEXT = 600
#: Files analysed at once. The deployment runs one worker; analysis is CPU.
MAX_ANALYSES = 2
MAX_KEY_HEADER = 4096
#: A recorder trust list is a few PEM keys; this is room for several, not a document.
MAX_TRUST_HEADER = 16384

SUPPORTED = (
    "a ledger export (a JSON object with an `entries` list, from "
    "`GET /v1/cases/{id}/export` or `assurance evidence export`)",
    "a machine verification bundle (schema `assurance.machine.bundle/1`)",
    "a signed head attestation log (a list or `{attestations: [...]}`, or the "
    "JSON-lines file `assurance attest` writes)",
)

_SERVICE_ASSUMPTION = (
    "This result was computed by the service you sent the file to. To check "
    "without trusting it, run the same verifier yourself: "
    "`python -m assurance evidence verify <file>` (offline, opens no socket)."
)


class _UnreadableError(Exception):
    """The body is not a JSON document we are willing to read."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _UnreadableError(
                f"the key {key!r} appears twice in one object. Different JSON "
                "readers keep different copies, so what was checked here may not "
                "be what another reader sees; this is refused, not guessed at")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise _UnreadableError(f"{name} is not valid JSON and is not a number that can be hashed")


def _too_deep(value: Any) -> bool:
    """Iteratively, so a hostile file cannot make this itself recurse."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: list[Any] = list(node.values())
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > MAX_DEPTH:
            return True
        stack.extend((child, depth + 1) for child in children
                     if isinstance(child, (dict, list)))
    return False


def _parse(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys,
                          parse_constant=_refuse_constant)
    except _UnreadableError:
        raise
    except RecursionError as exc:
        raise _UnreadableError("the nesting is far deeper than any evidence file") from exc
    except json.JSONDecodeError as exc:
        raise _UnreadableError(
            f"not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})") from exc
    except ValueError as exc:
        raise _UnreadableError(f"not valid JSON: {type(exc).__name__}") from exc


def _parse_lines(text: str) -> list[Any] | None:
    """A JSON-lines file (the attestation log format); ``None`` if it is not one.

    Cheap refusals first, so a hostile file cannot make this parse millions of
    lines: an attestation log is a few thousand records at most, and every line
    of one is an object.
    """
    if not text.lstrip().startswith("{"):
        return None
    if text.count("\n") > MAX_VERIFY_RECORDS + 1:
        return None
    out: list[Any] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("{"):
            return None
        try:
            out.append(_parse(stripped))
        except _UnreadableError:
            return None
    return out or None


def _clip(value: Any) -> Any:
    """Bound what goes back to an anonymous caller: strings, lists, and their count."""
    if isinstance(value, str):
        return value if len(value) <= MAX_TEXT else value[:MAX_TEXT] + "… (clipped)"
    if isinstance(value, list):
        shown = [_clip(v) for v in value[:MAX_LIST]]
        if len(value) > MAX_LIST:
            shown.append(f"… and {len(value) - MAX_LIST} more not listed")
        return shown
    if isinstance(value, dict):
        return {k: _clip(v) for k, v in value.items()}
    return value


def _result(
    kind: str, outcome: str, *, scope: str = "", entries: int = 0,
    verified: list[str] | None = None, problems: list[str] | None = None,
    assumptions: list[str] | None = None, not_checked: list[str] | None = None,
    tier: dict[str, Any] | None = None, head: dict[str, Any] | None = None,
    summary: str = "", signatures_verified: bool | None = None,
    level: str | None = None, completeness: str | None = None,
    anchor: dict[str, Any] | None = None, unestablished: list[str] | None = None,
) -> dict[str, Any]:
    return _clip({
        "kind": kind,
        "outcome": outcome,
        # True means only: no inconsistency was found in the checks that ran (read
        # `completeness` / `level` beside it). It is not "complete" and not "reproduced".
        "ok": outcome == "no_inconsistency_found",
        # Only an attestation log has signatures; null for every other kind.
        "signatures_verified": signatures_verified,
        # Machine bundles only: rejected | integrity_only | reproduced. This route
        # never receives the originals, so a bundle here is never "reproduced".
        "level": level,
        # Ledger exports only: anchored | anchored_partial | declared_head | not_checked
        # | failed. "anchored" means a signed head the signer READ from the ledger, over
        # at least one record, under the key the caller supplied, agrees with the bundle
        # and is its last record; "anchored_partial" means records follow that head and no
        # signature covers them; "declared_head" means the signer was only TOLD the head.
        "completeness": completeness,
        # The signed head completeness rests on, with its `basis`
        # (read_from_ledger | declared_by_holder).
        "anchor": anchor,
        # Ledger exports only: what was asked for and could not be established. Not
        # tampering; outcome "not_established" when this is the only open item.
        "unestablished": unestablished or [],
        "scope": scope,
        "entries": entries,
        "verified": verified or [],
        "problems": problems or [],
        "assumptions": assumptions or [],
        "not_checked": not_checked or [],
        "tier": tier,
        "head": head,
        "summary": summary,
        "stored": False,
    })


def _unreadable(problem: str) -> dict[str, Any]:
    return _result(
        "unknown", "unreadable", problems=[problem],
        not_checked=["nothing in the file could be checked."],
        summary="This file could not be read, so nothing was checked.")


# ---------------------------------------------------------------------------
# ledger export
# ---------------------------------------------------------------------------
def _ledger(doc: dict[str, Any], key_pem: str = "") -> dict[str, Any]:
    skeleton = doc.get("skeleton")
    held = len(doc["entries"]) + (len(skeleton) if isinstance(skeleton, list) else 0)
    if held > MAX_ENTRIES:
        return _result(
            "ledger_export", "unsupported",
            problems=[f"{held:,} entries (with the skeleton) is more than the "
                      f"{MAX_ENTRIES:,} this page checks; nothing was checked."],
            not_checked=["verify a file this large offline: "
                         "`python -m assurance evidence verify <file>`."],
            summary="Too many entries to check here.")
    trusted = None
    if key_pem.strip():
        try:
            trusted = VerifyingKey.from_pem(key_pem)
        except SigningKeyError as exc:
            return _result(
                "ledger_export", "unreadable",
                problems=[f"the public key supplied cannot be read: {exc}"],
                not_checked=["nothing was checked: completeness needs a readable key."],
                summary="The public key could not be read, so nothing was checked.")
    v = verify_export(doc, trusted_key=trusted)
    not_checked = list(v.checks_skipped)
    assumptions = [*v.assumptions, _SERVICE_ASSUMPTION]
    if v.head is not None and v.completeness != "anchored":
        not_checked.append(
            f"to show this is the operator's ledger, compare its head (seq "
            f"{v.head['seq']}, link hash {v.head['link_hash']}) with a signed head "
            "attestation obtained from a channel the operator does not control. "
            "The attestation inside this file is unsigned: it is the exporter's "
            "own statement.")
    basis = (v.anchor or {}).get("basis", "")
    if v.problems:
        outcome = "inconsistent"
        summary = (f"{len(v.problems)} problem(s) found in {v.entries} readable "
                   f"entries ({v.scope}). This file is not what the exporter wrote, "
                   "or it was not written by an exporter.")
    elif not v.ok:
        # Nothing was found wrong; something asked for could not be established. That is
        # not the tamper finding above, and it is not a pass.
        outcome = "not_established"
        first = v.unestablished[0] if v.unestablished else "a check could not be completed"
        lead = first if first.startswith("Completeness") else f"Could not be established: {first}"
        summary = (f"{lead} No inconsistency was found in the checks that ran, so this "
                   "is not a finding that the file was changed"
                   + (f"; {len(v.unestablished) - 1} further item(s) are listed below"
                      if len(v.unestablished) > 1 else "") + ".")
    elif v.completeness == "anchored":
        outcome = "no_inconsistency_found"
        summary = (f"{v.entries} entries, {v.scope}: none of the checks that ran "
                   "found a problem, and the bundle agrees with a signed head under "
                   f"the key you supplied (basis {basis}: the signer read it from the "
                   "ledger), which signs its last record. Anything appended since is "
                   "unsigned; read 'Not checked'.")
    elif v.completeness == "anchored_partial" and v.anchor:
        outcome = "no_inconsistency_found"
        after = v.anchor["records_after_anchor"]
        summary = (f"{v.entries} entries, {v.scope}: none of the checks that ran "
                   f"found a problem. A signed head (seq {v.anchor['head_seq']}, basis "
                   f"{basis}, under the key you supplied) matches the bundle only up to "
                   f"that record: {after} record(s) after it are covered by no "
                   "signature, so a cut of those would look the same. Read 'Not checked'.")
    elif v.completeness == "declared_head" and v.anchor:
        outcome = "no_inconsistency_found"
        summary = (f"{v.entries} entries, {v.scope}: none of the checks that ran "
                   "found a problem, but COMPLETENESS IS NOT SHOWN. The only signed head "
                   f"it agrees with (seq {v.anchor['head_seq']}, basis {basis}) was "
                   "declared to the signer, who was handed three numbers and never read "
                   "the chain; anyone entitled to ask for a counter-signature can have a "
                   "head they invented signed. That is not an anchor. Read 'Not checked'.")
    else:
        outcome = "no_inconsistency_found"
        summary = (f"{v.entries} entries, {v.scope}: none of the checks that ran "
                   "found a problem. That is internal consistency only, and "
                   "COMPLETENESS WAS NOT CHECKED: entries cut from the end, or a "
                   "rebuilt chain, would look the same. Read 'Not checked'.")
    return _result(
        "ledger_export", outcome, scope=v.scope, entries=v.entries,
        verified=list(v.verified), problems=list(v.problems),
        assumptions=assumptions, not_checked=not_checked,
        head=v.head, summary=summary, completeness=v.completeness, anchor=v.anchor,
        unestablished=list(v.unestablished))


# ---------------------------------------------------------------------------
# machine verification bundle
# ---------------------------------------------------------------------------
def _machine(doc: dict[str, Any], recorder_trust: RecorderTrust | None = None) -> dict[str, Any]:
    # The one implementation of the rules (seal, coherence, the envelope's tier
    # ceiling, the engine's set of checks, the unsealed copies) is the library's;
    # the same call is behind `assurance machine check` and /v1/machine/bundle/check.
    # `recorder_trust` is the CALLER's own list (X-Recorder-Trust); this route has no
    # list of its own, and a list inside the file is ignored.
    check = check_bundle_data(doc, recorder_trust=recorder_trust)
    problems = list(check.problems)
    # Only what a check actually established, and only when nothing was found.
    verified = list(check.verified) if check.ok else []
    tier: dict[str, Any] | None = None
    body: dict[str, Any] = {}
    try:
        body = Evidence.from_dict(doc["evidence"]).body
    except Exception:  # noqa: BLE001 - check_bundle_data already reported it
        body = {}
    if not isinstance(body, dict):
        body = {}

    try:
        recorded = AssuranceTier(str(body.get("tier")))
        tier = {
            "recorded_tier": recorded.value,
            # What the file says its tier would allow. Not something this check
            # established: a resealed file can say anything the engine's rules allow.
            "as_recorded_may_claim_physical_behaviour": recorded.may_claim_physical_behaviour,
            "evidence_required": recorded.evidence_required,
        }
    except ValueError:
        tier = {"recorded_tier": body.get("tier"),
                "as_recorded_may_claim_physical_behaviour": None,
                "evidence_required": ""}
    tier.update({
        "recorded_verdict": body.get("verdict"),
        "product": body.get("product"),
        "product_version": body.get("product_version"),
        "provenance": body.get("provenance"),
        # Who vouches for `provenance`: "declared_by_filer" means the filer said so and
        # nothing signed the recording (so it is capped at community).
        "provenance_basis": body.get("provenance_basis"),
        # What THIS check made of that claim: not_applicable | reproduced (accepted under
        # the recorder trust list the caller supplied) | unverifiable (none supplied: the
        # claim is NOT believed) | not_reproduced (rejected). `believed_tier` is the
        # recorded tier capped at community unless it was reproduced. Neither says the
        # recording is physically true: integrity is not recorder authenticity, which
        # is not physical safety.
        "provenance_reassessed": check.provenance_reassessed,
        "believed_tier": check.believed_tier,
        "trace_started_at": body.get("trace_started_at"),
    })

    not_checked = [
        "a seal is not a signature: anyone can produce a self-consistent file like "
        "this, including one that records a tier or verdict nobody earned. This "
        "check applies the engine's own rules to what the file claims; it cannot "
        "show who made it or that a verification was ever run.",
        "the original envelope and trace were not supplied, so nothing here shows "
        "the machine behaved as the bundle says. To re-run the engine on them: "
        "`python -m assurance machine check <bundle> --envelope ... --trace ...`.",
        "the tier is the one the bundle records; it was not re-derived from a "
        "trace, and a simulated run cannot support a claim about the real machine.",
        "a bundle on its own does not show it was ever recorded in a ledger, that "
        "it is the latest verification of that machine, or that the software "
        "running on the machine today is the software it describes.",
        "recorder authenticity: a recorded provenance_basis of 'recorder_attested' is "
        "a claim until the attestation is re-assessed under a recorder trust list you "
        "hold. Even then it shows only that a trusted key signed these trace bytes: "
        "integrity is not recorder authenticity, and recorder authenticity is not "
        "physical safety.",
    ]
    # What the checker itself said it did not do, beyond the fixed list above (the
    # missing-originals note repeats the second item there).
    not_checked.extend(
        n.removeprefix("NOT CHECKED: ") for n in check.limitations
        if "original envelope and trace were not supplied" not in n)
    assumptions = [
        "The actor named in the bundle is whoever the writer declared. Nothing "
        "here checks who a person is.",
        _SERVICE_ASSUMPTION,
    ]
    ok_final = check.ok
    summary = (
        "The sealed record is internally consistent. It was NOT REPRODUCED from the "
        "original envelope and trace, so that does not show the machine behaved as "
        "recorded; read 'Not checked'." if ok_final else
        f"{len(problems)} problem(s) found: this bundle is not what the verifier "
        "sealed, or it was edited after sealing.")
    return _result(
        "machine_bundle", "no_inconsistency_found" if ok_final else "inconsistent",
        scope=f"{body.get('product', '?')} {body.get('product_version', '')}".strip(),
        entries=1, verified=verified if ok_final else [], problems=problems,
        assumptions=assumptions, not_checked=not_checked, tier=tier, summary=summary,
        level=check.level)


# ---------------------------------------------------------------------------
# signed head attestation log
# ---------------------------------------------------------------------------
def _attestation_records(doc: Any) -> list[Any] | None:
    if isinstance(doc, list):
        return doc if doc and all(isinstance(r, dict) and "head_link_hash" in r for r in doc) else None
    if isinstance(doc, dict):
        if isinstance(doc.get("attestations"), list):
            return doc["attestations"]
        if isinstance(doc.get("attestation"), dict) and "head_link_hash" in doc["attestation"]:
            return [doc["attestation"]]
        if "head_link_hash" in doc and "signature" in doc:
            return [doc]
    return None


def _structure_problems(records: list[HeadAttestation]) -> list[str]:
    """The key-free checks: the log is a consistent chain of statements.

    A subset of :func:`assurance.attest.attestation.verify_log`, which cannot run
    without a key. Signatures are the part this leaves out, and it says so.
    """
    problems: list[str] = []
    previous: HeadAttestation | None = None
    for position, record in enumerate(records, start=1):
        where = f"attestation {record.sequence}"
        if record.sequence != position:
            problems.append(f"{where}: out of order, expected {position} — an "
                            "attestation was removed or the file was reordered")
        expected = previous.content_hash() if previous else ""
        if record.previous != expected:
            problems.append(f"{where}: does not name the attestation before it — "
                            "the log was spliced or edited")
        if previous is not None and record.ledger_length < previous.ledger_length:
            problems.append(f"{where}: covers fewer records than attestation "
                            f"{previous.sequence} did — the ledger was shortened")
        if not record.signature:
            problems.append(f"{where}: carries no signature")
        else:
            try:
                record.signature_bytes()
            except AttestationError:
                problems.append(f"{where}: the signature is not base64 — the record "
                                "is damaged, not merely unsigned")
        previous = record
    if len({r.key_fingerprint for r in records}) > 1:
        problems.append("the log names more than one signing key")
    return problems


def _attestations(items: list[Any], key_pem: str) -> dict[str, Any]:
    if len(items) > MAX_VERIFY_RECORDS:
        return _result(
            "attestation_log", "unsupported",
            problems=[f"{len(items)} attestations is more than the {MAX_VERIFY_RECORDS} "
                      "this endpoint checks"],
            not_checked=["verify it locally: `assurance attest verify --log <file>`."],
            summary="Too many attestations to check here.")
    records: list[HeadAttestation] = []
    problems: list[str] = []
    for index, raw in enumerate(items):
        try:
            if not isinstance(raw, dict):
                raise AttestationError("not an object")
            records.append(HeadAttestation.from_dict(raw))
        except (AttestationError, ValueError, KeyError, TypeError, OverflowError) as exc:
            problems.append(f"attestation {index + 1}: unreadable ({exc})")
    if problems:
        return _result(
            "attestation_log", "inconsistent", entries=len(records), problems=problems,
            not_checked=["the records that could be read were not checked either: a "
                         "log with an unreadable record is damaged as a whole."],
            summary="The log has records that cannot be read.")

    assumptions = [_SERVICE_ASSUMPTION]
    for record in records:
        try:
            if record.signature:
                record.signature_bytes()
        except AttestationError:
            problems.append(f"attestation {record.sequence}: the signature is not base64 "
                            "— the record is damaged, not merely unsigned")
    if problems:
        return _result(
            "attestation_log", "inconsistent", entries=len(records), problems=problems,
            not_checked=["nothing else was checked: a log with a damaged record is "
                         "damaged as a whole."],
            summary=f"{len(problems)} problem(s) found in the attestation log.")
    latest = records[-1]
    head = {"seq": latest.head_seq, "link_hash": latest.head_link_hash,
            "length": latest.ledger_length}
    not_checked = [
        "dropping the most recent attestation(s) from the end of a log cannot be "
        "detected from the log alone: what remains is still a consistent chain. Compare "
        "the count and the latest record with a copy you hold from another channel.",
        "the ledger itself was not examined: this cannot say whether it still holds "
        "the records the latest attestation was made over. Compare the head below "
        "with a ledger export, or run `assurance attest verify --ledger`.",
    ]
    if any(r.basis.value == "declared_by_holder" for r in records):
        not_checked.append(
            "some attestations are counter-signatures: the signer was handed the head "
            "values and never saw the ledger. They fix what was claimed and when; "
            "they do not say the chain verified at the time.")

    if key_pem.strip():
        try:
            key = VerifyingKey.from_pem(key_pem)
        except SigningKeyError as exc:
            return _result(
                "attestation_log", "unreadable", entries=len(records),
                problems=[f"the public key supplied cannot be read: {exc}"],
                not_checked=["nothing was checked: signatures need a readable key."],
                summary="The public key could not be read, so nothing was checked.")
        verdict = verify_log(records, key)
        problems = list(verdict.problems)
        verified: list[str] = []
        if verdict.ok:
            verified = [
                f"all {len(records)} signature(s) verify against the public key you "
                f"supplied (fingerprint {verdict.key_fingerprint})",
                "sequence numbers run 1..N with none missing",
                "each attestation names the one before it, so none was dropped from "
                "the middle",
                "the record counts never decrease",
            ]
        assumptions.append(
            "The public key is the issuer's: you supplied it, and this service cannot "
            "tell. A key that arrived with the attestations proves nothing; get it "
            "from a channel the issuer's administrator does not control.")
        not_checked = [*verdict.checks_skipped, *not_checked]
        # verify_log's own ledger-absent note duplicates ours.
        not_checked = list(dict.fromkeys(not_checked))
    else:
        problems = _structure_problems(records)
        verified = [] if problems else [
            "sequence numbers run 1..N with none missing",
            "each attestation names the one before it, so none was dropped from the "
            "middle",
            "the record counts never decrease",
            "every record carries a signature (present, not yet verified)",
        ]
        not_checked.insert(
            0,
            "the signatures were NOT verified: a file carries a key fingerprint, not "
            "the key, so a signature can only be checked against a public key you "
            "obtained independently. Supply it and check again.")

    keyed = bool(key_pem.strip())
    if problems:
        outcome, summary = "inconsistent", f"{len(problems)} problem(s) found in the attestation log."
    elif keyed:
        outcome = "no_inconsistency_found"
        summary = ("The log is consistent with itself and every signature verifies "
                   "against the key you supplied.")
    else:
        # Nothing about a signature was established, so this is not an "ok".
        outcome = "signatures_not_checked"
        summary = ("The log is consistent with itself, but NO signature was checked: "
                   "without the issuer's public key this establishes nothing about who "
                   "made it or whether any record was edited.")
    return _result(
        "attestation_log", outcome,
        scope=f"attestation log, {len(records)} record(s)", entries=len(records),
        verified=verified if not problems else [], problems=problems,
        assumptions=assumptions, not_checked=not_checked, head=head,
        summary=summary, signatures_verified=keyed and not problems)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def analyse(raw: bytes, public_key_pem: str = "",
            recorder_trust: RecorderTrust | None = None) -> dict[str, Any]:
    """Classify and check one file. Never raises: every outcome is a result."""
    if not raw.strip():
        return _unreadable("the file is empty")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _unreadable("the file is not UTF-8 text")
    containers = text.count("{") + text.count("[")
    if containers > MAX_CONTAINERS:
        return _unreadable(
            f"the file holds about {containers:,} JSON objects and lists, more than the "
            f"{MAX_CONTAINERS:,} this page reads (a genuine export of the allowed size "
            "holds a fraction of that); nothing was parsed. Verify a file this "
            "unusual offline: `python -m assurance evidence verify <file>`.")
    try:
        try:
            doc: Any = _parse(text)
        except _UnreadableError as first:
            lines = _parse_lines(text) if "\n" in text.strip() else None
            if lines is None or _attestation_records(lines) is None:
                raise first from None
            doc = lines
        if _too_deep(doc):
            raise _UnreadableError(f"nested more than {MAX_DEPTH} levels deep, which no "
                              "evidence file is")
    except _UnreadableError as exc:
        return _unreadable(str(exc))

    try:
        if isinstance(doc, dict) and isinstance(doc.get("entries"), list):
            return _ledger(doc, public_key_pem)
        if isinstance(doc, dict) and (doc.get("schema") == BUNDLE_SCHEMA
                                      or ("evidence" in doc and "envelope" in doc)):
            return _machine(doc, recorder_trust)
        records = _attestation_records(doc)
        if records is not None:
            return _attestations(records, public_key_pem)
    except Exception as exc:  # noqa: BLE001 - a check that crashed is not a pass
        return _result(
            "unknown", "check_failed",
            problems=[f"the check itself failed on this file ({type(exc).__name__}); "
                      "that is not a pass"],
            not_checked=["nothing in the file can be relied on from this result."],
            summary="The check could not be completed.")

    return _result(
        "unknown", "unsupported",
        problems=["this file is not one of the kinds that can be checked here"],
        not_checked=[f"supported: {s}" for s in SUPPORTED],
        summary="Not a file this page can check.")


class _Slots:
    """A small counting gate: at most ``size`` analyses run at once; the rest are refused."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._busy = 0
        self._lock = threading.Lock()

    def full(self) -> bool:
        with self._lock:
            return self._busy >= self._size

    def try_acquire(self) -> bool:
        with self._lock:
            if self._busy >= self._size:
                return False
            self._busy += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._busy -= 1


_SLOTS = _Slots(MAX_ANALYSES)

_PEM = re.compile(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----", re.DOTALL)


def _pem_from_header(value: str) -> str:
    """Rebuild a PEM from the one-line form a header can carry.

    A header cannot hold line breaks, so the key arrives with its lines joined by
    spaces. Anything that is not a recognisable PEM passes through unchanged and is
    reported as unreadable by the key parser.
    """
    match = _PEM.search(value.strip())
    if not match:
        return value
    body = "".join(match.group(2).split())
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "\n".join([f"-----BEGIN {match.group(1)}-----", *lines,
                      f"-----END {match.group(1)}-----"]) + "\n"


def _meter(principal: Principal, accounts: AccountStore) -> dict[str, str]:
    """Spend one unit and describe what is left. Blocking SQLite: runs off the event loop."""
    limit = principal.plan.validations_per_day
    spend(principal, "evidence_verify", limit, accounts)
    headers = {"X-Assurance-Tier": principal.tier}
    if limit is not None:
        used = accounts.usage_today(principal.subject).get("evidence_verify", 0)
        headers["X-Assurance-Quota-Limit"] = str(limit)
        headers["X-Assurance-Quota-Remaining"] = str(max(0, limit - used))
    return headers


def _guarded_analyse(raw: bytes, key_pem: str,
                     recorder_trust: RecorderTrust | None = None) -> dict[str, Any]:
    """Runs in a worker thread; frees the slot when the work (not the request) ends."""
    try:
        return analyse(raw, key_pem, recorder_trust)
    finally:
        _SLOTS.release()


def _recorder_trust_from_header(value: str | None) -> RecorderTrust | None:
    """The caller's own recorder trust list from ``X-Recorder-Trust``, or ``None``."""
    if value is None or not value.strip():
        return None
    if "PRIVATE" in value.upper():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "private_key_refused",
                    "detail": "That looks like a private key. It was not read or kept. "
                              "Only PUBLIC keys go in a recorder trust list; if this was a "
                              "real key, treat it as exposed and replace it."})
    if len(value) > MAX_TRUST_HEADER:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "recorder_trust_too_large",
                    "detail": f"A recorder trust header is at most {MAX_TRUST_HEADER} "
                              "characters."})
    try:
        return RecorderTrust.from_dict(loads_strict(value, "X-Recorder-Trust"))
    except RecorderAttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_recorder_trust", "detail": str(exc)[:300]}) from exc


@evidence_router.post(
    "/verify",
    summary="Check an evidence file you were handed. Free, anonymous, stores nothing.",
)
async def verify_evidence(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Anyone],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
    x_issuer_public_key: Annotated[str | None, Header(
        description="the issuer's Ed25519 PUBLIC key (PEM, line breaks as spaces), to "
                    "check attestation signatures, or a ledger export's signed anchor "
                    "(which is what shows nothing was removed). Never a private key: "
                    "those are refused unread.")] = None,
    x_recorder_trust: Annotated[str | None, Header(
        description="YOUR recorder trust list (JSON, format "
                    "assurance.machine.recorder-trust.v1, on one line), to re-assess the "
                    "recorder attestation in a machine bundle. Without it a bundle that "
                    "claims `recorder_attested` is reported as unverifiable and its tier "
                    "is not believed. Public keys only: a private key is refused "
                    "unread.")] = None,
) -> dict[str, Any]:
    """The body is the raw JSON file itself (not wrapped in anything).

    Send ``Content-Type: application/json``. Nothing is stored. The body is read
    into memory, checked and dropped; the only record is the ordinary access log
    line (method, path, status). The answer separates facts established
    (`verified`), what is taken on trust (`assumptions`) and every limit
    (`not_checked`); there is no bare "valid".

    Read these beside `ok` (which means only "no inconsistency was found in the checks
    that ran"):

    * `outcome`: `no_inconsistency_found`, `signatures_not_checked`, `not_established`
      (nothing wrong was found but a check asked for could not be completed, listed in
      `unestablished`; not a finding of tampering), `inconsistent` (listed in `problems`),
      `unreadable`, `unsupported`, `check_failed`.
    * `completeness` (ledger exports): `anchored` only when the file agrees with a signed
      head the signer READ from the ledger, over at least one record, under the public key
      you supplied in `X-Issuer-Public-Key`, and that head signs the last record;
      `anchored_partial` when records follow that head (`anchor.records_after_anchor`
      are covered by no signature); `declared_head` when the only agreeing signed head was
      `declared_by_holder` (the signer was told three numbers and never read the chain, so
      it is not an anchor); `not_checked` (no key, no anchor, or a head over zero records);
      `failed` (the file contradicts a signed head, or one is dated after it was signed).
      A one-case export is checked against its anchor only if it carries the opt-in ledger
      skeleton (`?skeleton=true` at export); otherwise a key gives `not_established`.
    * `anchor` (ledger exports): the signed head completeness rests on, with its `basis`
      (`read_from_ledger` or `declared_by_holder`), `head_seq` and `records_after_anchor`.
    * `level` (machine bundles): `integrity_only` here (the original envelope and trace are
      not supplied), never `reproduced`; `rejected` when a check failed.
    """
    # Cheap refusals first, none of which cost the caller an allowance unit.
    media = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media != "application/json":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={"error": "unsupported_media_type",
                    "detail": "Send the file with Content-Type: application/json."})
    key_pem = ""
    if x_issuer_public_key is not None and x_issuer_public_key.strip():
        if "PRIVATE" in x_issuer_public_key.upper():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "private_key_refused",
                        "detail": "That looks like a private key. It was not read or kept. "
                                  "Only a PUBLIC key is ever needed; if this was a real "
                                  "key, treat it as exposed and replace it."})
        if len(x_issuer_public_key) > MAX_KEY_HEADER:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "public_key_too_large",
                        "detail": f"A public key header is at most {MAX_KEY_HEADER} characters."})
        key_pem = _pem_from_header(x_issuer_public_key)
    recorder_trust = _recorder_trust_from_header(x_recorder_trust)
    if _SLOTS.full():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, headers={"Retry-After": "3"},
            detail={"error": "verifier_busy",
                    "detail": "Other files are being checked right now. Nothing was "
                              "counted against your allowance; try again in a moment."})
    # Spent before the body is read or parsed: an address over its allowance costs
    # the server a header lookup, not a parse. (A chunked body that then turns out to
    # exceed the cap has already spent its unit; a declared oversize one has not.)
    # Blocking SQLite, so off the event loop.
    headers = await run_in_threadpool(_meter, principal, accounts)
    response.headers.update(headers)
    response.headers["Cache-Control"] = "no-store"
    raw = await request.body()
    if not _SLOTS.try_acquire():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, headers={"Retry-After": "3"},
            detail={"error": "verifier_busy",
                    "detail": "Other files are being checked right now; try again in a moment."})
    return await run_in_threadpool(_guarded_analyse, raw, key_pem, recorder_trust)
