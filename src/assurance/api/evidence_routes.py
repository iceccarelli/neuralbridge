"""Free evidence verification: one anonymous, stateless door for the bundles.

``POST /v1/evidence/verify`` takes the raw text of a JSON file somebody handed
you and says what can and cannot be established from that file alone. It reads
no ledger, writes nothing, stores nothing and logs nothing beyond the ordinary
access line: the body is held in memory for the length of the request.

It recognises three kinds of file and calls the same domain functions the
offline CLI uses:

* a **ledger export** (``GET /v1/cases/{id}/export``, ``assurance evidence
  export``) — :func:`assurance.evidence.verify_export.verify_export`;
* a **machine verification bundle** — :func:`assurance.machine.bundle.
  verify_bundle_data`, plus the checks on the parts of the file the seal does
  not cover;
* a **signed head attestation log** — signatures are checked only against a
  public key the caller supplies, because the file carries a key *fingerprint*,
  not the key, and a key delivered with the signature proves nothing.

The result always separates three lists that must never be merged: ``verified``
(facts a check actually established), ``assumptions`` (what a pass still takes
on trust) and ``not_checked`` (every limit). ``ok`` means "no check that ran
found a problem"; it is not a statement that the evidence is true, complete or
the operator's ledger.

Metering: one unit of the free validator's daily allowance per call (scope
``evidence_verify``), per address; paid accounts are unmetered. The body cap on
this path is small (see :func:`assurance.api.deps.max_body_bytes`) for every
caller, because the whole point is that the caller has no account.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
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
from assurance.machine.bundle import BUNDLE_SCHEMA, verify_bundle_data
from assurance.machine.envelope import SafetyEnvelope

__all__ = ["evidence_router", "analyse"]

evidence_router = APIRouter(prefix="/v1/evidence", tags=["free"])

#: Nesting deeper than this is not an evidence file. It also keeps every later
#: recursive step (canonical JSON for hashing) far from the interpreter's limit.
MAX_DEPTH = 48

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
        stack.extend((child, depth + 1) for child in children)
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
    """A JSON-lines file (the attestation log format); ``None`` if it is not one."""
    out: list[Any] = []
    for line in text.splitlines():
        if line.strip():
            try:
                out.append(_parse(line))
            except _UnreadableError:
                return None
    return out or None


def _result(
    kind: str, outcome: str, *, scope: str = "", entries: int = 0,
    verified: list[str] | None = None, problems: list[str] | None = None,
    assumptions: list[str] | None = None, not_checked: list[str] | None = None,
    tier: dict[str, Any] | None = None, head: dict[str, Any] | None = None,
    summary: str = "",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "outcome": outcome,
        # True means only: none of the checks that ran found a problem.
        "ok": outcome == "no_inconsistency_found",
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
    }


def _unreadable(problem: str) -> dict[str, Any]:
    return _result(
        "unknown", "unreadable", problems=[problem],
        not_checked=["nothing in the file could be checked."],
        summary="This file could not be read, so nothing was checked.")


# ---------------------------------------------------------------------------
# ledger export
# ---------------------------------------------------------------------------
def _ledger(doc: dict[str, Any]) -> dict[str, Any]:
    v = verify_export(doc)
    not_checked = list(v.checks_skipped)
    if v.head is not None:
        not_checked.append(
            f"to show this is the operator's ledger, compare its head (seq "
            f"{v.head['seq']}, link hash {v.head['link_hash']}) with a signed head "
            "attestation obtained from a channel the operator does not control. "
            "The attestation inside this file is unsigned: it is the exporter's "
            "own statement.")
    if v.ok:
        outcome = "no_inconsistency_found"
        summary = (f"{v.entries} entries, {v.scope}: none of the checks that ran "
                   "found a problem. That is internal consistency only; read "
                   "'Not checked'.")
    else:
        outcome = "inconsistent"
        summary = (f"{len(v.problems)} problem(s) found in {v.entries} readable "
                   f"entries ({v.scope}). This file is not what the exporter wrote, "
                   "or it was not written by an exporter.")
    return _result(
        "ledger_export", outcome, scope=v.scope, entries=v.entries,
        verified=list(v.verified), problems=list(v.problems),
        assumptions=[*v.assumptions, _SERVICE_ASSUMPTION], not_checked=not_checked,
        head=v.head, summary=summary)


# ---------------------------------------------------------------------------
# machine verification bundle
# ---------------------------------------------------------------------------
def _machine(doc: dict[str, Any]) -> dict[str, Any]:
    ok, notes = verify_bundle_data(doc)
    problems = [n for n in notes if not n.startswith("NOT CHECKED:")]
    verified: list[str] = []
    tier: dict[str, Any] | None = None
    body: dict[str, Any] = {}
    try:
        body = Evidence.from_dict(doc["evidence"]).body
    except Exception:  # noqa: BLE001 - verify_bundle_data already reported it
        body = {}

    if not problems:
        # Beyond the seal: `envelope` and `result` sit outside the sealed
        # evidence, so a reader looking at them is looking at unsealed text.
        copy = doc.get("envelope")
        if isinstance(copy, dict):
            try:
                if SafetyEnvelope.from_dict(copy).content_hash() != body.get("envelope_hash"):
                    problems.append(
                        "the envelope copy in the bundle is not the envelope the "
                        "sealed evidence names — the readable copy was changed")
                else:
                    verified.append(
                        "the envelope copy in the bundle hashes to the envelope "
                        "hash sealed inside the evidence")
            except Exception:  # noqa: BLE001 - report, never crash on input
                problems.append("the envelope copy in the bundle cannot be read")
        result = doc.get("result")
        if isinstance(result, dict):
            for key in ("verdict", "tier"):
                if key in result and result[key] != body.get(key):
                    problems.append(
                        f"the bundle's unsealed result block says {key} "
                        f"{result[key]!r}; the sealed evidence says "
                        f"{body.get(key)!r}")
                    break
            else:
                verified.append("the unsealed result block agrees with the sealed "
                                "verdict and tier")

    if not problems:
        checks = body.get("checks") or []
        violated = sum(1 for c in checks if isinstance(c, dict) and c.get("outcome") == "violated")
        unchecked = sum(1 for c in checks if isinstance(c, dict) and c.get("outcome") == "unchecked")
        verified.insert(0, "the sealed evidence object still hashes to the hash it carries")
        verified.insert(1, f"the recorded verdict {body.get('verdict')!r} agrees with the "
                           f"bundle's own {len(checks)} checks ({violated} violated, "
                           f"{unchecked} unchecked)")

    try:
        recorded = AssuranceTier(str(body.get("tier")))
        tier = {
            "recorded_tier": recorded.value,
            "may_claim_physical_behaviour": recorded.may_claim_physical_behaviour,
            "evidence_required": recorded.evidence_required,
        }
    except ValueError:
        tier = {"recorded_tier": body.get("tier"), "may_claim_physical_behaviour": None,
                "evidence_required": ""}
        if not problems:
            problems.append(f"the recorded tier {body.get('tier')!r} is not a tier "
                            "this system defines")
    tier.update({
        "recorded_verdict": body.get("verdict"),
        "product": body.get("product"),
        "product_version": body.get("product_version"),
        "provenance": body.get("provenance"),
        "trace_started_at": body.get("trace_started_at"),
    })

    not_checked = [
        "the original envelope and trace were not supplied, so nothing here shows "
        "the machine behaved as the bundle says. To re-run the engine on them: "
        "`python -m assurance machine check <bundle> --envelope ... --trace ...`.",
        "the tier is the one the bundle records; it was not re-derived from a "
        "trace, and a simulated run cannot support a claim about the real machine.",
        "a bundle on its own does not show it was ever recorded in a ledger, that "
        "it is the latest verification of that machine, or that the software "
        "running on the machine today is the software it describes.",
    ]
    assumptions = [
        "The actor named in the bundle is whoever the writer declared. Nothing "
        "here checks who a person is.",
        _SERVICE_ASSUMPTION,
    ]
    ok_final = not problems
    summary = (
        "The sealed record is internally consistent. That does not show the machine "
        "behaved as recorded; read 'Not checked'." if ok_final else
        f"{len(problems)} problem(s) found: this bundle is not what the verifier "
        "sealed, or it was edited after sealing.")
    return _result(
        "machine_bundle", "no_inconsistency_found" if ok_final else "inconsistent",
        scope=f"{body.get('product', '?')} {body.get('product_version', '')}".strip(),
        entries=1, verified=verified if ok_final else [], problems=problems,
        assumptions=assumptions, not_checked=not_checked, tier=tier, summary=summary)


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
        except (AttestationError, ValueError, KeyError, TypeError) as exc:
            problems.append(f"attestation {index + 1}: unreadable ({exc})")
    if problems:
        return _result(
            "attestation_log", "inconsistent", entries=len(records), problems=problems,
            not_checked=["the records that could be read were not checked either: a "
                         "log with an unreadable record is damaged as a whole."],
            summary="The log has records that cannot be read.")

    assumptions = [_SERVICE_ASSUMPTION]
    latest = records[-1]
    head = {"seq": latest.head_seq, "link_hash": latest.head_link_hash,
            "length": latest.ledger_length}
    not_checked = [
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

    ok = not problems
    return _result(
        "attestation_log", "no_inconsistency_found" if ok else "inconsistent",
        scope=f"attestation log, {len(records)} record(s)", entries=len(records),
        verified=verified if ok else [], problems=problems, assumptions=assumptions,
        not_checked=not_checked, head=head,
        summary=("The log is consistent with itself" + (
            "; signatures verify against the key you supplied." if key_pem.strip()
            else "; signatures were not checked.")) if ok else
        f"{len(problems)} problem(s) found in the attestation log.")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def analyse(raw: bytes, public_key_pem: str = "") -> dict[str, Any]:
    """Classify and check one file. Never raises: every outcome is a result."""
    if not raw.strip():
        return _unreadable("the file is empty")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _unreadable("the file is not UTF-8 text")
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
            return _ledger(doc)
        if isinstance(doc, dict) and (doc.get("schema") == BUNDLE_SCHEMA
                                      or ("evidence" in doc and "envelope" in doc)):
            return _machine(doc)
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


@evidence_router.post(
    "/verify",
    summary="Check an evidence file you were handed. Free, anonymous, stores nothing.",
)
async def verify_evidence(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Anyone],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
    public_key_pem: Annotated[str, Query(
        max_length=4096,
        description="the issuer's Ed25519 public key (PEM), to check attestation "
                    "signatures. Public by nature; omit for other kinds of file.")] = "",
) -> dict[str, Any]:
    """The body is the raw JSON file itself (not wrapped in anything).

    Nothing is stored. The body is read into memory, checked and dropped; the
    only record is the ordinary access log line (method, path, status). The
    answer separates facts established (`verified`), what is taken on trust
    (`assumptions`) and every limit (`not_checked`); there is no bare "valid".
    """
    limit = principal.plan.validations_per_day
    # Spent before the body is read or parsed: an address over its allowance
    # costs the server a header lookup, not a parse.
    spend(principal, "evidence_verify", limit, accounts)
    response.headers["X-Assurance-Tier"] = principal.tier
    response.headers["Cache-Control"] = "no-store"
    if limit is not None:
        used = accounts.usage_today(principal.subject).get("evidence_verify", 0)
        response.headers["X-Assurance-Quota-Limit"] = str(limit)
        response.headers["X-Assurance-Quota-Remaining"] = str(max(0, limit - used))
    raw = await request.body()
    return await run_in_threadpool(analyse, raw, public_key_pem)

