"""Independent review of a limits table: the only route to a VALIDATED limits tier.

A limits table says who transcribed it and, in free text, who checked it. Both
are written by whoever wrote the table, so neither is evidence that anybody
checked anything. A hash pin binds a *claim* to exact bytes; it does not make the
claim true.

What can be checked by a machine is narrower, and this module does exactly that:
a reviewer holding an Ed25519 key signs a statement naming the table's content
hash and edition and the date, and the verifier accepts it only if the key is in
a trust configuration that arrived **separately from the table** and is not
revoked. The result establishes one thing: *the holder of a trusted key
attested, on that date, to having checked these exact bytes*. It does not
establish that the values are right, that the reviewer held a licensed copy, or
that the edition suits the product. The report says so.

Reuses :mod:`assurance.attest.keys` for the key, fingerprint and signature
primitives. A change to the table changes its hash, so a review of the old bytes
no longer applies to the new ones.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from assurance.attest.keys import SigningKey, SigningKeyError, VerifyingKey
from assurance.core.errors import AssuranceError
from assurance.core.identity import canonical_json, content_hash_of

if TYPE_CHECKING:
    from assurance.machine.limits import LimitsTable

__all__ = [
    "LimitsReview",
    "LimitsReviewAssessment",
    "ReviewError",
    "ReviewFinding",
    "ReviewStatus",
    "ReviewTrust",
    "TrustedReviewer",
    "assess_reviews",
    "REVIEW_FORMAT",
    "TRUST_FORMAT",
]

REVIEW_FORMAT = "assurance.machine.limits-review.v1"
TRUST_FORMAT = "assurance.machine.limits-trust.v1"

#: Upper bound on reviews examined per assessment. An assessment is cheap, but a
#: hostile bundle could carry thousands; none is a plausible review history.
MAX_REVIEWS = 32


class ReviewError(AssuranceError):
    """A review or trust file is malformed in a way that cannot be assessed."""


class ReviewStatus(StrEnum):
    """What became of the review evidence. Only ``accepted`` lifts the tier."""

    NONE = "none"                      # no review was supplied
    ACCEPTED = "accepted"
    MALFORMED = "malformed"
    TABLE_MISMATCH = "table_mismatch"  # signed over different content
    EDITION_MISMATCH = "edition_mismatch"
    UNTRUSTED_KEY = "untrusted_key"    # no trust config, or key not in it
    REVOKED_KEY = "revoked_key"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    BAD_SIGNATURE = "bad_signature"


def _iso_date(value: Any, name: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ReviewError(f"{name} {value!r} is not an ISO date (YYYY-MM-DD).") from exc


@dataclass(frozen=True)
class LimitsReview:
    """A signed statement that the holder of a key checked one exact table.

    ``reviewer`` and ``basis`` are the reviewer's own words and are signed, so they
    cannot be altered, but the verifier trusts the *key*, never these strings.
    """

    format: str
    table_hash: str
    edition: str
    reviewer: str
    basis: str
    reviewed_on: str
    expires_on: str
    key_fingerprint: str
    signature: str = ""

    def _body(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "table_hash": self.table_hash,
            "edition": self.edition,
            "reviewer": self.reviewer,
            "basis": self.basis,
            "reviewed_on": self.reviewed_on,
            "expires_on": self.expires_on,
            "key_fingerprint": self.key_fingerprint,
        }

    def signed_payload(self) -> bytes:
        return canonical_json(self._body()).encode("utf-8")

    def content_hash(self) -> str:
        return content_hash_of(self._body())

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "signature": self.signature}

    @classmethod
    def sign(
        cls, table: LimitsTable, key: SigningKey, *, reviewer: str, basis: str,
        reviewed_on: str, expires_on: str = "",
    ) -> LimitsReview:
        """Create a review of ``table`` as it is now. Used by the reviewer, offline."""
        _iso_date(reviewed_on, "reviewed_on")
        if expires_on:
            _iso_date(expires_on, "expires_on")
        if not basis.strip():
            raise ReviewError(
                "a review must state what was checked (basis), e.g. which licensed "
                "copy and edition the values were compared with.")
        unsigned = cls(
            format=REVIEW_FORMAT, table_hash=table.content_hash(),
            edition=table.edition, reviewer=reviewer, basis=basis,
            reviewed_on=reviewed_on, expires_on=expires_on,
            key_fingerprint=key.fingerprint)
        sig = base64.b64encode(key.sign(unsigned.signed_payload())).decode("ascii")
        return cls(**{**unsigned._body(), "signature": sig})

    @classmethod
    def from_dict(cls, data: Any) -> LimitsReview:
        if not isinstance(data, dict):
            raise ReviewError("a limits review must be a JSON object.")
        required = ("format", "table_hash", "edition", "reviewer", "basis",
                    "reviewed_on", "key_fingerprint", "signature")
        missing = [k for k in required if not isinstance(data.get(k), str) or
                   (k != "reviewer" and not data.get(k))]
        if missing:
            raise ReviewError("limits review is missing or has non-text " + ", ".join(missing))
        expires = data.get("expires_on", "")
        if not isinstance(expires, str):
            raise ReviewError("limits review expires_on must be text.")
        if data["format"] != REVIEW_FORMAT:
            raise ReviewError(
                f"limits review format {data['format']!r} is not {REVIEW_FORMAT!r}; "
                "an incompatible version cannot be assessed under these rules.")
        _iso_date(data["reviewed_on"], "reviewed_on")
        if expires:
            _iso_date(expires, "expires_on")
        return cls(
            format=data["format"], table_hash=data["table_hash"],
            edition=data["edition"], reviewer=data["reviewer"], basis=data["basis"],
            reviewed_on=data["reviewed_on"], expires_on=expires,
            key_fingerprint=data["key_fingerprint"], signature=data["signature"])

    def signature_bytes(self) -> bytes:
        try:
            return base64.b64decode(self.signature.encode("ascii"), validate=True)
        except Exception as exc:  # noqa: BLE001 - any decode failure is the same finding
            raise ReviewError(f"review signature is not base64: {exc}") from exc


@dataclass(frozen=True)
class TrustedReviewer:
    """A reviewer key the *verifier* chose to trust, with its own label."""

    label: str
    key: VerifyingKey
    revoked: bool = False
    revoked_on: str = ""

    @property
    def fingerprint(self) -> str:
        return self.key.fingerprint


class ReviewTrust:
    """Which reviewer keys are trusted. Supplied by the verifier, not by the table.

    The fingerprint of an entry is always computed from its public key; a declared
    fingerprint that disagrees is refused, so a typo cannot silently trust the
    wrong key.
    """

    def __init__(self, reviewers: Iterable[TrustedReviewer] = ()) -> None:
        self._by_fp: dict[str, TrustedReviewer] = {}
        for r in reviewers:
            if r.fingerprint in self._by_fp:
                raise ReviewError(f"reviewer key {r.fingerprint} is listed twice.")
            self._by_fp[r.fingerprint] = r

    def get(self, fingerprint: str) -> TrustedReviewer | None:
        return self._by_fp.get(fingerprint)

    def __len__(self) -> int:
        return len(self._by_fp)

    @property
    def reviewers(self) -> tuple[TrustedReviewer, ...]:
        return tuple(self._by_fp.values())

    @classmethod
    def from_dict(cls, data: Any) -> ReviewTrust:
        if not isinstance(data, dict) or data.get("format") != TRUST_FORMAT:
            raise ReviewError(f"a limits trust file must be an object with format {TRUST_FORMAT!r}.")
        raw = data.get("reviewers")
        if not isinstance(raw, list):
            raise ReviewError("limits trust file has no 'reviewers' list.")
        out: list[TrustedReviewer] = []
        for i, r in enumerate(raw):
            if not isinstance(r, dict) or not isinstance(r.get("public_key_pem"), str):
                raise ReviewError(f"reviewer #{i} needs a public_key_pem.")
            try:
                key = VerifyingKey.from_pem(r["public_key_pem"])
            except SigningKeyError as exc:
                raise ReviewError(f"reviewer #{i}: {exc}") from exc
            declared = r.get("fingerprint")
            if declared is not None and declared != key.fingerprint:
                raise ReviewError(
                    f"reviewer #{i} declares fingerprint {declared!r} but its key is "
                    f"{key.fingerprint}. Refusing to trust a key whose pinned "
                    "fingerprint does not match.")
            revoked_on = str(r.get("revoked_on", ""))
            if revoked_on:
                _iso_date(revoked_on, "revoked_on")
            out.append(TrustedReviewer(
                label=str(r.get("label", "")), key=key,
                revoked=bool(r.get("revoked", False)) or bool(revoked_on),
                revoked_on=revoked_on))
        return cls(out)

    @classmethod
    def from_json(cls, path: str | Path) -> ReviewTrust:
        p = Path(path)
        try:
            return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except OSError as exc:
            raise ReviewError(f"cannot read limits trust file {p}: {exc}") from exc
        except ValueError as exc:
            raise ReviewError(f"{p} is not valid JSON: {exc}") from exc


@dataclass(frozen=True)
class ReviewFinding:
    """What happened to one supplied review."""

    status: ReviewStatus
    detail: str
    key_fingerprint: str = ""
    review_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "detail": self.detail,
                "key_fingerprint": self.key_fingerprint, "review_hash": self.review_hash}


@dataclass(frozen=True)
class LimitsReviewAssessment:
    """The outcome of assessing every supplied review against one table."""

    table_hash: str
    status: ReviewStatus
    accepted: LimitsReview | None
    reviewer_label: str
    findings: tuple[ReviewFinding, ...]
    #: Every review as supplied, so a sealed bundle carries what a later verifier
    #: must re-assess under its own trust configuration.
    submitted: tuple[Any, ...] = ()
    #: The day expiry was judged against. Sealed, so replay judges the same day.
    assessed_on: str = ""

    @property
    def validated(self) -> bool:
        return self.status is ReviewStatus.ACCEPTED

    @property
    def explanation(self) -> str:
        """The sentence for the report: what was checked, by whom, on what basis."""
        if self.accepted is not None:
            r = self.accepted
            # The verifier's own label for the key is deliberately not in the
            # sentence: it would make the sealed text differ between verifiers.
            who = f"named in the review as {r.reviewer!r}, the reviewer's own text"
            return (
                f"the limits table {self.table_hash[:12]} carries a review signed by key "
                f"{r.key_fingerprint} ({who}), which this verifier's own trust "
                f"configuration lists and has not revoked; it names exactly this table "
                f"content and edition {r.edition!r}, dated {r.reviewed_on}"
                + (f", valid until {r.expires_on}" if r.expires_on else "")
                + f". The reviewer states the basis as: {r.basis!r}. This establishes "
                "that the key holder attested to these bytes; it does not establish that "
                "the values are correct, that a licensed copy was used, or that the "
                "edition suits this product.")
        if self.status is ReviewStatus.NONE:
            return (
                "no independent review of the limits table was supplied, so it is an "
                "unreviewed transcription and caps the tier at community. The table's own "
                "verified_by / verified_on text is the author's claim and is not evidence.")
        detail = "; ".join(f.detail for f in self.findings)
        return (
            f"review evidence for the limits table was supplied but not accepted "
            f"({self.status.value}): {detail}. The tier is capped at community.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "table_hash": self.table_hash,
            "status": self.status.value,
            "assessed_on": self.assessed_on,
            "validated": self.validated,
            "accepted_review": self.accepted.to_dict() if self.accepted else None,
            "findings": [f.to_dict() for f in self.findings],
            "reviews": list(self.submitted),
            "explanation": self.explanation,
        }


def assess_reviews(
    table: LimitsTable,
    reviews: Iterable[Any],
    trust: ReviewTrust | None,
    *,
    now: datetime | None = None,
) -> LimitsReviewAssessment:
    """Decide whether any supplied review lifts ``table`` to a validated limits tier.

    Fail-closed: every defect leaves the status short of ``accepted`` and the
    findings say which one. ``reviews`` may be review objects or raw dicts, so a
    malformed one is reported rather than raised past the caller.
    """
    today = (now or datetime.now(UTC)).date()
    on = today.isoformat()
    table_hash = table.content_hash()
    supplied = list(reviews)[: MAX_REVIEWS + 1]
    if not supplied:
        return LimitsReviewAssessment(table_hash, ReviewStatus.NONE, None, "", (), (), on)
    raw = tuple(r.to_dict() if isinstance(r, LimitsReview) else r for r in supplied)
    findings: list[ReviewFinding] = []
    if len(supplied) > MAX_REVIEWS:
        findings.append(ReviewFinding(
            ReviewStatus.MALFORMED, f"more than {MAX_REVIEWS} reviews supplied; only "
            "the first were examined"))
        supplied = supplied[:MAX_REVIEWS]
    accepted: LimitsReview | None = None
    label = ""
    for item in supplied:
        try:
            review = item if isinstance(item, LimitsReview) else LimitsReview.from_dict(item)
        except ReviewError as exc:
            findings.append(ReviewFinding(ReviewStatus.MALFORMED, str(exc)))
            continue
        fp, rh = review.key_fingerprint, review.content_hash()

        def bad(status: ReviewStatus, detail: str, fp: str = fp, rh: str = rh) -> None:
            findings.append(ReviewFinding(status, detail, fp, rh))

        if review.format != REVIEW_FORMAT:
            bad(ReviewStatus.MALFORMED, f"incompatible format {review.format!r}")
            continue
        entry = trust.get(fp) if trust is not None else None
        if entry is None:
            bad(ReviewStatus.UNTRUSTED_KEY,
                f"key {fp} is not in the trust configuration"
                if trust is not None and len(trust) else
                f"key {fp} cannot be trusted: no reviewer trust configuration was supplied")
            continue
        if entry.revoked:
            bad(ReviewStatus.REVOKED_KEY,
                f"key {fp} ({entry.label or 'unlabelled'}) is revoked"
                + (f" as of {entry.revoked_on}" if entry.revoked_on else ""))
            continue
        try:
            sig = review.signature_bytes()
        except ReviewError as exc:
            bad(ReviewStatus.MALFORMED, str(exc))
            continue
        if not entry.key.verify(review.signed_payload(), sig):
            bad(ReviewStatus.BAD_SIGNATURE,
                f"the signature does not verify under key {fp} over the stated content")
            continue
        # The signature is genuine; now ask whether it is about *this* table.
        if review.table_hash != table_hash:
            bad(ReviewStatus.TABLE_MISMATCH,
                f"the review covers table {review.table_hash[:12]}, not {table_hash[:12]}; "
                "the table was changed after it was reviewed, or this is another table")
            continue
        if review.edition != table.edition:
            bad(ReviewStatus.EDITION_MISMATCH,
                f"the review names edition {review.edition!r}, the table {table.edition!r}")
            continue
        if _iso_date(review.reviewed_on, "reviewed_on") > today:
            bad(ReviewStatus.NOT_YET_VALID, f"the review is dated {review.reviewed_on}, in the future")
            continue
        if review.expires_on and _iso_date(review.expires_on, "expires_on") < today:
            bad(ReviewStatus.EXPIRED, f"the review expired on {review.expires_on}")
            continue
        if accepted is None:
            accepted, label = review, entry.label
    if accepted is not None:
        return LimitsReviewAssessment(
            table_hash, ReviewStatus.ACCEPTED, accepted, label, tuple(findings), raw, on)
    # No review was accepted: report the first defect as the headline.
    return LimitsReviewAssessment(
        table_hash, findings[0].status if findings else ReviewStatus.MALFORMED,
        None, "", tuple(findings), raw, on)
