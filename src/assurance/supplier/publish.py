"""Signed component advisories, and the feed a supplier cannot quietly edit.

Today a safety-relevant component advisory reaches an integrator as a PDF
attached to an email, or a link in a newsletter. Nothing about it is verifiable.
Which means the following attack is available to anybody with a mail server and
a letterhead:

    From: security@controlco-support.example
    Subject: URGENT — safety controller firmware 3.9.0 advisory
    Action required within 24 hours: flash the attached image on all units.

An integrator who acts on that has just been induced to modify the safety
system of a machine that people stand next to. This is not a data breach with a
regulatory notification attached; it is a physical safety incident delivered by
email. The industry's current defence is that the recipient recognises the
sender's writing style.

Signing closes it. An advisory carries an Ed25519 signature by the supplier's
publishing key, and an integrator's tooling refuses to act on one that does not
verify. That is the whole idea, and the reason it is not already done everywhere
is not that it is hard.

Two further properties come from making the feed a chain rather than a list:

**A supplier cannot silently un-publish.** Each record names the content hash of
the previous record from that supplier. Remove one and the chain breaks at a
named position. This matters because the commercial incentive on a supplier who
has published an embarrassing advisory is to make it go away, and an integrator
who acted on it needs it to still exist.

**A withdrawal is a publication, not a deletion.** A supplier who got an
advisory wrong publishes a signed withdrawal that names it. Integrators already
acted on the original; erasing it leaves them holding a change nobody can
explain, which is worse than the wrong advisory was.

What this does not do, stated here because the limits travel with the claim:
it does not establish that the key belongs to the supplier. That is the one
thing cryptography cannot bootstrap. A fingerprint has to arrive by a route the
advisories do not travel on — a contract, a purchase order, a printed sheet in
the machine's documentation folder, a phone call. Sixteen hex characters read
aloud is a real and sufficient method, and the tooling prints them for exactly
that reason.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from ..attest.keys import SigningKey, VerifyingKey
from ..core.errors import AssuranceError
from ..core.identity import canonical_json, content_hash_of, format_utc, utc_now
from ..fleet.advisory import ComponentAdvisory

__all__ = [
    "FEED_FORMAT",
    "AdvisoryFeed",
    "FeedVerdict",
    "PublishError",
    "SignedAdvisory",
    "SupplierIdentity",
    "publish",
    "verify_feed",
    "withdraw",
]

#: Written into every record so a future reader knows what the signed bytes
#: were. Changing what is signed without changing this would make old
#: signatures fail for a reason nobody could diagnose.
FEED_FORMAT = "assurance.supplier-feed.v1"


class PublishError(AssuranceError):
    """An advisory cannot be published, or a feed does not hold up."""


@dataclass(frozen=True)
class SupplierIdentity:
    """Who is publishing, and how a stranger confirms the key is theirs."""

    supplier_id: str
    legal_name: str
    #: Where a reader goes to confirm the fingerprint by a route that is not
    #: this feed. Required: a key that can only be checked against the thing it
    #: signs establishes nothing.
    key_contact: str

    def __post_init__(self) -> None:
        if not self.supplier_id.strip() or not self.legal_name.strip():
            raise PublishError("a supplier needs an id and a legal name.")
        if any(c.isspace() or c in '/\\"' for c in self.supplier_id):
            raise PublishError(
                f"supplier_id {self.supplier_id!r} must be a single plain token: "
                "it names a file and appears in a URL."
            )
        if not self.key_contact.strip():
            raise PublishError(
                "key_contact is empty. Publish where a reader can confirm this "
                "key's fingerprint by some route other than this feed — a "
                "contract, the machine's documentation folder, a telephone "
                "number. A key checked only against what it signs proves that "
                "one party was consistent, and nothing else."
            )

    def to_dict(self) -> dict[str, Any]:
        return {"supplier_id": self.supplier_id, "legal_name": self.legal_name,
                "key_contact": self.key_contact}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SupplierIdentity:
        return cls(
            supplier_id=str(d.get("supplier_id", "")),
            legal_name=str(d.get("legal_name", "")),
            key_contact=str(d.get("key_contact", "")),
        )


@dataclass(frozen=True)
class SignedAdvisory:
    """One advisory as published: signed, positioned, and chained."""

    format: str
    sequence: int
    supplier: SupplierIdentity
    key_fingerprint: str
    published_at: str
    previous: str
    advisory: dict[str, Any]
    #: Set on a record that withdraws an earlier one. The withdrawn advisory is
    #: never removed; integrators already acted on it.
    withdraws: str = ""
    withdrawal_reason: str = ""
    signature: str = ""

    def _body(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "sequence": self.sequence,
            "supplier": self.supplier.to_dict(),
            "key_fingerprint": self.key_fingerprint,
            "published_at": self.published_at,
            "previous": self.previous,
            "advisory": self.advisory,
            "withdraws": self.withdraws,
            "withdrawal_reason": self.withdrawal_reason,
        }

    def signed_payload(self) -> bytes:
        return canonical_json(self._body()).encode("utf-8")

    def content_hash(self) -> str:
        return content_hash_of(self._body())

    @property
    def advisory_id(self) -> str:
        return str(self.advisory.get("advisory_id", ""))

    @property
    def is_withdrawal(self) -> bool:
        return bool(self.withdraws)

    def component(self) -> ComponentAdvisory:
        """The advisory itself, for the fleet engine to match against."""
        return ComponentAdvisory.from_dict(self.advisory)

    def verified_by(self, key: VerifyingKey) -> bool:
        if not self.signature:
            return False
        try:
            raw = base64.b64decode(self.signature.encode("ascii"), validate=True)
        except Exception as exc:  # noqa: BLE001 - any decode failure is one finding
            raise PublishError(
                f"advisory {self.advisory_id or self.sequence} carries a "
                f"signature that is not base64 ({exc}). Treat the feed as "
                "damaged, not as unsigned."
            ) from exc
        return key.verify(self.signed_payload(), raw)

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "signature": self.signature}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SignedAdvisory:
        missing = [k for k in ("format", "sequence", "supplier", "key_fingerprint",
                               "published_at", "previous", "advisory") if k not in d]
        if missing:
            raise PublishError(
                "feed record is missing " + ", ".join(missing)
                + " — it was not written by this system, or it was edited."
            )
        return cls(
            format=str(d["format"]),
            sequence=int(d["sequence"]),
            supplier=SupplierIdentity.from_dict(d["supplier"]),
            key_fingerprint=str(d["key_fingerprint"]),
            published_at=str(d["published_at"]),
            previous=str(d["previous"]),
            advisory=dict(d["advisory"]),
            withdraws=str(d.get("withdraws", "")),
            withdrawal_reason=str(d.get("withdrawal_reason", "")),
            signature=str(d.get("signature", "")),
        )


class AdvisoryFeed:
    """A supplier's append-only feed, one JSON record per line.

    Deliberately a text file. A supplier must be able to serve it from any web
    server, an integrator must be able to copy it onto a USB stick and carry it
    into a plant with no network, and both must be able to read it without this
    software installed.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read(self) -> list[SignedAdvisory]:
        if not self.path.exists():
            return []
        out: list[SignedAdvisory] = []
        for number, line in enumerate(self.path.read_text("utf-8").splitlines(), 1):
            text = line.strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise PublishError(
                    f"{self.path} line {number} is not JSON ({exc})."
                ) from exc
            out.append(SignedAdvisory.from_dict(data))
        return out

    def last(self) -> SignedAdvisory | None:
        records = self.read()
        return records[-1] if records else None

    def append(self, record: SignedAdvisory) -> SignedAdvisory:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), sort_keys=True,
                                    separators=(",", ":")) + "\n")
        return record

    def __len__(self) -> int:
        return len(self.read())


def _next(
    feed: AdvisoryFeed,
    identity: SupplierIdentity,
    key: SigningKey,
    rotating: bool,
) -> tuple[int, str, list[SignedAdvisory]]:
    history = feed.read()
    previous = history[-1] if history else None
    if previous is not None:
        if previous.supplier.supplier_id != identity.supplier_id:
            raise PublishError(
                f"this feed belongs to {previous.supplier.supplier_id!r} and you "
                f"are publishing as {identity.supplier_id!r}. One feed, one "
                "supplier: an integrator pins a key to a feed, and two suppliers "
                "sharing one file makes that pinning meaningless."
            )
        if previous.key_fingerprint != key.fingerprint and not rotating:
            raise PublishError(
                f"this feed was signed by key {previous.key_fingerprint} and the "
                f"key offered is {key.fingerprint}. If this is a deliberate "
                "rotation, say so explicitly and tell your customers the new "
                "fingerprint by the route in key_contact — otherwise this is "
                "what it looks like when somebody else starts publishing under "
                "your name."
            )
    return (
        (previous.sequence + 1) if previous else 1,
        previous.content_hash() if previous else "",
        history,
    )


def publish(
    advisory: ComponentAdvisory,
    identity: SupplierIdentity,
    key: SigningKey,
    feed: AdvisoryFeed,
    *,
    rotating: bool = False,
    now: datetime | None = None,
) -> SignedAdvisory:
    """Sign an advisory and append it to the supplier's feed.

    Refuses to publish the same ``advisory_id`` twice. A corrected advisory gets
    a new id and, if the first was wrong rather than incomplete, a signed
    withdrawal of it — because an integrator who already acted on the first one
    needs both records to exist.
    """
    sequence, previous, history = _next(feed, identity, key, rotating)

    for earlier in history:
        if earlier.advisory_id == advisory.advisory_id and not earlier.is_withdrawal:
            raise PublishError(
                f"{advisory.advisory_id} was already published at "
                f"{earlier.published_at} (sequence {earlier.sequence}). Republishing "
                "an id silently changes what your customers think they read. Give "
                "the correction a new id, and withdraw this one if it was wrong."
            )

    if advisory.issued_by != identity.supplier_id and \
            advisory.issued_by != identity.legal_name:
        raise PublishError(
            f"the advisory says issued_by={advisory.issued_by!r} and you are "
            f"publishing as {identity.supplier_id!r} ({identity.legal_name!r}). "
            "A feed that carries somebody else's advisory under your signature "
            "makes you the source of it."
        )

    record = SignedAdvisory(
        format=FEED_FORMAT,
        sequence=sequence,
        supplier=identity,
        key_fingerprint=key.fingerprint,
        published_at=format_utc(now if now is not None else utc_now()),
        previous=previous,
        advisory=advisory.to_dict(),
    )
    return feed.append(replace(
        record,
        signature=base64.b64encode(key.sign(record.signed_payload())).decode("ascii"),
    ))


def withdraw(
    advisory_id: str,
    reason: str,
    identity: SupplierIdentity,
    key: SigningKey,
    feed: AdvisoryFeed,
    *,
    rotating: bool = False,
    now: datetime | None = None,
) -> SignedAdvisory:
    """Publish a signed withdrawal of an earlier advisory.

    The original stays in the feed. Deleting it would leave every integrator who
    acted on it holding an unexplained change to a safety system, which is worse
    than the wrong advisory was.
    """
    if not reason.strip():
        raise PublishError(
            "a withdrawal needs a reason. Your customers changed a machine "
            "because of the original; 'withdrawn' without a reason tells them "
            "nothing about whether to change it back."
        )
    sequence, previous, history = _next(feed, identity, key, rotating)

    target = next((r for r in history
                   if r.advisory_id == advisory_id and not r.is_withdrawal), None)
    if target is None:
        raise PublishError(
            f"{advisory_id} is not in this feed, so there is nothing to withdraw."
        )
    if any(r.withdraws == advisory_id for r in history):
        raise PublishError(f"{advisory_id} has already been withdrawn.")

    record = SignedAdvisory(
        format=FEED_FORMAT,
        sequence=sequence,
        supplier=identity,
        key_fingerprint=key.fingerprint,
        published_at=format_utc(now if now is not None else utc_now()),
        previous=previous,
        advisory=target.advisory,
        withdraws=advisory_id,
        withdrawal_reason=reason,
    )
    return feed.append(replace(
        record,
        signature=base64.b64encode(key.sign(record.signed_payload())).decode("ascii"),
    ))


@dataclass(frozen=True)
class FeedVerdict:
    """What a reader can say about a feed, and what they still cannot."""

    ok: bool
    checked: int
    supplier_id: str = ""
    key_fingerprint: str = ""
    problems: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)
    live: tuple[SignedAdvisory, ...] = ()
    withdrawn: tuple[str, ...] = ()

    def summary(self) -> str:
        if self.checked == 0:
            return ("the feed is EMPTY — nothing was verified, and an empty feed "
                    "is not the same as a supplier with nothing to report")
        if self.ok:
            return (
                f"{self.checked} record(s) from {self.supplier_id} verify against "
                f"key {self.key_fingerprint}; {len(self.live)} advisory(ies) stand, "
                f"{len(self.withdrawn)} withdrawn"
            )
        return f"{len(self.problems)} problem(s) across {self.checked} record(s)"


def verify_feed(
    records: Iterable[SignedAdvisory],
    key: VerifyingKey,
    *,
    expect_supplier: str = "",
) -> FeedVerdict:
    """Check a supplier feed before anything acts on it.

    Every signature valid, the sequence unbroken, each record naming its
    predecessor, one supplier throughout, no advisory id published twice. A
    feed that fails any of these must not drive a change to a safety system,
    which is what ``assurance fleet advisory`` enforces by refusing it.
    """
    items = list(records)
    problems: list[str] = []
    skipped: list[str] = []

    # An empty feed must not verify. The commonest way to end up holding one is
    # a wrong path or a failed download, and "ok, nothing affects you" is the
    # worst possible answer to give somebody who is actually exposed. Silence
    # from a supplier and silence from a broken pipe look identical here, so
    # this refuses both rather than guessing which it was.
    if not items:
        problems.append(
            "the feed is empty. That is either a supplier who has published "
            "nothing or a file that did not arrive, and nothing in the file can "
            "tell you which. Check the path and the download before concluding "
            "your fleet is unaffected."
        )

    expected = 1
    previous: SignedAdvisory | None = None
    suppliers: set[str] = set()
    fingerprints: set[str] = set()
    live: dict[str, SignedAdvisory] = {}
    withdrawn: list[str] = []

    for record in items:
        where = f"record {record.sequence}"
        if record.format != FEED_FORMAT:
            problems.append(
                f"{where}: format is {record.format!r}, this build verifies "
                f"{FEED_FORMAT!r} — the signed bytes may not be what is "
                "recomputed here"
            )
        if record.sequence != expected:
            problems.append(
                f"{where}: out of order, expected {expected} — a record was "
                "removed from the feed, or the file was reordered"
            )
            expected = record.sequence
        expected_previous = previous.content_hash() if previous else ""
        if record.previous != expected_previous:
            problems.append(
                f"{where}: names predecessor "
                f"{record.previous[:12] or '(none)'} but follows "
                f"{expected_previous[:12] or '(none)'} — a record was withdrawn "
                "from the file rather than withdrawn in it"
            )
        if not record.verified_by(key):
            problems.append(
                f"{where} ({record.advisory_id}): signature does not verify "
                f"against key {key.fingerprint}. Do not act on this advisory."
            )
        suppliers.add(record.supplier.supplier_id)
        fingerprints.add(record.key_fingerprint)

        if record.is_withdrawal:
            if record.withdraws not in live:
                problems.append(
                    f"{where}: withdraws {record.withdraws}, which this feed "
                    "does not contain as a standing advisory"
                )
            else:
                live.pop(record.withdraws, None)
                withdrawn.append(record.withdraws)
        else:
            if record.advisory_id in live:
                problems.append(
                    f"{where}: advisory id {record.advisory_id} was already "
                    "published in this feed"
                )
            live[record.advisory_id] = record

        previous = record
        expected += 1

    if len(suppliers) > 1:
        problems.append(
            "the feed carries more than one supplier ("
            + ", ".join(sorted(suppliers))
            + "). An integrator pins one key to one feed; this cannot be verified "
            "as a whole."
        )
    if expect_supplier and suppliers and expect_supplier not in suppliers:
        problems.append(
            f"expected a feed from {expect_supplier!r} and this one is from "
            + ", ".join(sorted(suppliers))
        )
    if len(fingerprints) > 1:
        problems.append(
            "the feed names more than one signing key ("
            + ", ".join(sorted(fingerprints))
            + "). A rotation is legitimate but must be verified against each key "
            "over its own span; this check used one."
        )

    skipped.append(
        f"Whether key {key.fingerprint} belongs to this supplier was not "
        "checked, and cannot be checked from inside the feed. Confirm the "
        "fingerprint by the route the supplier published for that purpose"
        + (f" ({items[0].supplier.key_contact})" if items else "")
        + " — not by a link in the advisory."
    )
    skipped.append(
        "A verified feed says these advisories came from the holder of that key "
        "and have not been altered. It says nothing about whether they are "
        "correct, complete, or timely. A supplier who has not noticed a "
        "vulnerability publishes nothing, and this cannot tell you that."
    )

    return FeedVerdict(
        ok=not problems,
        checked=len(items),
        supplier_id=next(iter(sorted(suppliers))) if suppliers else "",
        key_fingerprint=key.fingerprint,
        problems=problems,
        checks_skipped=skipped,
        live=tuple(live.values()),
        withdrawn=tuple(withdrawn),
    )
