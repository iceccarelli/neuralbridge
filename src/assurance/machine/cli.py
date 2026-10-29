"""``assurance machine`` — verify a run, seal a bundle, re-check somebody else's.

Three verbs, and the third is the one that sells the first two.

``separation``
    Print S(t0) term by term for a declared envelope at a given speed. This is
    the thirty-second demonstration: an integrator reads their own light-curtain
    distance off the wall and compares it to the number that comes out.

``verify``
    Compare a trace against an envelope and seal the result into the ledger.
    Exits non-zero on a violation, so it belongs in a commissioning pipeline.

``check``
    Re-verify a bundle somebody else produced. Exits non-zero if the bundle was
    edited, if its verdict disagrees with its own checks, or if re-running the
    engine on the named inputs does not reproduce it. With ``--recorder-trust`` (your
    own list of recorder keys) a recorder attestation recorded in the bundle is
    re-assessed; without it a bundle that claims ``recorder_attested`` is NOT believed.

``recorder-sign``
    Run by the recorder operator, offline, on their own side: sign one trace as a
    recorder attestation with the recorder's private key. The key is read from a file
    here and goes nowhere else; it is never embedded in a bundle or sent to the API.

``recorder-trust``
    Add a recorder's PUBLIC key, with the provenance classes it may attest, to your own
    recorder trust file (the list ``verify`` / ``check`` take as ``--recorder-trust``).

An accepted attestation shows that a key you trust signed these exact trace bytes. It
does not show the recording is physically true, that the recorder was calibrated or
uncompromised, or that the machine is safe.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from assurance.attest.keys import SigningKey, VerifyingKey
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import (
    MachineSubjectError,
    build_bundle,
    check_bundle,
    resolve_machine_serial,
)
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
from assurance.machine.limits_review import ReviewTrust
from assurance.machine.recorder_attestation import (
    LIFTABLE_PROVENANCE,
    NOT_PROVED,
    PRIVATE_KEY_MESSAGE,
    RecorderAttestation,
    RecorderAttestationError,
    RecorderTrust,
    TrustedRecorder,
    load_attestation_file,
)
from assurance.machine.ssm import separation_required
from assurance.machine.trace import Trace
from assurance.machine.verify import Verdict

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance machine",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    sep = verbs.add_parser(
        "separation", help="print the protective separation distance, term by term")
    sep.add_argument("--envelope", required=True, type=Path)
    sep.add_argument("--speed", required=True, type=float,
                     help="TCP speed in mm/s")
    sep.add_argument("--human-speed", type=float, default=None,
                     help="closing speed in mm/s; omit to use the declared figure")
    sep.add_argument("--json", action="store_true")

    ver = verbs.add_parser("verify", help="verify a trace against an envelope")
    ver.add_argument("--envelope", required=True, type=Path)
    ver.add_argument("--trace", required=True, type=Path)
    ver.add_argument("--limits", type=Path, default=None,
                     help="body-region limits table for a power-and-force claim")
    ver.add_argument("--limits-review", type=Path, action="append", default=[],
                     help="signed review of the limits table (repeatable); only an "
                          "accepted review lifts the limits tier above community")
    ver.add_argument("--limits-trust", type=Path, default=None,
                     help="reviewer trust list obtained independently of the table; "
                          "without it no review can be accepted")
    ver.add_argument("--recorder-attestation", type=Path, action="append", default=[],
                     help="signed recorder attestation of the trace (repeatable); only one "
                          "accepted under YOUR --recorder-trust lifts the provenance above "
                          "community")
    ver.add_argument("--recorder-trust", type=Path, default=None,
                     help="your own recorder trust list (assurance.machine.recorder-trust."
                          "v1) obtained independently of the trace; without it no "
                          "attestation can be accepted")
    ver.add_argument("--machine-serial", default="",
                     help="the unit this verification is about; an attestation naming a "
                          "different serial is refused (default: the serial in a "
                          "--subject of the form maker/model#serial)")
    ver.add_argument("--actor", required=True,
                     help="who is signing this verification, e.g. 'v.grimaldi'")
    ver.add_argument("--role", default="verification engineer")
    ver.add_argument("--ledger", type=Path, default=None,
                     help="append the sealed bundle to this evidence ledger")
    ver.add_argument("--subject", default="",
                     help="file the bundle in the ledger under this subject. Give the "
                          "machine's key (manufacturer/model#serial) for it to count as "
                          "evidence for that unit; default is product@version")
    ver.add_argument("--out", type=Path, default=None, help="write the bundle here")
    ver.add_argument("--json", action="store_true")

    chk = verbs.add_parser("check", help="re-verify a bundle you did not produce")
    chk.add_argument("bundle", type=Path)
    chk.add_argument("--envelope", type=Path, default=None)
    chk.add_argument("--trace", type=Path, default=None)
    chk.add_argument("--as-of", default="",
                     help="ISO time to judge a limits review's expiry against "
                          "(default: now)")
    chk.add_argument("--limits-trust", type=Path, default=None,
                     help="your own reviewer trust list, to re-assess the limits "
                          "review sealed in the bundle")
    chk.add_argument("--recorder-trust", type=Path, default=None,
                     help="your own recorder trust list, to re-assess the recorder "
                          "attestation sealed in the bundle. Without it a bundle that "
                          "claims recorder_attested is not believed (capped at community)")
    chk.add_argument("--machine-serial", default=None,
                     help="the unit you say the bundle is about (default: the one it "
                          "records)")
    chk.add_argument("--limits", type=Path, default=None,
                     help="the body-region limits table the bundle was verified "
                          "against, if it used one")
    chk.add_argument("--json", action="store_true")

    sign = verbs.add_parser(
        "recorder-sign",
        help="(recorder operator, offline) sign a trace as a recorder attestation")
    sign.add_argument("--key", required=True, type=Path,
                      help="the recorder's PRIVATE key (PEM); read here, never stored in "
                           "the attestation or sent anywhere")
    sign.add_argument("--passphrase-env", default=None,
                      help="environment variable holding the key's passphrase")
    sign.add_argument("--trace", required=True, type=Path)
    sign.add_argument("--product", required=True,
                      help="the product the recorder was attached to (matched against "
                           "the verification's envelope)")
    sign.add_argument("--product-version", required=True)
    sign.add_argument("--machine-serial", default="",
                      help="the unit the recorder was attached to (optional)")
    sign.add_argument("--recorder-id", required=True,
                      help="the recorder's own label: signed, never trusted")
    sign.add_argument("--attested-on", default="",
                      help="ISO date of the attestation (default: today, UTC)")
    sign.add_argument("--expires-on", default="", help="ISO date it stops being valid")
    sign.add_argument("--attestation-id", default="",
                      help="a unique id (default: random)")
    sign.add_argument("--out", required=True, type=Path,
                      help="where the attestation goes (must not exist)")

    rt = verbs.add_parser(
        "recorder-trust",
        help="add a recorder's PUBLIC key to your recorder trust file")
    rt.add_argument("--trust", required=True, type=Path,
                    help="the trust file to create or extend")
    rt.add_argument("--public-key", required=True, type=Path)
    rt.add_argument("--label", required=True, help="your own name for the key")
    rt.add_argument("--provenance", required=True,
                    help="comma list of what the key may attest: bench, field")

    return p


def _unit_key_problem(subject: str) -> str:
    """Why *subject* is not a unit key (``manufacturer/model#serial``); "" if it is.

    Only the spelling is judged, never whether the unit exists. The ``#serial`` grammar is
    the one every reader of a ledger subject uses (``resolve_machine_serial``, shared with
    ``machinery.staleness``), not a copy of it; what this adds is the shape of the key a
    manifest writes (``MachineIdentity.key``): a maker and a model, neither empty nor padded.
    Coverage, the passport and re-verification look a verification up under that key exactly,
    so any other spelling is filed and never found.
    """
    if "#" not in subject:
        return "it has no '#serial'"
    try:
        resolve_machine_serial(subject)
    except MachineSubjectError as exc:
        return str(exc).split(": ", 1)[-1].split(". ")[0]
    head = subject.split("#", 1)[0]
    parts = head.split("/")
    if len(parts) < 2 or any(not p for p in parts):
        return "it does not name a manufacturer/model before the '#' (an empty part)"
    if any(p != p.strip() for p in parts):
        return "its manufacturer or model starts or ends with a space"
    return ""


def _subject_warning(subject: str, ledger: EvidenceLedger | None) -> str:
    """What to tell the person when this subject will not be found by coverage. "" if fine.

    A warning, never a refusal: a product-line subject (``product@version``) is accepted,
    and what is accepted does not change. Printed to stderr so ``--json`` stays a document.
    """
    if not subject:
        return ""
    problem = _unit_key_problem(subject)
    if problem:
        return (
            f"warning: --subject {subject!r} is not a unit key ({problem}), so coverage "
            "will not see this verification: it is looked up under the machine's key "
            "written exactly manufacturer/model#serial, as the manifest records it.")
    if ledger is not None:
        from assurance.machinery.record import MANIFEST_KIND

        known = {e.subject for e in ledger.entries(kind=MANIFEST_KIND)}
        if subject not in known:
            return (
                f"warning: this ledger holds no manifest recorded for {subject!r}, so "
                "coverage will not see this verification unless that is exactly the "
                "machine's key as its manifest writes it"
                + (f" (manifests here: {', '.join(sorted(known))})." if known else "."))
    return ""


def _read_trust(path: Path | None) -> RecorderTrust | None:
    return RecorderTrust.from_json(path) if path else None


def _cmd_separation(args: argparse.Namespace) -> int:
    envelope = SafetyEnvelope.from_json(args.envelope)
    b = separation_required(envelope, robot_speed_mm_s=args.speed,
                            human_speed_mm_s=args.human_speed)
    if args.json:
        print(json.dumps(b.to_dict(), indent=2))
        return 0
    print(f"{envelope.product} {envelope.product_version}  "
          f"envelope {envelope.content_hash()[:12]}")
    print(f"  TCP speed          {args.speed:.0f} mm/s")
    print(f"  human closing      {b.human_speed_mm_s:.0f} mm/s ({b.human_speed_source})")
    print()
    print(f"  Sh human travel    {b.human_travel_mm:8.0f} mm")
    print(f"  Sr robot reaction  {b.robot_reaction_travel_mm:8.0f} mm")
    print(f"  Ss robot stopping  {b.robot_stopping_travel_mm:8.0f} mm  "
          f"({b.stopping_basis})")
    print(f"  C  intrusion       {b.intrusion_mm:8.0f} mm")
    print(f"  Zd human uncert.   {b.human_uncertainty_mm:8.0f} mm")
    print(f"  Zr robot uncert.   {b.robot_uncertainty_mm:8.0f} mm")
    print(f"  {'-' * 32}")
    print(f"  S  required        {b.total_mm:8.0f} mm")
    if b.rests_on_extrapolation:
        print()
        print("  Ss is extrapolated: this speed is above the one the stopping")
        print(f"  distance was measured at "
              f"({envelope.stop.measured_at_speed_mm_s:.0f} mm/s). The number above "
              "is a model.")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    envelope = SafetyEnvelope.from_json(args.envelope)
    trace = Trace.from_json(args.trace)
    limits = LimitsTable.from_json(args.limits) if args.limits else None
    ledger = EvidenceLedger(args.ledger) if args.ledger else None
    reviews = [json.loads(p.read_text(encoding="utf-8")) for p in args.limits_review]
    trust = ReviewTrust.from_json(args.limits_trust) if args.limits_trust else None
    attestations = [load_attestation_file(p) for p in args.recorder_attestation]
    recorder_trust = _read_trust(args.recorder_trust)
    warning = _subject_warning(args.subject, ledger)
    if warning:
        print(warning, file=sys.stderr)

    bundle = build_bundle(
        envelope, trace,
        actor=Actor(identifier=args.actor, role=args.role, kind="person"),
        limits=limits, limits_reviews=reviews, review_trust=trust,
        recorder_attestations=attestations, recorder_trust=recorder_trust,
        machine_serial=args.machine_serial, ledger=ledger, subject=args.subject,
    )
    if args.out:
        bundle.write(args.out)

    if args.json:
        print(json.dumps(bundle.to_dict(), indent=2, sort_keys=True))
    else:
        print(bundle.summary())
        att = bundle.result.recorder_attestation or {}
        if att.get("status") not in (None, "none", "accepted"):
            print(f"  recorder attestation not accepted ({att['status']}):")
            for f in att.get("findings", []):
                print(f"    - {f['status']}: {f['detail']}")
        if bundle.result.checks_skipped:
            print("\n  not checked:")
            for c in bundle.result.checks_skipped:
                print(f"    - {c}")
        if args.out:
            print(f"\n  bundle written to {args.out}")
        if ledger:
            print(f"  sealed into {args.ledger} at entry {len(ledger)}")

    return 0 if bundle.verdict is Verdict.PASS else 1


def _cmd_check(args: argparse.Namespace) -> int:
    envelope = SafetyEnvelope.from_json(args.envelope) if args.envelope else None
    trace = Trace.from_json(args.trace) if args.trace else None
    limits = LimitsTable.from_json(args.limits) if args.limits else None
    trust = ReviewTrust.from_json(args.limits_trust) if args.limits_trust else None
    recorder_trust = _read_trust(args.recorder_trust)
    from assurance.core.identity import parse_utc
    result = check_bundle(args.bundle, envelope=envelope, trace=trace, limits=limits,
                          review_trust=trust, recorder_trust=recorder_trust,
                          machine_serial=args.machine_serial,
                          as_of=parse_utc(args.as_of) if args.as_of else None)
    if args.json:
        print(json.dumps({"ok": result.ok, "level": result.level,
                          "reproduced": result.reproduced,
                          "provenance_basis_recorded": result.provenance_basis,
                          "provenance_reassessed": result.provenance_reassessed,
                          "believed_tier": result.believed_tier,
                          "reassessment_note": result.reassessment_note,
                          "problems": result.notes,
                          "limitations": list(result.limitations)}, indent=2))
    else:
        if not result.ok:
            verdict = "REJECTED"
        elif result.reproduced:
            verdict = "OK, REPRODUCED from the supplied envelope and trace"
        else:
            verdict = ("OK, NOT REPRODUCED: no inconsistency found, but the engine was "
                       "not re-run on the original envelope and trace")
        print(f"{args.bundle}: {verdict}")
        for p in result.notes:
            print(f"  - {p}")
        if result.provenance_basis == "recorder_attested":
            if result.reassessment_note:
                print(f"  recorder attestation: {result.provenance_reassessed} "
                      f"({result.reassessment_note}); no tier above community is believed")
            else:
                print(f"  recorder attestation: {result.provenance_reassessed}; tier "
                      f"believed by this check: {result.believed_tier}")
        if result.ok and not result.reproduced:
            print("  A seal is not a signature. Supply --envelope and --trace (and "
                  "--limits if the bundle used a table) to check the claim, not just "
                  "the seal.")
    return 0 if result.ok else 1


def _passphrase(args: argparse.Namespace) -> str:
    name = getattr(args, "passphrase_env", None)
    if not name:
        return ""
    value = os.environ.get(name)
    if value is None:
        raise RecorderAttestationError(
            f"${name} is not set. The passphrase is read from the environment on purpose: "
            "on the command line it lands in shell history and the process table.")
    return value


def _cmd_recorder_sign(args: argparse.Namespace) -> int:
    """Offline, on the recorder operator's side. Nothing here opens a socket."""
    if args.out.exists():
        raise RecorderAttestationError(
            f"{args.out} already exists; refusing to overwrite an attestation.")
    key = SigningKey.load(args.key, passphrase=_passphrase(args))
    trace = Trace.from_json(args.trace)
    on = args.attested_on or datetime.now(UTC).date().isoformat()
    att = RecorderAttestation.sign(
        trace, key, recorder_id=args.recorder_id, product=args.product,
        product_version=args.product_version, attested_on=on,
        machine_serial=args.machine_serial, expires_on=args.expires_on,
        attestation_id=args.attestation_id)
    with args.out.open("x", encoding="utf-8") as fh:
        fh.write(json.dumps(att.to_dict(), indent=2, sort_keys=True) + "\n")
    print(f"attestation {att.attestation_id} signed by key {key.fingerprint}")
    print(f"  trace    {trace.trace_id} ({trace.provenance.value}) {att.trace_hash[:16]}")
    print(f"  machine  {att.machine_ref.describe()}   dated {att.attested_on}"
          + (f"   valid until {att.expires_on}" if att.expires_on else ""))
    print(f"  written to {args.out}")
    print("\n  This signs a statement binding these exact trace bytes to your recorder key "
          "and that machine reference. A verifier lifts the trace only if THEIR trust list "
          "names this key. It does NOT prove: " + NOT_PROVED.split("does not establish ")[1])
    print(f"  Give the verifier the PUBLIC key by another route; read the fingerprint "
          f"{key.fingerprint} aloud if you can. Never send the private key.")
    return 0


def _cmd_recorder_trust(args: argparse.Namespace) -> int:
    text = args.public_key.read_text(encoding="utf-8")
    if "PRIVATE KEY" in text.upper():
        raise RecorderAttestationError(PRIVATE_KEY_MESSAGE)
    key = VerifyingKey.from_pem(text)
    classes = frozenset(c.strip() for c in args.provenance.split(",") if c.strip())
    if not classes or not classes <= LIFTABLE_PROVENANCE:
        raise RecorderAttestationError(
            f"--provenance must name one or more of {', '.join(sorted(LIFTABLE_PROVENANCE))};"
            " 'simulation' is never liftable.")
    existing = RecorderTrust.from_json(args.trust).recorders if args.trust.exists() else ()
    trust = RecorderTrust([*existing, TrustedRecorder(
        label=args.label, key=key, provenance=classes)])
    args.trust.write_text(json.dumps(trust.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(f"{args.trust}: {len(trust)} recorder key(s); added {key.fingerprint} "
          f"({args.label}) for {', '.join(sorted(classes))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "separation": _cmd_separation,
        "verify": _cmd_verify,
        "check": _cmd_check,
        "recorder-sign": _cmd_recorder_sign,
        "recorder-trust": _cmd_recorder_trust,
    }
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
