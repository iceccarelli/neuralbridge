"""The boundary of a machine verification: what each answer covers and where it stops.

A verdict of ``pass`` is an answer to a narrow question. This module states, in
machine-readable form and from per-check constants (not prose scattered through the
engine), for every check and for the result as a whole:

``tested``
    what was compared with what.
``not_tested``
    what a reader might assume was covered and was not.
``inputs_used``
    the input fields the check read and the hashes of the files they came from.
``observed_vs_declared``
    for each quantity, whether it was ``observed`` (read from the recording),
    ``declared`` (written by whoever filed the envelope or the trace), ``derived``
    (computed from those), or ``mixed`` (it differs sample by sample).
``assumptions``
    what the engine takes to be true without being able to check it.
``valid_for``
    one sentence of scope.
``human_review``
    ``required`` is ALWAYS true for safety use. Software drafts; a qualified person decides
    whether the result supports a safety claim. ``reasons`` say what that person must decide.

Engine 7 and later seal this block; engine 6 bundles have none and are replayed without it.
The constants here are part of what a sealed bundle records, so changing a sentence changes
what engine 7 replays to: a change of wording is a new engine, like a change of meaning.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.trace import Trace

__all__ = [
    "BOUNDARY_KEYS",
    "FIRST_ENGINE_WITH_BOUNDARY",
    "boundary_problems",
    "check_boundary",
    "result_boundary",
]

#: The engine that first seals the block.
FIRST_ENGINE_WITH_BOUNDARY = 7

BOUNDARY_KEYS = ("tested", "not_tested", "inputs_used", "observed_vs_declared",
                 "assumptions", "valid_for", "human_review")
_SOURCES = ("observed", "declared", "derived", "mixed")

#: Said on every check and on the result: not conditional on anything in the data.
_ALWAYS_REVIEW = (
    "Software drafts this result; a qualified person decides whether it supports a safety "
    "claim for this machine. Nothing here is a conformity statement."
)

# -- per-check constants ------------------------------------------------------------------

_CHECKS: dict[str, dict[str, Any]] = {
    "workspace_containment": {
        "tested": ["Each recorded TCP position lies inside the declared axis-aligned "
                   "workspace box."],
        "not_tested": [
            "Motion between samples: a path can leave the box and return between two samples.",
            "Any point of the machine other than the TCP (links, tool, payload).",
            "That the trace's coordinate frame is the frame the workspace was declared in: "
            "the workspace's frame is not compared with the trace's.",
        ],
        "fields": ["trace.samples[].tcp", "envelope.workspace"],
        "ovd": {"tcp_position": "observed", "workspace": "declared"},
        "assumptions": ["The trace and the workspace use one coordinate frame, in millimetres."],
        "valid_for": "The recorded TCP samples of this trace, in the frame both files are "
                     "assumed to share.",
        "review": ["Confirm the workspace frame is the trace frame.",
                   "Decide whether TCP-only containment is sufficient for the tool and payload."],
    },
    "speed_limit": {
        "tested": ["Each recorded TCP speed is within the declared limit for the mode in force."],
        "not_tested": [
            "The recorded TCP speed against the speed implied by the recorded positions: it "
            "is trusted as written.",
            "Peaks between samples.",
            "The speed of any part other than the TCP.",
        ],
        "fields": ["trace.samples[].tcp_speed", "trace.samples[].mode",
                   "envelope.max_tcp_speed_mm_s"],
        "ovd": {"tcp_speed": "observed", "mode": "observed", "speed_limit": "declared"},
        "assumptions": ["The recorded tcp_speed is accurate and is the TCP speed.",
                        "The recorded mode labels are true."],
        "valid_for": "The recorded speeds and mode labels of this trace.",
        "review": ["Decide whether the controller's reported speed can be trusted without a "
                   "cross-check against positions.",
                   "Decide whether the mode labels are trustworthy."],
    },
    "ssm_separation": {
        "tested": ["Measured separation was at least the separation distance this package "
                   "computes from the envelope's figures, at every compared sample in a "
                   "separation-controlled mode."],
        "not_tested": [
            "That the sensing system detected every person present.",
            "Where on the machine and on the person `separation` is measured from: the "
            "reference point is not recorded or compared.",
            "The formula and its constants against ISO/TS 15066 and ISO 13855 (unverified; "
            "no copy of either is in this repository).",
            "Samples with no separation reading, and the interval inside a recording gap.",
        ],
        "fields": ["trace.samples[].separation", "trace.samples[].tcp_speed",
                   "trace.samples[].human_speed", "trace.samples[].mode",
                   "envelope.stop", "envelope.uncertainty", "envelope.intrusion_distance_mm",
                   "envelope.human_approach_speed_mm_s"],
        "ovd": {"separation": "observed", "tcp_speed": "observed",
                "reaction_time_stop_time_stop_distance": "declared",
                "intrusion_and_uncertainty": "declared", "required_separation": "derived"},
        "assumptions": [
            "`separation` is the minimum distance to the nearest person, measured from the "
            "reference point the stop figures assume.",
            "The robot's closing speed is taken as its whole TCP speed.",
            "The declared stop and reaction figures describe the machine as it is now.",
            "Above the speed the stopping distance was measured at, Ss is scaled by the "
            "square of the speed ratio (constant deceleration); the reaction and stop times "
            "inside Sh are not scaled.",
        ],
        "valid_for": "The compared samples of this trace, under this formula, with the "
                     "envelope's stop and sensing figures as declared.",
        "review": [
            "The separation formula and its constants are unverified against the standards.",
            "Decide where `separation` is measured from and whether that matches the stop "
            "figures.",
            "Decide whether the person's closing speed (sensed, declared or the package "
            "default) is acceptable for this application.",
        ],
    },
    "stop_characterisation": {
        "tested": ["The machine never ran faster than the speed its stopping distance was "
                   "measured at, in separation-controlled modes."],
        "not_tested": [
            "The stopping distance itself: it is not re-measured from this trace.",
            "Whether the stopping figures still describe the machine (load, wear, tool, "
            "direction, age: no maximum age is applied).",
        ],
        "fields": ["trace.samples[].tcp_speed", "trace.samples[].mode",
                   "envelope.stop.measured_at_speed_mm_s"],
        "ovd": {"tcp_speed": "observed", "measured_at_speed": "declared"},
        "assumptions": ["The stopping figure applies at every payload, direction and tool "
                        "configuration in the run."],
        "valid_for": "The speeds in this trace against the one speed the stop was measured at.",
        "review": ["Decide whether the stop figure covers the payloads, directions and "
                   "tool configurations the machine ran."],
    },
    "pfl_contact": {
        "tested": ["Contact force and pressure stayed within the QUASI-STATIC limits of the "
                   "declared body-region table wherever contact was permitted."],
        "not_tested": [
            "Transient contact: only quasi-static limits are applied.",
            "The pressure margin (it is evaluated but not recorded).",
            "That the body region credited to a contact is the one touched.",
            "Contact samples with no force, no area or a region the table lacks.",
            "The limits table's content against the standard, unless a signed independent "
            "review of it was accepted.",
        ],
        "fields": ["trace.samples[].contact_force", "trace.samples[].contact_area",
                   "trace.samples[].body_region", "trace.samples[].mode",
                   "envelope.pfl_limits_hash"],
        "ovd": {"contact_force": "observed", "contact_area": "observed",
                "body_region": "declared", "limits": "declared"},
        "assumptions": ["Quasi-static limits are the applicable ones.",
                        "The recorded body-region labels are true.",
                        "The force and area sensors are calibrated."],
        "valid_for": "The contact samples of this trace against the pinned limits table.",
        "review": ["Decide whether quasi-static limits are the applicable ones.",
                   "Decide whether the body-region labels and the force and area sensors "
                   "can be trusted."],
    },
    "mode_consistency": {
        "tested": ["No person was detected (a separation reading is present) while the cell "
                   "was in unrestricted automatic mode."],
        "not_tested": [
            "Every other mode label is trusted as recorded: a mislabelled mode is not found.",
            "A missing reading in automatic mode is not evidence that nobody was there.",
        ],
        "fields": ["trace.samples[].mode", "trace.samples[].separation"],
        "ovd": {"mode": "observed", "separation": "observed"},
        "assumptions": ["The mode labels are true.",
                        "A separation reading means a person was detected."],
        "valid_for": "The mode labels and readings of this trace. The check counts "
                     "detections; its `unit` field is not a distance.",
        "review": ["Decide whether the mode signal is trustworthy."],
    },
    "trace_coverage": {
        "tested": ["The trace has at least the package's sanity floor of samples and "
                   "duration and exercised a safety regime."],
        "not_tested": ["That the run is long or representative enough for any particular "
                       "claim: the floor is chosen by this package, not taken from a standard."],
        "fields": ["trace.samples", "trace.sample_rate_hz"],
        "ovd": {"trace": "observed"},
        "assumptions": ["The sanity floor separates a run from a data point."],
        "valid_for": "The size and regimes of this trace only.",
        "review": ["Decide whether this run covers the conditions the claim is about."],
    },
    "input_dates": {
        "tested": ["The trace's start and the figure dates are not after the moment of "
                   "verification (one day of clock tolerance)."],
        "not_tested": [
            "The END of the trace: a run that ends in the future still verifies.",
            "How old the figures are: no maximum age is applied.",
            "That any date is true.",
        ],
        "fields": ["trace.started_at", "envelope.stop.basis.date",
                   "envelope.uncertainty.basis.date"],
        "ovd": {"dates": "declared"},
        "assumptions": ["The verifier's clock is right."],
        "valid_for": "The dates as written in these files.",
        "review": ["Decide whether the figures' dates and age are acceptable."],
    },
}

#: Said once for the result as a whole.
_RESULT = {
    "tested": ["Each of the checks listed, against exactly the envelope and trace named by "
               "the hashes in `inputs_used`."],
    "not_tested": [
        "Whether the trace came from the machine it names, beyond what its provenance basis "
        "says.",
        "Whether the envelope is the right envelope for this application.",
        "Any person the sensing system did not detect.",
        "Whether the envelope's figures describe the machine today.",
        "Whether the formula and constants match ISO/TS 15066 and ISO 13855 (unverified).",
    ],
    "assumptions": [
        "The basis a figure names (`measured`, `datasheet`, `estimated`, its reference and "
        "date) is the filer's word: it is not signed and not checked.",
        "Distances are millimetres, speeds mm/s, times seconds: nothing is converted, and a "
        "value typed in metres is only caught if it falls outside a plausibility rail.",
        "The recording is complete in the intervals between samples that were compared.",
    ],
    "valid_for": "This envelope and this trace (see the hashes), at the tier stated, under "
                 "this engine's rules. Not the machine in general, not another firmware, "
                 "configuration, tool or payload.",
}


def _source_for_counts(n_sensed: int, n_other: int) -> str:
    if n_sensed and not n_other:
        return "observed"
    if n_sensed:
        return "mixed"
    return "declared"


def _ssm_facts(envelope: SafetyEnvelope, trace: Trace) -> dict[str, int]:
    """Counts over the samples ``ssm_separation`` compared (separation-controlled, with a reading)."""
    compared = [s for s in trace.samples
                if s.mode.separation_is_the_control and s.separation is not None]
    sensed = [s for s in compared if s.human_speed is not None]
    ceiling = envelope.stop.measured_at_speed_mm_s
    return {
        "compared": len(compared),
        "sensed": len(sensed),
        "not_sensed": len(compared) - len(sensed),
        "sensed_below_fallback": sum(
            1 for s in sensed if (s.human_speed or 0.0) < envelope.approach_speed_mm_s),
        "extrapolated": sum(1 for s in compared if s.tcp_speed > ceiling),
    }


def _hashes(envelope_hash: str, trace_hash: str, limits_hash: str) -> dict[str, str]:
    out = {"envelope": envelope_hash, "trace": trace_hash}
    if limits_hash:
        out["limits"] = limits_hash
    return out


def _review_block(reasons: Sequence[str]) -> dict[str, Any]:
    # `required` is not computed from anything: it is the same for every result.
    return {"required": True, "reasons": [_ALWAYS_REVIEW, *reasons]}


def check_boundary(
    name: str, *, envelope: SafetyEnvelope, trace: Trace, envelope_hash: str,
    trace_hash: str, limits_hash: str, outcome: str, reason: str,
) -> dict[str, Any]:
    """The boundary block of one check."""
    spec = _CHECKS[name]
    ovd = dict(spec["ovd"])
    review = list(spec["review"])
    if name == "ssm_separation":
        f = _ssm_facts(envelope, trace)
        ovd["human_speed"] = _source_for_counts(f["sensed"], f["not_sensed"])
        if f["sensed"]:
            review.append(
                f"{f['sensed']} of {f['compared']} compared samples used the trace's own "
                f"closing speed ({f['sensed_below_fallback']} below the envelope's "
                f"{'declared' if envelope.approach_speed_declared else 'default'} figure), "
                "which can turn a failing separation into a passing one.")
        if f["extrapolated"]:
            review.append(
                f"{f['extrapolated']} compared samples ran above the speed the stopping "
                "distance was measured at, so Ss is a model and not a measurement.")
    if outcome == "unchecked":
        review.append(f"This check could not run: {reason}".rstrip())
    return {
        "tested": list(spec["tested"]),
        "not_tested": list(spec["not_tested"]),
        "inputs_used": {"fields": list(spec["fields"]),
                        "hashes": _hashes(envelope_hash, trace_hash,
                                          limits_hash if name == "pfl_contact" else "")},
        "observed_vs_declared": ovd,
        "assumptions": list(spec["assumptions"]),
        "valid_for": spec["valid_for"],
        "human_review": _review_block(review),
    }


def result_boundary(
    checks: Sequence[tuple[str, dict[str, Any]]], *, envelope: SafetyEnvelope,
    envelope_hash: str, trace_hash: str, limits_hash: str,
) -> dict[str, Any]:
    """The boundary block of the whole result, from the per-check blocks (name, block)."""
    fields: list[str] = []
    ovd: dict[str, str] = {}
    reasons: list[str] = []
    for _name, block in checks:
        for f in block["inputs_used"]["fields"]:
            if f not in fields:
                fields.append(f)
        for k, v in block["observed_vs_declared"].items():
            ovd[k] = v if ovd.get(k, v) == v else "mixed"
        for r in block["human_review"]["reasons"][1:]:
            if r not in reasons:
                reasons.append(r)
    stop, sensing = envelope.stop.basis, envelope.uncertainty.basis
    assumptions = [
        *_RESULT["assumptions"],
        f"Stopping figures are a {stop.kind} figure ({stop.reference}); sensing figures are "
        f"a {sensing.kind} figure ({sensing.reference}).",
    ]
    return {
        "tested": list(_RESULT["tested"]),
        "not_tested": list(_RESULT["not_tested"]),
        "inputs_used": {"fields": fields,
                        "hashes": _hashes(envelope_hash, trace_hash, limits_hash)},
        "observed_vs_declared": ovd,
        "assumptions": assumptions,
        "valid_for": _RESULT["valid_for"],
        "human_review": _review_block(reasons),
    }


def boundary_problems(block: Any, where: str) -> list[str]:
    """Is a sealed boundary block well-formed, and does it still say a human must review?

    No trust is involved. A resealed body cannot turn ``required`` off without being
    reported here, whatever else the checker could or could not replay.
    """
    if not isinstance(block, dict):
        return [f"{where} records no boundary block, which every engine "
                f"{FIRST_ENGINE_WITH_BOUNDARY} result carries."]
    out: list[str] = []
    missing = [k for k in BOUNDARY_KEYS if k not in block]
    if missing:
        out.append(f"{where}'s boundary block omits {', '.join(missing)}.")
    review = block.get("human_review")
    if not (isinstance(review, dict) and review.get("required") is True
            and isinstance(review.get("reasons"), list) and review["reasons"]
            and all(isinstance(r, str) and r.strip() for r in review["reasons"])):
        out.append(f"{where}'s boundary block does not say that qualified human review is "
                   "required. It always is: software never decides it.")
    for key in ("tested", "not_tested", "assumptions"):
        if key in block and not (isinstance(block[key], list) and all(
                isinstance(x, str) and x.strip() for x in block[key])):
            out.append(f"{where}'s boundary block has a malformed {key}.")
    # What was tested and what was not are never empty: every check and the result state both.
    for key in ("tested", "not_tested"):
        if key in block and block[key] == []:
            out.append(f"{where}'s boundary block lists nothing under {key}, which every "
                       "engine 7 result states.")
    if "valid_for" in block and not (isinstance(block["valid_for"], str)
                                     and block["valid_for"].strip()):
        out.append(f"{where}'s boundary block has no valid_for scope sentence.")
    ovd = block.get("observed_vs_declared")
    if "observed_vs_declared" in block and not (isinstance(ovd, dict) and all(
            v in _SOURCES for v in ovd.values())):
        out.append(f"{where}'s boundary block has an observed_vs_declared entry that is not "
                   f"one of {', '.join(_SOURCES)}.")
    return out
