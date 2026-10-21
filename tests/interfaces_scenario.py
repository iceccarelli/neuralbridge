"""One Change Assurance sequence, driven through four interfaces.

The library, the command line (a real ``python -m assurance`` subprocess), the
HTTP API (a real server, real accounts and per-account ledgers) and the MCP read
tools all run the same plant: two machines enrolled by the offline kit, the
firmware changed on one, a watch run, an assessment, and the lifecycle through
re-verification, waiver, resolution and closure. ``run_sequence`` is written
once against :class:`Driver`; a divergence between interfaces is a test failure
that names the step.

Deliberately free of a ``pytest`` import, like :mod:`tests.support`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assurance.change import (
    CaseNotFoundError,
    CaseStore,
    CaseTransitionError,
    TriggerType,
    advance,
    assess_advisory,
    case_id_for,
    claim,
    decide,
    reconstruct_case,
    resolve_decision,
    resume,
    reverify,
    waive_reverification,
)
from assurance.change.model import queue_summary
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machine.bundle import build_bundle
from assurance.machinery.record import interventions_from_ledger, manifests_from_ledger
from assurance.machinery.staleness import VerificationRecord

from .interfaces_support import envelope, envelope_dict, trace, trace_dict
from .support import plan_dict, write_export

SRC = str(Path(__file__).resolve().parents[1] / "src")
KEY = "Grimaldi/AR-7#0501"         # the machine whose firmware changes
OTHER = "Grimaldi/AR-7#0412"
PERSON = "v.grimaldi"
#: After any real collection moment, so the run describes the machine as it is
#: after the change. The engine compares instants; it does not forbid a date.
TRACE_START = datetime(2031, 1, 1, tzinfo=UTC)
ADVISORY_ID = "ROBO-2026-03"


def advisory() -> ComponentAdvisory:
    """Names a label both machines report with an artefact hash neither has: a
    contradiction, so the case carries open human questions as well as work."""
    return ComponentAdvisory(
        advisory_id=ADVISORY_ID, issued_by="RoboCo",
        issued_at=datetime(2026, 9, 12, 8, tzinfo=UTC),
        title="Parameter export may omit the stop category", summary="s",
        severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact(supplier="RoboCo", name="Robot safety parameter set",
                                   versions=("3.8.2",), content_hashes=("e" * 64,)),),
        remedy="Re-export with the 3.9.0 tool.", reference="https://roboco.example/a",
        fixed_versions=("3.9.0",), fixed_hashes=("f" * 64,))


def cli_env(**extra: str) -> dict[str, str]:
    return {"PYTHONPATH": SRC, "PATH": os.environ.get("PATH", "/usr/bin:/bin"), **extra}


def run_cli(*argv: Any, cwd: Path | None = None, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", *map(str, argv)],
        capture_output=True, text=True, cwd=cwd, env=cli_env(**env), check=False)


# ---------------------------------------------------------------------------
# the plant
# ---------------------------------------------------------------------------

class Plant:
    """Two machines' vendor exports, a kit and a watch over them, in one folder."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        plan = plan_dict()
        plan["manufacturer"], plan["model"] = "Grimaldi", "AR-7"
        (root / "plans").mkdir(exist_ok=True)
        (root / "plans" / "cell.json").write_text(json.dumps(plan), encoding="utf-8")
        for serial in ("0412", "0501"):
            write_export(root / "exports" / serial, stamp="2026-09-14T06:00:00Z",
                         operator="m.tech", seq="4181")
        machines = [{"serial": s, "plan": "plans/cell.json", "exports": f"exports/{s}"}
                    for s in ("0412", "0501")]
        (root / "kit.json").write_text(json.dumps({
            "kit_id": "plant-2", "organisation": "Grimaldi Robotics",
            "prepared_by": "m.keller", "site": "Plant 2", "country": "DE",
            "machines": machines}), encoding="utf-8")
        (root / "watch.json").write_text(json.dumps({
            "watch_id": "WATCH-PLANT2", "max_age_hours": 168,
            "targets": [{"serial": s, "plan": "plans/cell.json", "root": f"exports/{s}",
                         "site": "Plant 2", "country": "DE"} for s in ("0412", "0501")]}),
            encoding="utf-8")

    @property
    def ledger_path(self) -> Path:
        return self.root / "out" / "evidence.db"

    @property
    def ledger(self) -> EvidenceLedger:
        return EvidenceLedger(self.ledger_path)

    def kit_run(self, via: str) -> None:
        if via == "cli":
            r = run_cli("kit", "run", "kit.json", "--out", "out", cwd=self.root)
            assert r.returncode == 0, r.stdout + r.stderr
        else:
            from assurance.kit.enrol import KitConfig, run_kit

            run = run_kit(KitConfig.from_json(self.root / "kit.json"), self.root / "out")
            assert run.verdict == "complete" and run.airgap.held

    def watch_run(self, via: str, *, expect: int) -> None:
        if via == "cli":
            r = run_cli("watch", "run", "watch.json", "--ledger", self.ledger_path,
                        cwd=self.root)
            assert r.returncode == expect, r.stdout + r.stderr
        else:
            from assurance.watch.config import WatchConfig
            from assurance.watch.runner import run_watch

            run = run_watch(WatchConfig.from_json(self.root / "watch.json"), self.ledger)
            assert {0: "quiet", 1: "findings", 2: "degraded"}[expect] == run.verdict

    def change_firmware(self, serial: str = "0501") -> None:
        shutil.rmtree(self.root / "exports" / serial)
        write_export(self.root / "exports" / serial, stamp="2026-09-21T06:00:00Z",
                     operator="a.integrator", seq="4199", fw=b"firmware 3.9.0")

    def enrol_and_change(self, via: str) -> None:
        """Kit enrolment, a baseline look, a firmware change, a look that sees it."""
        self.kit_run(via)
        self.watch_run(via, expect=1)           # first look: nothing changed, never verified
        self.change_firmware()
        self.watch_run(via, expect=1)           # drift: opens the case

    def push(self, api_url: str, key: str) -> None:
        """The one networked path: report the latest sealed run to a hosted ledger."""
        r = run_cli("watch", "push", "watch.json", "--ledger", self.ledger_path,
                    "--api-url", api_url, "--key-env", "PLANT_API_KEY", cwd=self.root,
                    PLANT_API_KEY=key)
        assert r.returncode == 0, r.stdout + r.stderr

    def enrol_and_change_hosted(self, api_url: str, key: str) -> None:
        """As :meth:`enrol_and_change`, reporting each look to the account's own ledger."""
        self.kit_run("cli")
        self.watch_run("cli", expect=1)
        self.push(api_url, key)
        # Observations are stamped to the second and the hosted ledger refuses two
        # different observations of one machine in the same second.
        time.sleep(1.1)
        self.change_firmware()
        self.watch_run("cli", expect=1)
        self.push(api_url, key)

    def manifest_dict(self) -> dict[str, Any]:
        return manifests_from_ledger(self.ledger, KEY)[-1].to_dict()

    def expected_drift_case_id(self) -> str:
        observed = manifests_from_ledger(self.ledger, KEY)[-1]
        return case_id_for(TriggerType.MACHINE_DRIFT, observed.configuration_hash())


# ---------------------------------------------------------------------------
# drivers
# ---------------------------------------------------------------------------

@dataclass
class Out:
    kind: str          # ok | refused | notfound | invalid | unauthenticated | unentitled
    case: dict[str, Any] | None = None
    text: str = ""


def snap(case: dict[str, Any] | None) -> tuple[Any, ...] | None:
    """The part of a case that must be identical on every interface."""
    if case is None:
        return None
    return (case["case_id"], case["status"], case["owner"], case["decision"],
            case["decision_by"], tuple(sorted(case["required_reverifications"])),
            tuple(sorted(case["human_decisions_required"])),
            tuple(sorted(case["evidence_current"].items())),
            tuple(sorted(r.get("kind", "answer") for r in case["resolved_decisions"])),
            tuple(case["machines"]), tuple(case["affected_functions"]))


def rows_of(listing: dict[str, Any]) -> list[tuple[Any, ...]]:
    return [(r["case_id"], r["status"], r["owner"], r["trigger"], tuple(r["machines"]))
            for r in listing["cases"]]


class Driver:
    name = "?"

    def get(self, cid: str) -> dict[str, Any] | None: ...
    def listing(self) -> dict[str, Any]: ...
    def assess_advisory(self, adv: ComponentAdvisory) -> Out: ...
    def claim(self, cid: str, owner: str, who: str) -> Out: ...
    def advance(self, cid: str, who: str) -> Out: ...
    def verify(self, who: str) -> str: ...
    def reverify(self, cid: str, vhash: str, who: str) -> Out: ...
    def resolve(self, cid: str, decision: str, resolution: str, who: str) -> Out: ...
    def waive(self, cid: str, entry: str, reason: str, who: str) -> Out: ...
    def decide(self, cid: str, disposition: str, reason: str, who: str) -> Out: ...
    def resume(self, cid: str, reason: str, who: str) -> Out: ...
    def replay(self, cid: str) -> dict[str, Any]: ...
    def export(self, cid: str) -> dict[str, Any]: ...


def _person(who: str) -> Actor:
    return Actor(identifier=who, role="reviewer", kind="person")


class LibraryDriver(Driver):
    name = "library"

    def __init__(self, plant: Plant) -> None:
        self.plant = plant
        self.ledger = plant.ledger
        self.store = CaseStore(self.ledger)

    def _do(self, fn, *a, **kw) -> Out:
        try:
            case = fn(self.store, *a, **kw)
        except CaseNotFoundError as exc:
            return Out("notfound", text=str(exc))
        except CaseTransitionError as exc:
            return Out("refused", text=str(exc))
        except (AssuranceError, ValueError, KeyError) as exc:
            return Out("invalid", text=str(exc))
        return Out("ok", case.to_dict() if case else None)

    def get(self, cid):
        case = self.store.get(cid)
        return case.to_dict() if case else None

    def listing(self):
        cases = self.store.list()
        return {"cases": [c.row() for c in cases], "summary": queue_summary(cases)}

    def assess_advisory(self, adv):
        report = assess_impact(adv, Fleet.from_ledger(self.ledger))
        case = assess_advisory(self.store, report, actor=Actor("operator", "fleet",
                                                               kind="automation"))
        return Out("ok", case.to_dict() if case else None)

    def claim(self, cid, owner, who):
        return self._do(claim, cid, owner=owner, actor=_person(who))

    def advance(self, cid, who):
        return self._do(advance, cid, actor=_person(who))

    def verify(self, who):
        bundle = build_bundle(envelope(), trace(TRACE_START), actor=Actor(
            who, "verification engineer", kind="person"), ledger=self.ledger, subject=KEY)
        return bundle.content_hash

    def reverify(self, cid, vhash, who):
        manifest = self.plant.manifest_dict()
        from assurance.machinery.manifest import SafetyManifest

        m = SafetyManifest.from_dict(manifest)
        return self._do(
            lambda store, c, **kw: reverify(
                store, c, m, VerificationRecord.from_ledger(self.ledger, subject=KEY),
                interventions_from_ledger(self.ledger, KEY), **kw),
            cid, verification_content_hash=vhash, actor=_person(who))

    def resolve(self, cid, decision, resolution, who):
        return self._do(resolve_decision, cid, decision=decision, resolution=resolution,
                        actor=_person(who))

    def waive(self, cid, entry, reason, who):
        return self._do(waive_reverification, cid, entry=entry, reason=reason,
                        actor=_person(who))

    def decide(self, cid, disposition, reason, who):
        return self._do(decide, cid, disposition=disposition, reason=reason,
                        actor=_person(who))

    def resume(self, cid, reason, who):
        return self._do(resume, cid, reason=reason, actor=_person(who))

    def replay(self, cid):
        return reconstruct_case(self.ledger, cid).to_dict()

    def export(self, cid):
        return self.ledger.export(subject=cid)


class CliDriver(Driver):
    name = "cli"

    def __init__(self, plant: Plant) -> None:
        self.plant = plant
        self.ledger_path = plant.ledger_path

    def _run(self, *argv) -> subprocess.CompletedProcess[str]:
        return run_cli("change", *argv, "--ledger", self.ledger_path, cwd=self.plant.root)

    def _out(self, r: subprocess.CompletedProcess[str], cid: str = "") -> Out:
        if r.returncode == 0:
            return Out("ok", self.get(cid) if cid else None, r.stdout)
        if r.returncode == 1 and r.stderr.startswith("finding:"):
            return Out("refused", text=r.stderr)
        if r.returncode == 2 and "no case" in r.stderr:
            return Out("notfound", text=r.stderr)
        if r.returncode == 2:
            return Out("invalid", text=r.stderr)
        raise AssertionError(f"unexpected CLI result {r.returncode}: {r.stdout}{r.stderr}")

    def get(self, cid):
        r = self._run("show", cid, "--json")
        return json.loads(r.stdout) if r.stdout.strip() else None

    def listing(self):
        return json.loads(self._run("list", "--json").stdout)

    def assess_advisory(self, adv):
        path = self.plant.root / "advisory.json"
        path.write_text(json.dumps(adv.to_dict()), encoding="utf-8")
        r = self._run("assess-advisory", "--advisory", path)
        assert r.returncode == 0, r.stderr
        return Out("ok", self.get(case_id_for(TriggerType.SUPPLIER_ADVISORY,
                                              adv.advisory_id)))

    def claim(self, cid, owner, who):
        return self._out(self._run("claim", cid, "--owner", owner, "--actor", who), cid)

    def advance(self, cid, who):
        return self._out(self._run("advance", cid, "--actor", who), cid)

    def verify(self, who):
        env, tr = self.plant.root / "envelope.json", self.plant.root / "trace.json"
        env.write_text(json.dumps(envelope_dict()), encoding="utf-8")
        tr.write_text(json.dumps(trace_dict(TRACE_START)), encoding="utf-8")
        r = run_cli("machine", "verify", "--envelope", env, "--trace", tr, "--actor", who,
                    "--ledger", self.ledger_path, "--subject", KEY, "--json",
                    cwd=self.plant.root)
        assert r.returncode == 0, r.stdout + r.stderr
        return str(json.loads(r.stdout)["evidence"]["content_hash"])

    def reverify(self, cid, vhash, who):
        path = self.plant.root / "manifest.json"
        path.write_text(json.dumps(self.plant.manifest_dict()), encoding="utf-8")
        return self._out(self._run("reverify", cid, "--manifest", path,
                                   "--verification-hash", vhash, "--actor", who), cid)

    def resolve(self, cid, decision, resolution, who):
        case = self.get(cid)
        open_ = case["human_decisions_required"] if case else []
        number = open_.index(decision) + 1 if decision in open_ else len(open_) + 1
        return self._out(self._run("resolve-decision", cid, "--number", number,
                                   "--resolution", resolution, "--actor", who), cid)

    def waive(self, cid, entry, reason, who):
        return self._out(self._run("waive-reverification", cid, "--entry", entry,
                                   "--reason", reason, "--actor", who), cid)

    def decide(self, cid, disposition, reason, who):
        return self._out(self._run("decide", cid, "--disposition", disposition,
                                   "--reason", reason, "--actor", who), cid)

    def resume(self, cid, reason, who):
        return self._out(self._run("resume", cid, "--reason", reason, "--actor", who), cid)

    def replay(self, cid):
        return json.loads(self._run("replay", cid, "--json").stdout)

    def export(self, cid):
        out = self.plant.root / "export.json"
        r = self._run("export", cid, "--out", out)
        assert r.returncode == 0, r.stderr
        return json.loads(out.read_text(encoding="utf-8"))


class ApiDriver(Driver):
    name = "api"

    def __init__(self, plant: Plant, base_url: str, headers: dict[str, str]) -> None:
        import httpx

        self.plant = plant
        self.http = httpx.Client(base_url=base_url, headers=headers, timeout=60.0)

    def _out(self, r) -> Out:
        kind = {200: "ok", 409: "refused", 404: "notfound", 422: "invalid",
                401: "unauthenticated", 402: "unentitled"}.get(r.status_code)
        assert kind, f"unexpected status {r.status_code}: {r.text}"
        return Out(kind, r.json() if kind == "ok" else None, r.text)

    def _post(self, cid: str, verb: str, body: dict[str, Any]) -> Out:
        return self._out(self.http.post(f"/v1/change/cases/{cid}/{verb}", json=body))

    def get(self, cid):
        r = self.http.get(f"/v1/change/cases/{cid}")
        return r.json() if r.status_code == 200 else None

    def listing(self):
        return self.http.get("/v1/change/cases").json()

    def assess_advisory(self, adv):
        r = self.http.post("/v1/change/assess/advisory", json={"advisory": adv.to_dict()})
        assert r.status_code == 200, r.text
        return Out("ok", r.json()["case"])

    def claim(self, cid, owner, who):
        return self._post(cid, "claim", {"owner": owner, "actor": who})

    def advance(self, cid, who):
        return self._post(cid, "advance", {"actor": who})

    def verify(self, who):
        r = self.http.post("/v1/machine/verify", json={
            "envelope": envelope_dict(), "trace": trace_dict(TRACE_START), "actor": who,
            "subject": KEY})
        assert r.status_code == 200, r.text
        return str(r.json()["content_hash"])

    def reverify(self, cid, vhash, who):
        return self._post(cid, "reverification", {
            "manifest": self.plant.manifest_dict(), "verification_content_hash": vhash,
            "actor": who})

    def resolve(self, cid, decision, resolution, who):
        return self._post(cid, "resolve-decision", {
            "decision": decision, "resolution": resolution, "actor": who})

    def waive(self, cid, entry, reason, who):
        return self._post(cid, "waive-reverification", {
            "entry": entry, "reason": reason, "actor": who})

    def decide(self, cid, disposition, reason, who):
        return self._post(cid, "decision", {
            "disposition": disposition, "reason": reason, "actor": who})

    def resume(self, cid, reason, who):
        return self._post(cid, "resume", {"reason": reason, "actor": who})

    def replay(self, cid):
        return self.http.get(f"/v1/change/cases/{cid}/replay").json()

    def export(self, cid):
        return self.http.get(f"/v1/change/cases/{cid}/export").json()


# ---------------------------------------------------------------------------
# the sequence
# ---------------------------------------------------------------------------

@dataclass
class Result:
    trace: list[tuple[Any, ...]]
    drift_id: str
    advisory_id: str
    verification_hash: str
    listing: dict[str, Any]
    exports: dict[str, dict[str, Any]]
    replays: dict[str, dict[str, Any]]


def run_sequence(d: Driver, drift_id: str) -> Result:
    """The lifecycle, written once. Every step names the outcome it must have."""
    steps: list[tuple[Any, ...]] = []

    def step(label: str, cid: str, out: Out, expect: str) -> Out:
        assert out.kind == expect, f"[{d.name}] {label}: expected {expect}, got {out.kind}: " \
                                   f"{out.text[:300]}"
        steps.append((label, out.kind, snap(d.get(cid))))
        return out

    # -- what the watch found: one drift case, and it is the id the engines derive
    queue = d.listing()
    drifts = [r for r in queue["cases"] if r["trigger"] == "machine_drift"]
    assert [r["case_id"] for r in drifts] == [drift_id], (d.name, queue)
    assert d.get(drift_id)["status"] == "open"
    steps.append(("queued", "ok", snap(d.get(drift_id))))

    # -- refusals: unknown case, wrong state, names automation goes by
    step("unknown case", "case-doesnotexist", d.claim("case-doesnotexist", PERSON, PERSON),
         "notfound")
    step("close while open", drift_id, d.decide(drift_id, "closed", "early", PERSON),
         "refused")
    step("advance while open", drift_id, d.advance(drift_id, PERSON), "refused")
    step("reverify while open", drift_id, d.reverify(drift_id, "a" * 64, PERSON), "refused")
    step("claim owned by an agent", drift_id, d.claim(drift_id, "agent", PERSON), "refused")
    step("claim", drift_id, d.claim(drift_id, PERSON, PERSON), "ok")
    step("claim twice", drift_id, d.claim(drift_id, PERSON, PERSON), "refused")
    for name in ("automation", "System", "bot-7"):
        step(f"decide as {name}", drift_id, d.decide(drift_id, "rejected", "r", name),
             "refused")
    step("advance 1", drift_id, d.advance(drift_id, PERSON), "ok")
    step("advance 2", drift_id, d.advance(drift_id, PERSON), "ok")
    step("advance with work outstanding", drift_id, d.advance(drift_id, PERSON), "refused")
    step("reverify citing nothing real", drift_id, d.reverify(drift_id, "b" * 64, PERSON),
         "refused")

    # -- the evidence: a real verification filed under the machine, then re-verify
    vhash = d.verify(PERSON)
    ready = step("reverify", drift_id, d.reverify(drift_id, vhash, PERSON), "ok")
    assert ready.case["status"] == "ready_to_close", (d.name, ready.case["status"])
    step("close as automation", drift_id, d.decide(drift_id, "closed", "r", "automation"),
         "refused")
    step("close", drift_id, d.decide(drift_id, "closed", "Re-verified after the firmware "
                                     "change.", PERSON), "ok")
    step("close twice", drift_id, d.decide(drift_id, "closed", "again", PERSON), "refused")

    # -- an advisory case with open questions and entries nobody can verify
    adv = advisory()
    aid = case_id_for(TriggerType.SUPPLIER_ADVISORY, adv.advisory_id)
    opened = d.assess_advisory(adv)
    assert opened.case and opened.case["case_id"] == aid, (d.name, opened)
    steps.append(("advisory opened", "ok", snap(d.get(aid))))
    case = d.get(aid)
    questions, entries = case["human_decisions_required"], case["required_reverifications"]
    assert len(questions) == 2 and len(entries) == 4, (d.name, questions, entries)

    step("claim advisory", aid, d.claim(aid, PERSON, PERSON), "ok")
    step("advisory advance", aid, d.advance(aid, PERSON), "ok")
    step("defer", aid, d.decide(aid, "deferred", "Not today.", PERSON), "ok")
    step("resolve while deferred", aid,
         d.resolve(aid, questions[0], "ok", PERSON), "refused")
    step("resume as automation", aid, d.resume(aid, "back", "automation"), "refused")
    step("resume", aid, d.resume(aid, "Capacity is back.", PERSON), "ok")
    step("advisory advance 1", aid, d.advance(aid, PERSON), "ok")
    step("advisory advance 2", aid, d.advance(aid, PERSON), "ok")
    step("resolve as agent", aid, d.resolve(aid, questions[0], "ok", "agent"), "refused")
    step("resolve a question not asked", aid,
         d.resolve(aid, "something else", "ok", PERSON), "refused")
    step("waive as automation", aid, d.waive(aid, entries[0], "r", "automation"), "refused")
    step("waive an entry not owed", aid, d.waive(aid, "nope/SF-09", "r", PERSON), "refused")
    step("waive without a reason", aid, d.waive(aid, entries[0], " ", PERSON), "refused")
    step("close with work outstanding", aid, d.decide(aid, "closed", "r", PERSON), "refused")
    for n, entry in enumerate(entries):
        out = step(f"waive {n + 1}", aid,
                   d.waive(aid, entry, "Machine is out of service.", PERSON), "ok")
        assert out.case["evidence_current"][entry] == "waived"
    for n, question in enumerate(questions):
        step(f"resolve {n + 1}", aid,
             d.resolve(aid, question, "Hash checked against the supplier's table.", PERSON),
             "ok")
    step("advisory advance to ready", aid, d.advance(aid, PERSON), "ok")
    step("advisory close", aid, d.decide(aid, "closed", "Closed on the waivers above.",
                                         PERSON), "ok")

    listing = d.listing()
    return Result(
        trace=steps, drift_id=drift_id, advisory_id=aid, verification_hash=vhash,
        listing=listing,
        exports={drift_id: d.export(drift_id), aid: d.export(aid)},
        replays={drift_id: d.replay(drift_id), aid: d.replay(aid)})
