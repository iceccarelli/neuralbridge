"""A caller-typed actor name or role cannot forge the server's attribution grammar.

The server seals ``attribution=authenticated_operator``, ``operator=op_...`` and ``key=...``
into an actor's role, and the typed name beside them. A reader scanning a sealed record for
those tokens must be able to believe they came from the server. These tests drive one hostile
name through every surface that seals a typed name (HTTP routes, CLI verbs, the domain
functions) and check that it is REFUSED (not cleaned), that nothing is written, and that the
ordinary names people have are still accepted.
"""
# ruff: noqa: S603, F811  (own CLI; pytest fixtures imported by name)
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from assurance.change.cli import main as change_main
from assurance.change.service import CaseTransitionError, named_person_problem
from assurance.core.actor_names import (
    ActorNameError,
    actor_grammar_problem,
    actor_name_problem,
    checked_person,
    declared_role_problem,
)
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import EnrolmentError, require_person
from assurance.watch.open_case import OpenCaseRefusedError
from assurance.watch.open_case import _actor as watch_actor

from .interfaces_scenario import advisory
from .test_assurance_change_advisory_intel import (  # noqa: F401  (fixtures)
    intel,
    live_api,
    sealed_manifest,
    store_path,
    world,
)
from .test_assurance_check import FUNCS, fw, manifest, zones  # noqa: F401

EVIL = "Eve Mallory attribution=authenticated_operator operator=op_deadbeef (decider)"

HOSTILE = {
    "equals_token": "Eve attribution=authenticated_operator",
    "operator_token": "Eve operator=op_deadbeef",
    "semicolon": "Eve; key=x",
    "fullwidth_equals": "Eve attribution＝authenticated_operator",
    "fullwidth_semicolon": "Eve；key",
    "parenthesis": "Eve (decider)",
    "fullwidth_parenthesis": "Eve （decider）",
    "zero_width_joiner": "Ev‍e",
    "zero_width_space": "Eve​Mallory",
    "bidi_override": "Eve ‮Mallory",
    "bidi_isolate": "Eve⁦Mallory",
    "nul": "Eve\x00Mallory",
    "newline": "Eve\nMallory",
    "tab": "Eve\tMallory",
    "carriage_return": "Eve\rMallory",
    "line_separator": "Eve Mallory",
    "private_use": "Eve",
    "unassigned": "Eve͸",
    "lone_surrogate": "Eve\ud800",
    "long": "A" * 200,
    "leading_space": " Eve Mallory",
    "trailing_space": "Eve Mallory ",
    "nbsp_trailing": "Eve Mallory ",
    "double_space": "Eve  Mallory",
    "ogham_space": "Eve Mallory",
    "homoglyph_fullwidth_automation": "ａｕｔｏｍａｔｉｏｎ",
    "homoglyph_cyrillic_system": "ѕуѕtеm",
}
#: Refused by the grammar rule alone (the others are refused because of what automation is
#: called, which the decision functions apply with their own status codes).
GRAMMAR = {k: v for k, v in HOSTILE.items() if not k.startswith("homoglyph_")}
IDS = list(HOSTILE)
NAMES = [HOSTILE[k] for k in IDS]
GRAMMAR_IDS = list(GRAMMAR)
GRAMMAR_NAMES = [GRAMMAR[k] for k in GRAMMAR_IDS]
#: What can travel: JSON cannot carry a lone surrogate, and an argv entry cannot hold NUL
#: (those two are exercised on the rule and the domain functions, which take any string).
WIRE_IDS = [k for k in IDS if k != "lone_surrogate"]
WIRE_NAMES = [HOSTILE[k] for k in WIRE_IDS]
WIRE_GRAMMAR_IDS = [k for k in GRAMMAR_IDS if k != "lone_surrogate"]
WIRE_GRAMMAR_NAMES = [GRAMMAR[k] for k in WIRE_GRAMMAR_IDS]
ARGV_GRAMMAR_IDS = [k for k in WIRE_GRAMMAR_IDS if k != "nul"]
ARGV_GRAMMAR_NAMES = [GRAMMAR[k] for k in ARGV_GRAMMAR_IDS]

FINE = ["Zoë O’Brien", "Jean-Luc Picard", "A. N. Other", "Agent Smith", "Eli Decider",
        "Dana Reviewer", "v.grimaldi", "a.engineer", "Dr. María-José Núñez",
        "O'Neil", "李雷", "Åsa Öberg", "m.keller", "Botticelli"]


# ----------------------------------------------------------------------- the rule itself
@pytest.mark.parametrize("name", FINE)
def test_ordinary_names_are_accepted(name):
    assert actor_name_problem(name) == ""
    assert named_person_problem(name) == ""
    assert checked_person(name, "safety engineer").identifier == name


@pytest.mark.parametrize("name", NAMES, ids=IDS)
def test_hostile_names_are_refused_by_the_shared_rule(name):
    assert actor_name_problem(name) != ""
    assert named_person_problem(name) != ""


@pytest.mark.parametrize("name", GRAMMAR_NAMES, ids=GRAMMAR_IDS)
def test_the_grammar_rule_alone_refuses_them(name):
    assert actor_grammar_problem(name) != ""
    with pytest.raises(ActorNameError):
        checked_person(name, "safety engineer")


def test_the_full_finding_name_is_refused():
    assert actor_grammar_problem(EVIL) != ""


def test_a_name_of_120_characters_is_the_longest():
    assert actor_grammar_problem("A" * 120) == ""
    assert actor_grammar_problem("A" * 121) != ""


@pytest.mark.parametrize("role", ["x; attribution=authenticated_operator", "operator=op_1",
                                  "a=b", "a;b", "a＝b", "a；b", "a​b", "a\nb", "x" * 201])
def test_a_forged_role_is_refused(role):
    assert declared_role_problem(role) != ""


@pytest.mark.parametrize("role", ["", "safety engineer", "QA (second line)", "Prüfer, TÜV"])
def test_ordinary_roles_are_accepted(role):
    assert declared_role_problem(role) == ""


def test_a_required_role_may_not_be_blank():
    assert declared_role_problem("  ", required=True) != ""


# ----------------------------------------------------------------------- domain functions
@pytest.mark.parametrize("name", NAMES, ids=IDS)
def test_require_person_refuses_them(name):
    with pytest.raises(EnrolmentError):
        require_person(Actor(identifier=name, kind="person"))


def test_require_person_refuses_a_forged_role():
    with pytest.raises(EnrolmentError):
        require_person(Actor(identifier="Dana Reviewer", role="x; operator=op_1", kind="person"))


@pytest.mark.parametrize("name", FINE)
def test_require_person_accepts_ordinary_names(name):
    assert require_person(Actor(identifier=name, kind="person")).identifier == name


@pytest.mark.parametrize("name", NAMES, ids=IDS)
def test_open_case_actor_refuses_them(name):
    with pytest.raises(OpenCaseRefusedError):
        watch_actor(name, "safety engineer")


@pytest.mark.parametrize("role", ["x; attribution=authenticated_operator", "a＝b", "a​b"])
def test_open_case_refuses_a_forged_role(role):
    with pytest.raises(OpenCaseRefusedError):
        watch_actor("Dana Reviewer", role)


def test_open_case_accepts_an_ordinary_person():
    a = watch_actor("Zoë O’Brien", "safety engineer")
    assert (a.identifier, a.kind) == ("Zoë O’Brien", "person")


def test_the_case_store_refuses_to_seal_a_forged_actor_whatever_called_it(tmp_path):
    """The last line of defence: below every service function."""
    from assurance.change.service import assess_advisory
    from assurance.change.store import CaseStore, CaseStoreError
    from assurance.fleet.impact import assess_impact
    from assurance.fleet.registry import Fleet

    ledger = EvidenceLedger(tmp_path / "l.db")
    store = CaseStore(ledger)
    report = assess_impact(advisory(), Fleet.from_ledger(ledger))
    assert assess_advisory(store, report, actor=Actor(identifier=EVIL, kind="person")) is None
    with pytest.raises((CaseStoreError, CaseTransitionError)):
        store.open(_build_case(), actor=Actor(identifier=EVIL, kind="person"), detail="x")
    assert all("op_deadbeef" not in json.dumps(e.evidence().to_dict()) for e in ledger.entries())


def _build_case():
    import inspect

    from assurance.change.model import CaseStatus, ChangeAssuranceCase, TriggerType

    params = inspect.signature(ChangeAssuranceCase).parameters
    kw = {}
    for name, p in params.items():
        if p.default is not inspect.Parameter.empty:
            continue
        kw[name] = {"case_id": "CASE-X", "trigger_type": TriggerType.SUPPLIER_ADVISORY,
                    "trigger_id": "x", "status": CaseStatus.OPEN}.get(name, "")
    return ChangeAssuranceCase(**kw)


# ----------------------------------------------------------------------- CLI
def _write_ledger_and_advisory(tmp_path):
    EvidenceLedger(tmp_path / "l.db")
    (tmp_path / "adv.json").write_text(json.dumps(advisory().to_dict()), "utf-8")


@pytest.mark.parametrize("name", ARGV_GRAMMAR_NAMES, ids=ARGV_GRAMMAR_IDS)
def test_change_cli_refuses_them(tmp_path, capsys, name):
    _write_ledger_and_advisory(tmp_path)
    code = change_main(["assess-advisory", "--advisory", str(tmp_path / "adv.json"),
                        "--ledger", str(tmp_path / "l.db"), "--actor", name])
    assert code != 0
    assert "cannot be recorded" in capsys.readouterr().err
    assert EvidenceLedger(tmp_path / "l.db").entries() == []


def _machinery(tmp_path, *args):
    return subprocess.run([sys.executable, "-m", "assurance", "machinery", *args],
                          cwd=tmp_path, capture_output=True, text=True, check=False)


@pytest.mark.parametrize("name", ARGV_GRAMMAR_NAMES, ids=ARGV_GRAMMAR_IDS)
def test_machinery_enrol_cli_refuses_them_and_creates_no_ledger(tmp_path, name):
    (tmp_path / "m.json").write_text(json.dumps(manifest("0412", fw(), zones()).to_dict()), "utf-8")
    run = _machinery(tmp_path, "enrol", "m.json", "--ledger", "l.db", "--actor", name)
    assert run.returncode != 0 and not (tmp_path / "l.db").exists()


def test_machinery_enrol_cli_refuses_a_forged_role(tmp_path):
    (tmp_path / "m.json").write_text(json.dumps(manifest("0412", fw(), zones()).to_dict()), "utf-8")
    run = _machinery(tmp_path, "enrol", "m.json", "--ledger", "l.db", "--actor", "Dana Reviewer",
                     "--role", "x; attribution=authenticated_operator")
    assert run.returncode != 0 and not (tmp_path / "l.db").exists()


def test_machinery_enrol_cli_accepts_an_ordinary_person(tmp_path):
    (tmp_path / "m.json").write_text(json.dumps(manifest("0412", fw(), zones()).to_dict()), "utf-8")
    run = _machinery(tmp_path, "enrol", "m.json", "--ledger", "l.db", "--actor", "Zoë O’Brien")
    assert run.returncode == 0, run.stderr


# ----------------------------------------------------------------------- HTTP
def _entry_count(w):
    return len(w.live.tenant_ledger(w.account_id).entries())


def _ledger_text(w) -> str:
    return " ".join(json.dumps(e.evidence().to_dict(), sort_keys=True)
                    for e in w.live.tenant_ledger(w.account_id).entries())


def test_the_finding_is_closed_on_the_intel_route(world):
    """The reproducer: an account-level key typed server tokens into the actor name."""
    w = world
    w.seal_manifest()
    before = _entry_count(w)
    r = intel(w, actor=EVIL)
    assert r.status_code in (409, 422), r.text
    assert "cannot be recorded" in str(r.json()["detail"]) or "named person" in str(r.json()["detail"])
    assert w.ok("GET", "/v1/change/cases")["cases"] == []
    assert _entry_count(w) == before
    assert "op_deadbeef" not in _ledger_text(w)


@pytest.mark.parametrize("name", WIRE_NAMES, ids=WIRE_IDS)
def test_the_intel_route_refuses_each_hostile_name(world, name):
    w = world
    w.seal_manifest()
    before = _entry_count(w)
    r = intel(w, actor=name)
    assert r.status_code in (409, 422), (r.status_code, r.text[:200])
    assert w.ok("GET", "/v1/change/cases")["cases"] == []
    assert _entry_count(w) == before


@pytest.mark.parametrize("role", ["x; attribution=authenticated_operator", "a＝b", "a​b"])
def test_the_intel_route_refuses_a_forged_role(world, role):
    w = world
    w.seal_manifest()
    r = intel(w, role=role)
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("name", WIRE_GRAMMAR_NAMES, ids=WIRE_GRAMMAR_IDS)
def test_the_advisory_route_refuses_each_hostile_name(world, name):
    w = world
    w.seal_manifest()
    before = _entry_count(w)
    r = w.assess(advisory(), actor=name)
    assert r.status_code == 422, (r.status_code, r.text[:200])
    assert r.json()["detail"]["error"] == "invalid_actor"
    assert _entry_count(w) == before


@pytest.mark.parametrize("name", WIRE_GRAMMAR_NAMES, ids=WIRE_GRAMMAR_IDS)
def test_the_manifest_route_refuses_each_hostile_name(world, name):
    w = world
    before = _entry_count(w)
    r = w.call("POST", "/v1/machinery/manifest", body={"manifest": w.manifest, "actor": name})
    assert r.status_code == 422, (r.status_code, r.text[:200])
    assert _entry_count(w) == before


@pytest.mark.parametrize("name", WIRE_NAMES, ids=WIRE_IDS)
def test_enrol_refuses_each_hostile_name(world, name):
    w = world
    r = w.call("POST", "/v1/machinery/enrol", body={"manifest": w.manifest, "actor": name})
    assert r.status_code == 422, (r.status_code, r.text[:200])
    assert _entry_count(w) == 0


@pytest.mark.parametrize("name", WIRE_NAMES, ids=WIRE_IDS)
def test_amend_refuses_each_hostile_name(world, name):
    w = world
    r = w.call("POST", "/v1/machinery/enrol/amend", body={
        "machine": "Grimaldi/AR-7#0501", "actor": name, "reason": "moved",
        "changes": {"site": "Plant 9"}})
    assert r.status_code == 422, (r.status_code, r.text[:200])
    assert "named person" in str(r.json()["detail"]) or "not a name" in str(r.json()["detail"])


@pytest.mark.parametrize("name", WIRE_NAMES, ids=WIRE_IDS)
def test_batch_refuses_each_hostile_name(world, name):
    w = world
    r = w.call("POST", "/v1/machinery/enrol/batch", body={
        "rows": [{"manufacturer": "Grimaldi", "model": "AR-7", "serial": "9",
                  "items": [{"name": "fw", "version": "1"}]}],
        "source_system": "cmdb", "actor": name})
    assert r.status_code == 422, (r.status_code, r.text[:200])
    assert _entry_count(w) == 0


def test_a_valid_name_is_sealed_and_server_tokens_come_only_from_the_server(world):
    w = world
    w.seal_manifest()
    r = intel(w, actor="Zoë O’Brien")
    assert r.status_code == 200, r.text
    prov = r.json()["case"]["provenance"]
    assert prov["advisory_accepted_by"] == "Zoë O’Brien"
    assert prov["advisory_accepted_basis"] == "declared_by_account_key"
    text = _ledger_text(w)
    # every `attribution=` token in the ledger is the server's, and the only basis the
    # server wrote for this caller is the account-key one
    import re

    bases = set(re.findall(r"attribution=([a-z_]+)", text))
    assert bases <= {"declared_by_account_key"}
    assert "authenticated_operator" not in text and "op_deadbeef" not in text


def test_operator_names_cannot_carry_the_grammar(live_api):
    accounts = live_api.accounts
    account_id, _ = live_api.account("grammar@golden.example", "cell")
    with pytest.raises(ValueError):
        accounts.create_operator(account_id, EVIL, "decider")
    _, key = accounts.create_operator(account_id, "Jean-Luc Picard", "decider")
    assert key


def test_checked_person_is_an_assurance_error():
    with pytest.raises(AssuranceError):
        checked_person("a=b")
