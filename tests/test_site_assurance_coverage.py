"""The /assurance "Coverage" panel: what share of the fleet has evidence, verification, an intel
match and an attested anchor.

Two kinds of check, in the repo's pattern for the site. Source-level checks read ``app/**`` (the
panel calls only documented GET routes, stores nothing, mounts in the workspace, shows its
denominators and its UNKNOWN column). Behaviour checks run the pure ``app/lib/coverage.ts`` with
node type stripping, fed (a) hand-built answers for each edge and (b) the REAL JSON the server's
own domain functions produce for a real ledger (``assess_position``, ``Fleet.to_dict``, an
attestation signed by ``attest``), so a renamed server field fails here. The browser behaviour is
``tests-e2e/assurance-coverage.spec.ts``.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assurance.attest.attestation import AttestationLog, attest
from assurance.attest.keys import SigningKey
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import HashSource
from assurance.machinery.record import record_manifest
from assurance.value.position import assess_position

from .test_assurance_change import fw, manifest, seal_a_real_verification
from .test_assurance_change import ledger as ledger  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / "app" / "components" / "assurance"
PANEL = COMP / "CoveragePanel.tsx"
VIEW = COMP / "CoverageView.tsx"
LIB = ROOT / "app" / "lib" / "coverage.ts"
OPENAPI = json.loads((ROOT / "public" / "openapi.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 10, 22, tzinfo=UTC)


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code(path: Path) -> str:
    src = re.sub(r"/\*.*?\*/", "", text(path), flags=re.S)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("//"))


def compute(inp: dict[str, Any]) -> dict[str, Any]:
    node = shutil.which("node")
    assert node, "node is not installed"
    script = (
        "const m = await import('./app/lib/coverage.ts');"
        f"process.stdout.write(JSON.stringify(m.computeCoverage({json.dumps(inp)})));"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is built in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


# ------------------------------------------------------------------ hand-built answers
def frow(machine: str, cfg: str = "h1", verdict: str = "gaps") -> dict[str, Any]:
    return {"machine": machine, "site": "", "configuration_hash": cfg, "verdict": verdict}


def fleet(*rows: dict[str, Any], chain: bool = True) -> dict[str, Any]:
    return {"summary": {}, "machines": list(rows), "chain_verified": chain, "chain_problems": []}


def vmachine(machine: str, *, items=2, read=2, functions=1, current=1, collection_incomplete=False,
             manifest_=True, **extra: int) -> dict[str, Any]:
    if not manifest_:
        return {"machine": machine, "manifest": None, "inventory": None, "coverage": None}
    return {
        "machine": machine,
        "manifest": {"manifest_id": "M", "taken_at": "x", "configuration_hash": "h1",
                     "collection_incomplete": collection_incomplete},
        "inventory": {"items": items, "read_from_machine": read, "supplied_by_vendor": 0,
                      "declared_only": items - read},
        "coverage": {"functions": functions, "current": current, **extra},
    }


def value(*machines: dict[str, Any], findings=None, withheld="") -> dict[str, Any]:
    v: dict[str, Any] = {"as_of": "x", "machines": list(machines), "findings": findings or [],
                         "ledger": {"entries": 9, "chain_verified": True, "chain_problems": []}}
    if withheld:
        v["withheld"] = withheld
    return v


def ok(data: Any) -> dict[str, Any]:
    return {"status": "ok", "data": data}


DOWN = {"status": "unavailable", "reason": "Plan does not include this (402)"}
LOADING = {"status": "loading"}
NO_CASES = ok({"cases": [], "summary": {}})
NO_ATTEST = ok({"count": 0, "attestations": [], "warnings": []})


def cell(report, machine, dim):
    row = next(m for m in report["machines"] if m["machine"] == machine)
    return row["cells"][dim]


class TestAnEmptyFleetIsNotClear:
    def test_zero_machines_is_empty_and_every_denominator_is_zero(self):
        r = compute({"fleet": fleet(), "value": ok(value()), "cases": NO_CASES, "attest": NO_ATTEST})
        assert r["empty"] is True and r["machines"] == []
        for dim in ("evidence", "verification", "intel", "anchor"):
            t = r["tally"][dim]
            assert t == {"covered": 0, "partial": 0, "none": 0, "unknown": 0, "denominator": 0}

    def test_the_share_of_nothing_is_not_defined_rather_than_zero_or_one_hundred(self):
        out = subprocess.run(  # noqa: S603
            [shutil.which("node") or "node", "--experimental-strip-types", "--no-warnings",
             "--input-type=module", "-e",
             "const m = await import('./app/lib/coverage.ts');"
             "process.stdout.write(m.shareText(0, 0));"],
            capture_output=True, text=True, check=True, cwd=ROOT, timeout=120).stdout
        assert "not defined" in out and "%" not in out

    def test_the_view_says_so_and_does_not_draw_a_table(self):
        src = code(VIEW)
        assert "coverage-empty" in src and "not clear and not covered" in " ".join(src.split())
        assert src.index("report.empty") < src.index("coverage-machines")


class TestMissingDataIsUnknownNeverCoveredNeverZero:
    def test_a_source_that_is_down_makes_its_cells_unknown_and_counts_them(self):
        r = compute({"fleet": fleet(frow("A"), frow("B")), "value": DOWN, "cases": DOWN, "attest": DOWN})
        for dim in ("evidence", "verification", "intel", "anchor"):
            t = r["tally"][dim]
            assert t["unknown"] == 2 and t["covered"] == 0 and t["none"] == 0 and t["denominator"] == 2
            assert "unavailable" in cell(r, "A", dim)["reason"]

    def test_a_source_still_loading_is_unknown_not_covered(self):
        r = compute({"fleet": fleet(frow("A")), "value": LOADING, "cases": LOADING, "attest": LOADING})
        assert [cell(r, "A", d)["state"] for d in ("evidence", "verification", "intel", "anchor")] \
            == ["unknown"] * 4
        assert "not answered" in cell(r, "A", "intel")["reason"]

    def test_a_machine_missing_from_the_position_answer_is_unknown(self):
        r = compute({"fleet": fleet(frow("A"), frow("B")), "value": ok(value(vmachine("A"))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        assert cell(r, "A", "evidence")["state"] == "covered"
        assert cell(r, "B", "evidence")["state"] == "unknown"
        assert cell(r, "B", "verification")["state"] == "unknown"

    def test_no_manifest_is_not_covered_and_not_an_unseen_pass(self):
        r = compute({"fleet": fleet(frow("A")), "value": ok(value(vmachine("A", manifest_=False))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        assert cell(r, "A", "evidence")["state"] == "none"
        assert cell(r, "A", "verification")["state"] == "none"

    def test_no_declared_function_is_unknown_not_covered(self):
        r = compute({"fleet": fleet(frow("A")), "value": ok(value(vmachine("A", functions=0, current=0))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        assert cell(r, "A", "verification")["state"] == "unknown"

    def test_a_withheld_position_is_unknown_for_evidence_and_verification(self):
        r = compute({"fleet": fleet(frow("A")),
                     "value": ok(value(withheld="the ledger's hash chain does not verify")),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        assert cell(r, "A", "evidence")["state"] == "unknown"
        assert cell(r, "A", "verification")["state"] == "unknown"
        assert r["functions"] is None

    def test_a_broken_chain_makes_every_cell_unknown_even_if_the_rows_look_fine(self):
        r = compute({"fleet": fleet(frow("A"), chain=False), "value": ok(value(vmachine("A"))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        assert all(cell(r, "A", d)["state"] == "unknown"
                   for d in ("evidence", "verification", "intel", "anchor"))
        assert r["chain_verified"] is False

    def test_the_functions_total_is_unknown_not_zero_when_the_position_is_down(self):
        r = compute({"fleet": fleet(frow("A")), "value": DOWN, "cases": NO_CASES, "attest": NO_ATTEST})
        assert r["functions"] is None


class TestEachDimensionsRule:
    def test_evidence_covered_only_when_every_item_was_read_off_the_unit(self):
        r = compute({"fleet": fleet(frow("A"), frow("B"), frow("C")),
                     "value": ok(value(vmachine("A"), vmachine("B", read=1),
                                       vmachine("C", collection_incomplete=True))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        assert [cell(r, m, "evidence")["state"] for m in "ABC"] == ["covered", "partial", "partial"]

    def test_verification_partial_when_some_functions_are_not_current(self):
        r = compute({"fleet": fleet(frow("A"), frow("B"), frow("C")),
                     "value": ok(value(vmachine("A", functions=3, current=3),
                                       vmachine("B", functions=3, current=2, stale=1),
                                       vmachine("C", functions=3, current=0, never_verified=3))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        assert [cell(r, m, "verification")["state"] for m in "ABC"] == ["covered", "partial", "none"]
        assert "1 stale" in cell(r, "B", "verification")["reason"]
        assert r["functions"] == {"current": 5, "total": 9, "machines_without_figures": 0}

    def test_verification_below_validated_is_partial_not_covered(self):
        r = compute({"fleet": fleet(frow("A", verdict="covered_at_community")),
                     "value": ok(value(vmachine("A"))), "cases": NO_CASES, "attest": NO_ATTEST})
        assert cell(r, "A", "verification")["state"] == "partial"

    def test_unchecked_and_incomplete_functions_are_never_current(self):
        r = compute({"fleet": fleet(frow("A")),
                     "value": ok(value(vmachine("A", functions=2, current=0, unchecked=1, incomplete=1))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        c = cell(r, "A", "verification")
        assert c["state"] == "none" and "1 unchecked" in c["reason"] and "1 incomplete" in c["reason"]

    def test_intel_is_covered_only_by_an_advisory_case_and_otherwise_unknown_never_clear(self):
        cases = ok({"cases": [
            {"case_id": "C-1", "trigger": "supplier_advisory", "machines": ["A"]},
            {"case_id": "C-2", "trigger": "machine_drift", "machines": ["B"]},
        ], "summary": {}})
        r = compute({"fleet": fleet(frow("A"), frow("B"), frow("C")),
                     "value": ok(value(vmachine("A"), vmachine("B"), vmachine("C"))),
                     "cases": cases, "attest": NO_ATTEST})
        assert [cell(r, m, "intel")["state"] for m in "ABC"] == ["covered", "unknown", "unknown"]
        assert "not a finding of no match" in cell(r, "C", "intel")["reason"]
        assert r["tally"]["intel"]["none"] == 0   # the service never learns "no match" here

    def _anchored(self, records, seq):
        finding = {"kind": "fact", "machine": "A", "statement": "A: manifest",
                   "refs": [{"seq": seq, "content_hash": "h"}]}
        return compute({"fleet": fleet(frow("A")), "value": ok(value(vmachine("A"), findings=[finding])),
                        "cases": NO_CASES,
                        "attest": ok({"count": len(records), "attestations": records, "warnings": []})})

    @staticmethod
    def rec(basis, head_seq):
        return {"sequence": 1, "ledger_length": head_seq, "head_seq": head_seq, "basis": basis,
                "attested_at": "2026-10-01T00:00:00Z", "key_fingerprint": "f"}

    def test_a_record_at_or_before_an_operator_read_head_is_anchored(self):
        r = self._anchored([self.rec("read_from_ledger", 5)], 5)
        assert cell(r, "A", "anchor")["state"] == "covered"
        assert "signature not checked" in cell(r, "A", "anchor")["reason"]

    def test_a_record_after_the_latest_anchor_is_not_covered(self):
        r = self._anchored([self.rec("read_from_ledger", 5)], 6)
        assert cell(r, "A", "anchor")["state"] == "none"

    def test_the_newest_operator_read_head_is_the_anchor_not_the_first(self):
        r = self._anchored([self.rec("read_from_ledger", 3), self.rec("read_from_ledger", 9),
                            self.rec("read_from_ledger", 4)], 8)
        assert cell(r, "A", "anchor")["state"] == "covered"

    def test_holder_declared_attestations_never_anchor_a_hosted_record(self):
        r = self._anchored([self.rec("declared_by_holder", 99)], 1)
        c = cell(r, "A", "anchor")
        assert c["state"] == "none" and "declared by the holder" in c["reason"]

    def test_an_empty_log_is_not_covered(self):
        r = self._anchored([], 1)
        assert cell(r, "A", "anchor")["state"] == "none"

    def test_an_anchor_with_no_known_record_position_is_unknown_not_covered(self):
        r = compute({"fleet": fleet(frow("A")), "value": ok(value(vmachine("A"))), "cases": NO_CASES,
                     "attest": ok({"count": 1, "attestations": [self.rec("read_from_ledger", 9)],
                                   "warnings": []})})
        assert cell(r, "A", "anchor")["state"] == "unknown"


class TestDenominatorsAndConfigurations:
    def test_the_four_states_always_add_up_to_the_denominator(self):
        r = compute({"fleet": fleet(frow("A"), frow("B"), frow("C"), frow("D")),
                     "value": ok(value(vmachine("A"), vmachine("B", read=0),
                                       vmachine("C", manifest_=False))),
                     "cases": DOWN, "attest": NO_ATTEST})
        for tally in list(r["tally"].values()) + list(r["configurations"]["tally"].values()):
            assert tally["covered"] + tally["partial"] + tally["none"] + tally["unknown"] \
                == tally["denominator"]
        assert r["tally"]["evidence"]["denominator"] == 4

    def test_a_configuration_is_covered_only_if_every_machine_on_it_is(self):
        r = compute({"fleet": fleet(frow("A", "h1"), frow("B", "h1"), frow("C", "h2")),
                     "value": ok(value(vmachine("A"), vmachine("B", read=0), vmachine("C"))),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        c = r["configurations"]
        assert c["denominator"] == 2 and c["tally"]["evidence"]["covered"] == 1
        assert c["tally"]["evidence"]["partial"] == 1

    def test_a_configuration_with_one_covered_and_one_unknown_machine_is_unknown(self):
        r = compute({"fleet": fleet(frow("A", "h1"), frow("B", "h1")),
                     "value": ok(value(vmachine("A"))), "cases": NO_CASES, "attest": NO_ATTEST})
        assert r["configurations"]["tally"]["evidence"] == {
            "covered": 0, "partial": 0, "none": 0, "unknown": 1, "denominator": 1}

    def test_machines_without_a_hash_are_counted_apart_not_dropped(self):
        r = compute({"fleet": fleet(frow("A", ""), frow("B", "h1")),
                     "value": ok(value(vmachine("A"), vmachine("B"))), "cases": NO_CASES,
                     "attest": NO_ATTEST})
        assert r["configurations"]["denominator"] == 1 and r["configurations"]["unhashed_machines"] == 1
        assert r["tally"]["evidence"]["denominator"] == 2


# ------------------------------------------------------------------ the server's real JSON
class TestAgainstWhatTheServerReallySends:
    def test_a_real_ledger_feeds_the_report_through_the_real_domain_functions(self, ledger, tmp_path):
        record_manifest(ledger, manifest(fw(), manifest_id="M-ONE"))
        seal_a_real_verification(ledger, when=datetime(2026, 1, 21, tzinfo=UTC))
        pos = assess_position(ledger, now=NOW)
        flt = Fleet.from_ledger(ledger).to_dict()
        log = AttestationLog(tmp_path / "attest.jsonl")
        attest(ledger, SigningKey.generate(), log)
        att = {"count": 1, "attestations": [a.to_dict() for a in log.read()], "warnings": []}
        r = compute({"fleet": flt, "value": ok(pos), "cases": NO_CASES, "attest": ok(att)})
        assert len(r["machines"]) == 1
        m = r["machines"][0]["machine"]
        assert cell(r, m, "evidence")["state"] == "covered"
        assert cell(r, m, "verification")["state"] in ("covered", "partial")
        assert cell(r, m, "anchor")["state"] == "covered"      # sealed before the operator-read head
        assert cell(r, m, "intel")["state"] == "unknown"

    def test_a_vendor_hashed_item_is_partial_evidence_in_the_real_answer(self, ledger):
        record_manifest(ledger, manifest(fw(hash_source=HashSource.SUPPLIED_BY_VENDOR), manifest_id="V"))
        pos = assess_position(ledger, now=NOW)
        r = compute({"fleet": Fleet.from_ledger(ledger).to_dict(), "value": ok(pos),
                     "cases": NO_CASES, "attest": NO_ATTEST})
        m = r["machines"][0]["machine"]
        assert cell(r, m, "evidence")["state"] == "partial"
        assert cell(r, m, "verification")["state"] == "none"       # nothing verified
        assert cell(r, m, "anchor")["state"] == "none"

    def test_the_fields_the_logic_reads_exist_in_the_servers_sources(self):
        position = text(ROOT / "src" / "assurance" / "value" / "position.py")
        for field in ("collection_incomplete", "read_from_machine", "supplied_by_vendor",
                      "declared_only", "configuration_hash", "withheld", "findings"):
            assert f'"{field}"' in position, field
        att = text(ROOT / "src" / "assurance" / "attest" / "attestation.py")
        for field in ("head_seq", "basis", "attested_at", "read_from_ledger", "declared_by_holder"):
            assert field in att, field
        assert 'SUPPLIER_ADVISORY = "supplier_advisory"' in text(
            ROOT / "src" / "assurance" / "change" / "model.py")


# ------------------------------------------------------------------ the source of the panel
class TestThePanelIsWiredHonestly:
    def test_files_exist_and_the_workspace_mounts_it_with_the_shared_panels(self):
        for p in (PANEL, VIEW, LIB):
            assert p.is_file(), p
        ws = text(ROOT / "app" / "components" / "AssuranceWorkspace.tsx")
        assert re.search(r"<CoveragePanel apiKey=\{key\} fleet=\{fleet\} queue=\{queue\}", ws)
        assert "import CoveragePanel from './assurance/CoveragePanel'" in ws

    def test_it_reads_only_documented_get_routes_and_no_others(self):
        src = code(PANEL)
        routes = re.findall(r"""['"`](/v1/[\w/.-]+)""", src)
        assert sorted(set(routes)) == ["/v1/change/cases", "/v1/fleet/machines", "/v1/ledger/attest/log",
                                       "/v1/value"]
        for route in set(routes):
            assert "get" in OPENAPI["paths"][route], route
            assert "post" not in OPENAPI["paths"][route] or route == "/v1/ledger/attest/log"
        assert "method:" not in src and "POST" not in src

    def test_it_stores_nothing_and_never_fetches_directly(self):
        for p in (PANEL, VIEW, LIB):
            src = code(p)
            assert not re.search(r"localStorage|sessionStorage|document\.cookie|console\.|fetch\(", src), p.name

    def test_it_makes_no_safety_or_compliance_claim(self):
        for p in (PANEL, VIEW, LIB):
            visible = re.sub(r"not a statement that any machine is safe or compliant", "", code(p))
            assert not re.search(r"\b(compliant|certified|approved|is safe|are safe|verified safe)\b",
                                 visible, re.I), p.name

    def test_the_view_shows_every_denominator_and_an_unknown_column(self):
        src = code(VIEW)
        for needle in ("tally-denominator", "tally-unknown", "tally-covered", "Unknown",
                       "All {unit} (denominator)", "coverage-rows", "m.cells[d].reason"):
            assert needle in src, needle
        assert "shareText(t.covered, t.denominator)" in src

    def test_unknown_is_not_styled_as_covered_and_state_is_text_not_colour_only(self):
        src = code(VIEW)
        assert "state === 'covered' ? undefined : 'aw-bad'" in src
        assert "unknown: 'UNKNOWN'" in src

    def test_a_percentage_is_never_computed_without_a_denominator(self):
        src = code(LIB)
        body = src.split("export function shareText", 1)[1]
        assert body.index("denominator <= 0") < body.index("Math.round")

    def test_sources_that_have_not_answered_are_listed_with_the_cells_they_feed(self):
        src = code(PANEL)
        assert "the cells it feeds are UNKNOWN" in src and "data-status" in src
        # last-good data is not reused for the extra sources: only an ok outcome is a source
        assert "o.kind === 'ok'" in src and "good" not in src.split("function sourceOf", 1)[1].split("}\n", 3)[0]
