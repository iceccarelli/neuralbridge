"""The /assurance workspace "Machine passport" panel.

Source-level checks on the TSX/TS (the repo's pattern for the site), plus the pure reader in
``app/lib/passportDoc.ts`` run under node on a passport the real domain function built, plus
parity with the real HTTP routes (``POST /v1/machinery/passport`` and ``/passport/check``). They
pin that the panel calls exactly the documented routes, sends no key to the free check, never
seals, never reads a missing value as a good or zero one, and keeps "not checked" apart from
"no problem found". The browser behaviour is ``tests-e2e/assurance-passport.spec.ts``.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.record import build_passport
from tests.test_assurance_check import fw, manifest, zones

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / "app" / "components" / "assurance"
PANEL = COMP / "PassportPanel.tsx"
VIEW = COMP / "PassportView.tsx"
DOC = ROOT / "app" / "lib" / "passportDoc.ts"
API = ROOT / "app" / "lib" / "passportApi.ts"
FILES = (PANEL, VIEW, DOC, API)
OPENAPI = json.loads((ROOT / "public" / "openapi.json").read_text(encoding="utf-8"))


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code(path: Path) -> str:
    src = re.sub(r"/\*.*?\*/", "", text(path), flags=re.S)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("//"))


def _node(script: str) -> object:
    node = shutil.which("node")
    assert node, "node is not installed"
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is built in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _passport(tmp_path: Path) -> dict:
    ledger = EvidenceLedger(tmp_path / "l.db")
    built = build_passport(ledger, manifest("PP-0001", fw(), zones()),
                           actor=Actor(identifier="Ada Integrator", role="verification engineer", kind="person"),
                           seal=False)
    return built.to_dict()


def _read(doc: dict) -> dict:
    return _node(
        "const m = await import('./app/lib/passportDoc.ts');"
        f"process.stdout.write(JSON.stringify(m.readPassport({json.dumps(doc)})));")


class TestMountedAndRoutedToTheDocumentedRoutes:
    def test_the_files_exist(self):
        for path in FILES:
            assert path.is_file(), path

    def test_the_workspace_mounts_the_panel_with_the_shared_actor(self):
        ws = text(ROOT / "app" / "components" / "AssuranceWorkspace.tsx")
        assert re.search(r"<PassportPanel apiKey=\{key\} actor=\{actor\} setActor=\{setActor\} />", ws)

    def test_exactly_the_two_documented_routes(self):
        routes = re.findall(r"""['"`](/v1/[^'"`]*)""", code(API))
        assert routes == ["/v1/machinery/passport/check", "/v1/machinery/passport"]
        for route in routes:
            assert "post" in OPENAPI["paths"][route]
        for path in (PANEL, VIEW, DOC):
            assert not re.findall(r"""['"`](/v1/[^'"`]*)""", code(path)), path.name

    def test_the_assemble_body_uses_documented_fields_and_never_seals(self):
        ref = OPENAPI["paths"]["/v1/machinery/passport"]["post"]["requestBody"]["content"][
            "application/json"]["schema"]["$ref"]
        schema = OPENAPI["components"]["schemas"][ref.rsplit("/", 1)[1]]
        body = code(API).split("body: { manifest", 1)[1].split("},", 1)[0]
        sent = {"manifest"} | set(re.findall(r"\b(actor|role|seal)\b", body))
        assert sent <= set(schema["properties"]), (sent, set(schema["properties"]))
        assert "seal: false" in code(API)
        assert not re.search(r"seal:\s*true|seal:\s*(?!false)\w", code(API))

    def test_the_free_check_is_sent_without_a_key(self):
        # `call(base, '', ...)`: the check is open to anyone, so nothing identifying goes with it.
        assert re.search(r"call<PassportCheck>\(apiBase, '', '/v1/machinery/passport/check'", code(API))
        assert "apiKey" not in code(API).split("export function checkPassport", 1)[1].split("export function assemblePassport", 1)[0]

    def test_the_check_route_is_free_and_the_assemble_route_is_not(self):
        caps = text(ROOT / "src" / "assurance" / "capabilities.py")
        assert '"POST /v1/machinery/passport/check", "machinery_passport_check"' in caps

    def test_nothing_is_stored_logged_or_fetched_directly(self):
        for path in FILES:
            src = code(path)
            assert not re.search(r"localStorage|sessionStorage|document\.cookie|console\.", src), path.name
            assert "fetch(" not in src, path.name
        assert "API_BASE" in code(PANEL)

    def test_the_actor_is_checked_before_assembling(self):
        src = code(PANEL)
        assert src.index("actorProblem(actor)") < src.index("await assemblePassport")

    def test_a_late_answer_for_an_older_request_is_ignored(self):
        src = code(PANEL)
        assert src.count("if (id !== seq.current) return;") >= 2


class TestWhatTheReaderTakesFromARealPassport:
    def test_it_reads_the_domain_functions_own_output(self, tmp_path):
        raw = _passport(tmp_path)
        out = _read(raw)
        assert out["ok"] is True
        doc = out["doc"]
        body = raw["evidence"]["body"]
        assert doc["verdict"] == body["verdict"] == "gaps"
        assert doc["content_hash"] == raw["evidence"]["content_hash"]
        assert doc["configuration_hash"] == body["configuration_hash"]
        assert [f["function_id"] for f in doc["functions"]] == ["SF-01", "SF-02"]
        assert {f["coverage"] for f in doc["functions"]} == {"never_verified"}
        assert doc["actor"] == {"identifier": "Ada Integrator", "role": "verification engineer", "kind": "person"}
        assert doc["checks_skipped"] == list(raw["evidence"]["checks_skipped"])
        assert doc["verification_hashes"] == []

    def test_an_empty_tier_is_no_tier_and_an_empty_hash_is_none_recorded(self, tmp_path):
        doc = _read(_passport(tmp_path))["doc"]
        assert doc["evidence_tier_floor"] is None
        assert all(f["last_verified_hash"] is None and f["evidence_tier"] is None for f in doc["functions"])
        assert doc["ledger_head"] is not None  # a head is recorded

    def test_a_missing_field_is_null_never_zero_false_or_empty(self, tmp_path):
        raw = _passport(tmp_path)
        for k in ("ledger_chain_verified", "verification_hashes", "intervention_ids", "verdict", "ledger_head"):
            del raw["evidence"]["body"][k]
        doc = _read(raw)["doc"]
        assert doc["ledger_chain_verified"] is None
        assert doc["verification_hashes"] is None and doc["intervention_ids"] is None
        assert doc["verdict"] is None and doc["ledger_head"] is None

    @pytest.mark.parametrize("bad", [
        [], "x", None, 3, {}, {"schema": "assurance.machinery.passport/9"},
        {"schema": "assurance.machinery.passport/1"},
        {"schema": "assurance.machinery.passport/1", "evidence": {"body": []}},
    ])
    def test_a_file_that_is_not_a_passport_is_refused_with_a_reason(self, bad):
        out = _node("const m = await import('./app/lib/passportDoc.ts');"
                    f"process.stdout.write(JSON.stringify(m.readPassport({json.dumps(bad)})));")
        assert out["ok"] is False and out["reason"]


class TestTheGapsAreEverythingUnchecked:
    def _gaps(self, doc: dict, check: dict | None) -> list[dict]:
        return _node(
            "const m = await import('./app/lib/passportDoc.ts');"
            f"const r = m.readPassport({json.dumps(doc)});"
            f"process.stdout.write(JSON.stringify(m.passportGaps(r.doc, {json.dumps(check)})));")

    def test_with_no_check_answer_the_first_gap_says_nothing_was_checked(self, tmp_path):
        gaps = self._gaps(_passport(tmp_path), None)
        assert gaps[0]["id"] == "check-not-run" and "nothing in this file has been checked" in gaps[0]["text"]

    def test_the_ledger_is_listed_as_not_checked_and_the_producers_own_skips_are_kept(self, tmp_path):
        raw = _passport(tmp_path)
        check = {"ok": True, "problems": ["NOT CHECKED: no ledger was supplied."],
                 "checked": {"seal": True, "internal_consistency": True, "against_ledger": False}}
        gaps = self._gaps(raw, check)
        texts = {g["id"]: g for g in gaps}
        assert texts["not-against-ledger"]["source"] == "check"
        assert texts["limit-0"]["text"] == "NOT CHECKED: no ledger was supplied."
        skipped = [g["text"] for g in gaps if g["source"] == "passport"]
        assert skipped == list(raw["evidence"]["checks_skipped"])

    def test_every_function_that_is_not_current_is_a_gap_and_so_are_no_verification_and_no_tier(self, tmp_path):
        gaps = self._gaps(_passport(tmp_path), {"ok": True, "problems": [],
                          "checked": {"seal": True, "internal_consistency": True, "against_ledger": False}})
        ids = {g["id"] for g in gaps}
        assert {"fn-SF-01", "fn-SF-02", "no-vf", "no-tier"} <= ids
        assert "never_verified" in next(g["text"] for g in gaps if g["id"] == "fn-SF-01")

    def test_an_unstated_chain_and_unstated_verifications_are_gaps_not_silence(self, tmp_path):
        raw = _passport(tmp_path)
        del raw["evidence"]["body"]["ledger_chain_verified"]
        del raw["evidence"]["body"]["verification_hashes"]
        ids = {g["id"] for g in self._gaps(raw, None)}
        assert {"chain-unstated", "no-vf-field"} <= ids

    def test_a_chain_that_failed_is_stated_as_covering_nothing(self, tmp_path):
        raw = _passport(tmp_path)
        raw["evidence"]["body"]["ledger_chain_verified"] = False
        gap = next(g for g in self._gaps(raw, None) if g["id"] == "chain")
        assert "Nothing in it is covered" in gap["text"]

    def test_a_current_function_is_not_listed_as_a_gap(self, tmp_path):
        raw = _passport(tmp_path)
        raw["evidence"]["body"]["functions"][0]["coverage"] = "current"
        assert "fn-SF-01" not in {g["id"] for g in self._gaps(raw, None)}
        assert "fn-SF-02" in {g["id"] for g in self._gaps(raw, None)}


class TestParityWithTheRealRoutes:
    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        from assurance.api import deps
        from assurance.api.service import create_app

        monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "l.db"))
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "a.db"))
        monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
        monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
        deps._register_for.cache_clear()
        deps._accounts_for.cache_clear()
        with TestClient(create_app()) as c:
            yield c, deps.get_accounts()
        deps._register_for.cache_clear()
        deps._accounts_for.cache_clear()

    def test_a_clean_check_lists_only_not_checked_limitations(self, client, tmp_path):
        c, _ = client
        r = c.post("/v1/machinery/passport/check", json={"passport": _passport(tmp_path)})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True and body["checked"]["against_ledger"] is False
        assert body["problems"] and all(p.startswith("NOT CHECKED") for p in body["problems"])

    def test_the_page_splits_findings_from_limitations_as_the_server_words_them(self, client, tmp_path):
        c, _ = client
        raw = _passport(tmp_path)
        tampered = copy.deepcopy(raw)
        tampered["evidence"]["body"]["verdict"] = "covered"
        body = c.post("/v1/machinery/passport/check", json={"passport": tampered}).json()
        assert body["ok"] is False
        split = _node(
            "const m = await import('./app/lib/passportDoc.ts');"
            f"process.stdout.write(JSON.stringify(m.splitCheckFindings({json.dumps(body['problems'])})));")
        assert split["findings"], body
        assert not any(f.startswith("NOT CHECKED") for f in split["findings"])
        assert all(x.startswith("NOT CHECKED") for x in split["limitations"])
        assert len(split["findings"]) + len(split["limitations"]) == len(body["problems"])

    def test_the_assembled_passport_without_the_two_extra_keys_is_what_the_check_reads(self, client):
        c, store = client
        account = store.upsert_account(email="pp-cell@example.de", tier="cell")
        headers = {"X-API-Key": store.issue_key(account.id)}
        r = c.post("/v1/machinery/passport", headers=headers, json={
            "manifest": manifest("PP-0002", fw(), zones()).to_dict(),
            "actor": "Ada Integrator", "seal": False})
        assert r.status_code == 200, r.text
        built = r.json()
        assert built["sealed"] is False
        file = {k: v for k, v in built.items() if k not in ("sealed", "verdict")}
        chk = c.post("/v1/machinery/passport/check", json={"passport": file}).json()
        assert chk["ok"] is True and chk["recorded_verdict"] == built["verdict"]
        out = _read(file)
        assert out["ok"] and out["doc"]["verdict"] == built["verdict"]

    def test_the_assemble_route_is_401_without_a_key_and_402_when_unentitled(self, client):
        c, store = client
        body = {"manifest": manifest("PP-0003", fw(), zones()).to_dict(), "actor": "Ada Integrator", "seal": False}
        assert c.post("/v1/machinery/passport", json=body).status_code == 401
        account = store.upsert_account(email="pp-reg@example.de", tier="register")
        r = c.post("/v1/machinery/passport", json=body, headers={"X-API-Key": store.issue_key(account.id)})
        assert r.status_code == 402


class TestTheWordsAndDefaults:
    BANNED = re.compile(r"\b(verified|compliant|compliance|safe|certified|approved|passed|passes|trusted|valid)\b", re.I)

    def test_no_sentence_calls_a_machine_verified_compliant_or_safe(self):
        for path in (PANEL, VIEW):
            src = code(path).replace("never_verified", "")
            assert not self.BANNED.findall(src), (path.name, self.BANNED.findall(src))

    def test_no_invented_claims(self):
        for path in FILES:
            assert not re.search(r"\b(customer|pilot|revenue|production deployment)s?\b", code(path), re.I), path.name
            assert "github.com" not in text(path)

    def test_nothing_is_defaulted_to_zero_true_or_a_pass(self):
        for path in (VIEW, DOC):
            assert not re.search(r"\?\?\s*0\b|\|\|\s*0\b|\?\?\s*true|\|\|\s*true", code(path)), path.name

    def test_no_problem_found_is_only_drawn_from_an_ok_check_and_never_without_one(self):
        view = code(VIEW)
        assert view.count("no problem found") == 1
        assert re.search(r"const sound = check\.data\.ok;", view)
        assert re.search(r"check\?\.kind === 'ok' && check\.data\.ok", view)
        # no answer (null) and a refusal are `running` / `unchecked`, not a clean result
        assert "data-state=\"running\"" in view and "data-state=\"unchecked\"" in view
        assert "This is not a clean result" in view

    def test_the_signer_block_says_no_signature_and_declared_not_authenticated(self):
        view = code(VIEW)
        assert "A passport carries no signature field" in view
        assert "not authenticated" in view

    def test_no_signature_field_exists_in_a_real_passport(self, tmp_path):
        raw = _passport(tmp_path)
        flat = json.dumps(raw).lower()
        assert "signature" not in flat

    def test_the_panel_offers_no_download_or_print_the_api_does_not_provide(self):
        for path in (PANEL, VIEW):
            assert not re.search(r"download|window\.print|Blob\(|createObjectURL", code(path)), path.name

    def test_every_field_the_view_shows_is_one_the_domain_function_writes(self):
        record = text(ROOT / "src" / "assurance" / "machinery" / "record.py")
        for key in ("manifest_id", "manifest_hash", "configuration_hash", "verdict", "coverage_verdict",
                    "evidence_tier_floor", "functions", "intervention_ids", "verification_hashes",
                    "ledger_chain_verified", "ledger_head", "assessed_at", "checks_skipped"):
            assert f'"{key}"' in record or f"{key}=" in record, key
            assert key in text(DOC), key
