"""The /assurance "Ledger verify" panel: what it calls, and that it never turns an unchecked,
unanchored or incomplete answer into a pass.

Two kinds of check. Source-level (the repo's pattern for the site: read ``app/**``), and a contract
check that takes REAL ``GET /v1/ledger/verify`` answers from the API (real keys, real per-account
ledgers, throwaway data) and runs them through the page's own ``judge()`` with node type stripping.
The browser behaviour is ``tests-e2e/assurance-ledger-verify.spec.ts``.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

from assurance.api import deps
from assurance.capabilities import CAPABILITIES

from .test_assurance_export_api import _account, _read_sign, _signal, api  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / "app" / "components" / "assurance"
PANEL = COMP / "LedgerVerifyPanel.tsx"
VIEW = COMP / "LedgerVerifyView.tsx"
LIB = ROOT / "app" / "lib" / "ledgerVerifyApi.ts"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code(path: Path) -> str:
    src = re.sub(r"/\*.*?\*/", "", text(path), flags=re.S)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("//"))


def _judge(payloads: list) -> list[dict]:
    node = shutil.which("node")
    assert node, "node is not installed"
    script = (
        "import {judge} from './app/lib/ledgerVerifyApi.ts';"
        f"const xs = {json.dumps(payloads)};"
        "console.log(JSON.stringify(xs.map(judge)));"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is built in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _one(payload) -> dict:
    return _judge([payload])[0]


# --------------------------------------------------------------------------- wiring
class TestWiring:
    def test_files_exist_and_the_workspace_mounts_the_panel_with_the_key_and_me(self):
        for p in (PANEL, VIEW, LIB):
            assert p.is_file(), p
        ws = text(ROOT / "app" / "components" / "AssuranceWorkspace.tsx")
        assert re.search(r"<LedgerVerifyPanel apiKey=\{key\} me=\{me\} />", ws)
        assert "import LedgerVerifyPanel" in ws

    def test_the_panel_gets_exactly_the_documented_route_and_that_route_exists(self):
        assert "'/v1/ledger/verify'" in code(LIB)
        assert "usePanel<LedgerVerifyResponse>(apiKey, LEDGER_VERIFY_PATH)" in code(PANEL)
        assert "GET /v1/ledger/verify" in {r for c in CAPABILITIES for r in c.api}
        assert "get" in json.loads((ROOT / "public" / "openapi.json").read_text())["paths"]["/v1/ledger/verify"]

    def test_it_stores_nothing_and_sends_no_request_of_its_own(self):
        for p in (PANEL, VIEW, LIB):
            src = code(p)
            assert not re.search(r"localStorage|sessionStorage|document\.cookie|console\.|fetch\(", src), p.name
            assert not re.search(r"[?&]key=|api_key=", src), p.name

    def test_it_is_read_only(self):
        for p in (PANEL, VIEW, LIB):
            assert not re.search(r"method:\s*'(POST|PUT|PATCH|DELETE)'|<button|onSubmit", code(p)), p.name

    def test_every_field_the_view_reads_is_one_the_server_sends(self, api):  # noqa: F811
        _acct, headers = _account("fields@example.de")
        _signal(api, headers, "C0")
        body = api.get("/v1/ledger/verify", headers=headers).json()
        for key in ("verified", "problems", "completeness", "not_checked", "ledger_id", "anchor",
                    "anchor_meaning", "attestation", "note"):
            assert key in body, key
        for key in ("length", "head_link_hash"):
            assert key in body["attestation"], key
        _read_sign(_acct)
        anchor = api.get("/v1/ledger/verify", headers=headers).json()["anchor"]
        for key in ("sequence", "attested_at", "ledger_length", "head_link_hash", "key_fingerprint", "basis"):
            assert key in anchor, key
            if key not in ("sequence",):  # the sequence number is not shown; the rest are
                assert re.search(rf"\ba\??\.{key}\b", code(VIEW)), key


# --------------------------------------------------------------------------- no false pass
class TestNoFalsePass:
    def test_no_wording_of_a_pass_anywhere(self):
        for p in (VIEW, LIB, PANEL):
            src = code(p)
            assert not re.search(r"\b(passed|passes|compliant|certified|approved|all clear|tamper[- ]proof)\b", src, re.I), p.name
        # The state words are the four the brief names, and each has its own heading text.
        view = code(VIEW)
        for state in ("complete", "incomplete", "unanchored", "unchecked"):
            assert re.search(rf"^\s*{state}:", view, re.M), state

    def test_only_incomplete_and_broken_are_styled_as_bad_and_no_state_is_styled_as_good(self):
        view = code(VIEW)
        assert "aw-ok" not in view and "aw-good" not in view and "aw-pass" not in view
        assert "v.completeness === 'incomplete' ? 'aw-bad'" in view
        assert "v.chain === 'broken' ? 'aw-bad'" in view

    def test_truncation_is_a_role_alert(self):
        view = code(VIEW)
        assert re.search(r"v\.completeness === 'incomplete' \|\| v\.chain === 'broken'", view)
        assert 'role="alert"' in view and 'data-testid="lv-alert"' in view

    def test_the_servers_own_not_established_text_and_anchor_meaning_are_rendered(self):
        view = code(VIEW)
        assert "data.not_checked" in view and "data.anchor_meaning" in view and "data.problems" in view

    def test_the_complete_state_says_what_it_does_not_cover(self):
        view = text(VIEW)
        assert "Records added after that head are not covered by it" in view
        assert "uncoveredAfterAnchor" in view

    def test_the_unanchored_text_says_it_is_not_a_pass(self):
        assert "This is not a pass" in text(VIEW)


class TestJudgeMatrix:
    BASE = {"verified": True, "problems": [], "completeness": "not_checked", "not_checked": [],
            "ledger_id": "L", "anchor": None, "anchor_meaning": "m",
            "attestation": {"length": 3, "head_seq": 3, "head_link_hash": "h", "attested_at": "t"}}
    ANCHOR = {"sequence": 1, "attested_at": "t", "ledger_length": 3, "head_seq": 3,
              "head_link_hash": "h", "key_fingerprint": "fp", "basis": "read_from_ledger"}

    def d(self, **kw):
        return {**self.BASE, **kw}

    def test_checked_against_anchor_is_complete_and_counts_uncovered_records(self):
        r = _one(self.d(completeness="checked_against_anchor", anchor={**self.ANCHOR, "ledger_length": 2}))
        assert r == {"chain": "intact", "completeness": "complete", "inconsistency": "", "uncoveredAfterAnchor": 1}

    def test_contradicted_is_incomplete_even_when_the_chain_links(self):
        r = _one(self.d(completeness="contradicted_by_anchor", verified=True, anchor=self.ANCHOR))
        assert r["completeness"] == "incomplete"

    def test_contradicted_is_incomplete_when_the_chain_is_broken_too(self):
        r = _one(self.d(completeness="contradicted_by_anchor", verified=False, problems=["x"], anchor=self.ANCHOR))
        assert (r["chain"], r["completeness"]) == ("broken", "incomplete")

    def test_not_checked_without_an_anchor_is_unanchored_never_complete(self):
        r = _one(self.d())
        assert (r["chain"], r["completeness"]) == ("intact", "unanchored")

    def test_a_broken_chain_is_not_complete_and_completeness_is_unchecked(self):
        r = _one(self.d(verified=False, problems=["seq 2 bad"]))
        assert (r["chain"], r["completeness"]) == ("broken", "unchecked")

    def test_verified_true_with_problems_listed_is_not_trusted(self):
        r = _one(self.d(verified=True, problems=["seq 2 bad"], completeness="checked_against_anchor", anchor=self.ANCHOR))
        assert r["chain"] == "broken" and r["completeness"] != "complete"

    def test_a_checked_claim_without_a_named_anchor_is_unchecked(self):
        for anchor in (None, {**self.ANCHOR, "key_fingerprint": ""}, {k: v for k, v in self.ANCHOR.items() if k != "ledger_length"}):
            r = _one(self.d(completeness="checked_against_anchor", anchor=anchor))
            assert r["completeness"] == "unchecked" and r["inconsistency"], anchor

    def test_a_ledger_shorter_than_its_anchor_but_not_contradicted_is_unchecked(self):
        r = _one(self.d(completeness="checked_against_anchor", anchor={**self.ANCHOR, "ledger_length": 9}))
        assert r["completeness"] == "unchecked"

    def test_anchor_named_but_not_compared_is_unchecked(self):
        assert _one(self.d(anchor=self.ANCHOR))["completeness"] == "unchecked"

    def test_unknown_completeness_value_and_malformed_answers_are_unchecked(self):
        assert _one(self.d(completeness="verified"))["completeness"] == "unchecked"
        for bad in (None, {}, {"verified": True}, {**self.BASE, "problems": "none"}, {**self.BASE, "completeness": 1}):
            r = _one(bad)
            assert (r["chain"], r["completeness"]) == ("unknown", "unchecked"), bad


# --------------------------------------------------------------------------- real API answers
def _cut(account, keep):
    db = sqlite3.connect(deps.tenant_ledger_path(account.id))
    db.execute("DELETE FROM chain WHERE seq > ?", (keep,))
    db.commit()
    db.close()


class TestRealServerAnswers:
    def _get(self, api, headers):  # noqa: F811
        r = api.get("/v1/ledger/verify", headers=headers)
        assert r.status_code == 200, r.text
        return r.json()

    def test_each_real_state_is_judged_as_its_own_state(self, api):  # noqa: F811
        # unanchored: a fresh ledger nobody counter-signed
        acct_a, ha = _account("a@example.de")
        for i in range(3):
            _signal(api, ha, f"C{i}")
        unanchored = self._get(api, ha)
        # complete: counter-signed head, then one more record after it
        acct_b, hb = _account("b@example.de")
        for i in range(3):
            _signal(api, hb, f"C{i}")
        _read_sign(acct_b)
        complete = self._get(api, hb)
        _signal(api, hb, "LATER")
        complete_later = self._get(api, hb)
        # incomplete: counter-signed head, then truncated past it
        acct_c, hc = _account("c@example.de")
        for i in range(3):
            _signal(api, hc, f"C{i}")
        _read_sign(acct_c)
        _cut(acct_c, 1)
        truncated = self._get(api, hc)

        got = _judge([unanchored, complete, complete_later, truncated])
        assert [g["completeness"] for g in got] == ["unanchored", "complete", "complete", "incomplete"]
        assert got[1]["uncoveredAfterAnchor"] == 0 and got[2]["uncoveredAfterAnchor"] == 1
        assert got[3]["chain"] == "broken" or truncated["verified"] is False
        # The server's own words reach the view unchanged: it has them to show.
        assert truncated["problems"] and truncated["anchor"]["key_fingerprint"]

    def test_a_service_without_a_signing_key_is_unanchored_not_complete(self, api, monkeypatch):  # noqa: F811
        acct, headers = _account("nokey@example.de")
        _signal(api, headers, "C0")
        _read_sign(acct)
        monkeypatch.delenv("ASSURANCE_ATTEST_KEY")
        body = self._get(api, headers)
        assert _one(body)["completeness"] == "unanchored"

    def test_refusals_go_through_the_shared_frame_which_shows_them_as_refusals(self):
        # 401/402 are enforced and tested server-side (tests/test_assurance_verify_anchor.py,
        # tests/test_assurance_entitlements.py); the panel must not render data it was refused.
        assert "<PanelFrame" in code(PANEL) and "{(data) =>" in code(PANEL)
