"""Every outcome the API can give a workspace screen has its own, honest rendering text.

``app/lib/assuranceApi.ts`` is pure, so node runs it directly. For each status the server can return
(and for no address, no answer and a broken ledger) the test classifies a realistic response and checks
the heading names that outcome, the server's own remedy text survives, and nothing reads as an empty or
successful result. The 401 text must not send a visitor to a checkout that does not exist.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCRIPT = """
const m = await import('./app/lib/assuranceApi.ts');
const cases = {
  unconfigured: { kind: 'unconfigured' },
  unreachable: { kind: 'unreachable', message: 'The API could not be reached from this browser.' },
  s401: m.classify(401, { detail: 'Invalid or revoked API key.' }),
  s402: m.classify(402, { detail: { error: 'plan_required', tier: 'register', account_status: 'active', remedy: 'Included from the Cell plan upward.' } }),
  s403: m.classify(403, { detail: { error: 'decider_role_required', detail: 'This key may not decide.', remedy: 'Use a decider operator.' } }),
  s404: m.classify(404, { detail: 'No such case.' }),
  s409: m.classify(409, { detail: 'Not ready to close.' }),
  s413: m.classify(413, { detail: 'Too big', limit_bytes: 1000 }),
  s422: m.classify(422, { detail: 'Unreadable manifest.' }),
  s429: m.classify(429, { detail: 'Allowance used.' }, '30'),
  s500: m.classify(500, { error: 'ledger_integrity', detail: 'chain broken at 4' }),
  s503: m.classify(503, { detail: 'down' }),
};
const out = {};
for (const [k, v] of Object.entries(cases)) out[k] = { kind: v.kind, ...m.describeOutcome(v) };
process.stdout.write(JSON.stringify(out));
"""


def _described() -> dict:
    node = shutil.which("node")
    assert node, "node is not installed"
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is a constant in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", SCRIPT],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_every_outcome_has_its_own_heading_and_none_reads_as_success_or_empty():
    out = _described()
    headings = [o["heading"] for o in out.values()]
    assert len(set(headings)) >= len(headings) - 1, headings  # 503 and unreachable-like generic errors may share
    for name, o in out.items():
        text = f"{o['heading']} {o['text']} {o['remedy']}".lower()
        assert o["heading"], name
        assert not any(w in text for w in ("no machines", "all clear", "verified ok", "covered")), name


def test_status_codes_are_named_in_the_heading():
    out = _described()
    for code in ("401", "402", "403", "404", "409", "413", "422", "429"):
        assert f"({code})" in out[f"s{code}"]["heading"], code
    assert "(500)" in out["s500"]["heading"] and "DOES NOT VERIFY" in out["s500"]["heading"]


def test_the_servers_remedy_text_is_passed_through():
    out = _described()
    assert "Included from the Cell plan upward." in out["s402"]["remedy"]
    assert "Use a decider operator." in out["s403"]["text"]
    assert "30" in out["s429"]["remedy"]


def test_unconfigured_and_unreachable_are_not_empty_results():
    out = _described()
    assert "NEXT_PUBLIC_ASSURANCE_API_URL" in out["unconfigured"]["text"]
    assert "not an empty result" in out["unreachable"]["remedy"]


def test_a_401_covers_revoked_keys_and_does_not_point_at_a_checkout_that_does_not_exist():
    remedy = _described()["s401"]["remedy"]
    assert "revoked or expired" in remedy
    assert "not available" in remedy and "checkout" in remedy
    assert "shown once, at checkout" not in remedy
