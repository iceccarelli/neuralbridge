"""The customer workspace is one app (the Next.js site); ``src/dashboard`` is gone and nothing dangles.

Source-level checks on ``app/**`` plus the pure helpers (``app/lib/credentials.ts``,
``workspaceIdentity.ts``, ``workspaceJourney.ts``), which are run under node type stripping with a fake
storage. They pin: credential handling (one list, cleared on sign-out, legacy copies deleted, never
rendered or logged or put in a URL), identity on every screen (account, plan, API origin, ledger),
demonstration data labelled, the journey table naming only things the capability catalogue has, the
platform panels calling exactly the documented routes, and that no fixed sample figure from the
retired dashboard survives. Browser behaviour is checked in a real browser, not here.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
COMP = APP / "components"


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def code(rel: str) -> str:
    """Source without comments, so an explanation may use any word."""
    src = re.sub(r"/\*.*?\*/", "", text(rel), flags=re.S)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("//"))


def node(script: str) -> object:
    exe = shutil.which("node")
    assert exe, "node is not installed"
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is built in this file
        [exe, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


FAKE_STORAGE = """
class Fake {
  constructor(init) { this.m = new Map(Object.entries(init)); }
  get length() { return this.m.size; }
  key(i) { return [...this.m.keys()][i] ?? null; }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
  dump() { return Object.fromEntries(this.m); }
}
"""


# ---------------------------------------------------------------------------
# 1. The retired dashboard is gone and nothing refers to it as if it existed
# ---------------------------------------------------------------------------
class TestDashboardRetired:
    def test_the_directory_is_gone(self):
        assert not (ROOT / "src" / "dashboard").exists()

    def test_nothing_that_builds_or_ships_still_names_it(self):
        for rel in ("Dockerfile", ".github/workflows/ci.yml", "tsconfig.json", ".gitignore", "package.json",
                    "vercel.json", "mkdocs.yml", ".dockerignore", "docker-compose.yml"):
            path = ROOT / rel
            if path.exists():
                body = path.read_text(encoding="utf-8")
                assert "src/dashboard" not in body.replace("former `src/dashboard`", ""), rel
        assert "dashboard-builder" not in text("Dockerfile")
        assert "node:" not in text("Dockerfile")
        ci = text(".github/workflows/ci.yml")
        assert not re.search(r"^  dashboard:", ci, re.M)

    def test_the_ci_site_job_is_still_there(self):
        ci = text(".github/workflows/ci.yml")
        assert re.search(r"^  site:", ci, re.M) and "npm ci" in ci

    def test_no_screen_shows_the_retired_fixed_figures(self):
        banned = ("12,847", "$2,340", "68%", "22 adapters", "Cost Savings", "Cache hit", "cache-hit", "CostOptimizer")
        for path in APP.rglob("*.ts*"):
            body = path.read_text(encoding="utf-8")
            for phrase in banned:
                assert phrase not in body, (path.relative_to(ROOT), phrase)

    def test_the_status_table_row_names_the_workspace_not_the_old_app(self):
        assert "Vite" not in text("app/lib/platformStatus.ts")
        assert "Customer workspace" in text("README.md")


# ---------------------------------------------------------------------------
# 2. Credentials: one list, cleared together, never shown
# ---------------------------------------------------------------------------
class TestCredentials:
    def test_sign_out_removes_every_credential_and_nothing_else(self):
        out = node(FAKE_STORAGE + """
import * as c from './app/lib/credentials.ts';
const s = new Fake({
  'nb-api-key': 'asr_secret', 'nb-console-api-key': 'old1', 'nb-ai-api-key': 'old2',
  'nb-assurance-decision-credential': 'asr_op', 'nb-ai-actor': 'operator-x', 'nb-ai-session': 'uuid',
  'nb-checkout-claim:cs_test_1': 'claim', 'nb-checkout-claim:cs_test_2': 'claim2', 'unrelated': 'keep',
});
const removed = c.clearCredentials(s);
console.log(JSON.stringify({ removed: removed.sort(), left: s.dump() }));
""")
        assert out["left"] == {"unrelated": "keep"}
        assert len(out["removed"]) == 8

    def test_a_legacy_key_is_adopted_once_and_every_legacy_copy_is_deleted(self):
        out = node(FAKE_STORAGE + """
import * as c from './app/lib/credentials.ts';
const a = new Fake({ 'nb-ai-api-key': 'asr_legacy' });
const adopted = c.readStoredKey(a);
const b = new Fake({ 'nb-api-key': 'asr_current', 'nb-console-api-key': 'asr_stale' });
const kept = c.readStoredKey(b);
console.log(JSON.stringify({ adopted, a: a.dump(), kept, b: b.dump() }));
""")
        assert out["adopted"] == "asr_legacy"
        assert out["a"] == {"nb-api-key": "asr_legacy"}
        assert out["kept"] == "asr_current"
        assert out["b"] == {"nb-api-key": "asr_current"}

    def test_blocked_storage_reads_as_empty_and_clears_without_throwing(self):
        out = node("""
import * as c from './app/lib/credentials.ts';
const boom = { get length() { throw new Error('blocked'); }, key() { throw new Error('blocked'); },
  getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); }, removeItem() { throw new Error('blocked'); } };
console.log(JSON.stringify({ read: c.readStoredKey(boom), cleared: c.clearCredentials(boom) }));
""")
        assert out == {"read": "", "cleared": []}

    def test_a_pasted_key_loses_its_whitespace_only(self):
        out = node("""
import { normaliseKey } from './app/lib/credentials.ts';
console.log(JSON.stringify([normaliseKey('  asr_abc\\n'), normaliseKey('asr_a b')]));
""")
        assert out == ["asr_abc", "asr_a b"]

    def test_the_hook_trims_stores_in_session_storage_only_and_signs_out(self):
        src = code("app/lib/apiKey.ts")
        assert "normaliseKey(raw)" in src
        assert "localStorage" not in src
        assert "export function signOut" in src and "clearCredentials(window.sessionStorage)" in src
        assert "CREDENTIALS_CLEARED_EVENT" in src

    def test_every_holder_of_a_credential_listens_for_sign_out(self):
        for rel in ("app/lib/apiKey.ts", "app/components/assurance/DecisionCredential.tsx",
                    "app/components/AiWorkspace.tsx", "app/components/Console.tsx"):
            assert "CREDENTIALS_CLEARED_EVENT" in text(rel), rel

    def test_the_decision_credential_uses_the_shared_constant(self):
        assert "DECISION_CREDENTIAL_STORAGE" in text("app/components/assurance/DecisionCredential.tsx")

    def test_a_key_is_never_rendered_logged_or_put_in_a_url(self):
        for path in sorted(list(COMP.rglob("*.tsx")) + list((APP / "checkout").rglob("*.tsx"))):
            body = code(str(path.relative_to(ROOT)))
            rel = path.relative_to(ROOT)
            assert not re.search(r"console\.(log|info|warn|error|debug)\s*\(", body), rel
            assert not re.search(r"[?&](?:api_?key|key|token)=\$\{", body, re.I), rel
            # The key is a control's value (a password field) or a prop handed to a child; it is never
            # interpolated into visible text or into a template string (a URL, a message).
            assert not re.search(r">\s*\{\s*(?:apiKey|opKey|key|password)\s*\}", body), rel
            assert not re.search(r"\$\{\s*(?:apiKey|opKey|password)\s*\}", body), rel

    def test_the_key_inputs_are_password_fields(self):
        for rel in ("app/components/AiWorkspace.tsx", "app/components/Console.tsx", "app/components/AssuranceWorkspace.tsx"):
            body = text(rel)
            assert re.search(r'type="password"', body), rel
        assert 'type="password"' in text("app/components/ai/ConnectionsPanel.tsx")

    def test_a_database_password_is_dropped_whether_or_not_the_call_succeeded(self):
        body = code("app/components/ai/ConnectionsPanel.tsx")
        call = body.index("'/ai/connections', {")
        clear = body.index("setPassword('')", call)
        branch = body.index("if (out.kind === 'ok')", call)
        assert call < clear < branch, "the password must be cleared before the outcome is looked at"
        assert 'autoComplete="new-password"' in body

    def test_the_workspace_never_sends_a_key_to_a_public_feed(self):
        assert "Never sends a key" in text("app/lib/assuranceApi.ts")


# ---------------------------------------------------------------------------
# 3. Identity: account, plan, API origin, ledger; demonstration data labelled
# ---------------------------------------------------------------------------
class TestIdentity:
    def test_describe_origin(self):
        out = node("""
import { describeOrigin as d } from './app/lib/workspaceIdentity.ts';
const pick = (x) => ({ c: x.configured, o: x.origin, e: x.environment, t: x.keyTransport });
console.log(JSON.stringify([
  pick(d('https://api.example.com/', 'S')), pick(d('http://127.0.0.1:8001', 'S')),
  pick(d('http://api.example.com', 'S')), pick(d('', 'S')), pick(d('not a url', 'S')), pick(d('ftp://x', 'S')),
  pick(d('http://localhost:3000/x?y=1', 'S')),
]));
""")
        assert out == [
            {"c": True, "o": "https://api.example.com", "e": "hosted", "t": "encrypted"},
            {"c": True, "o": "http://127.0.0.1:8001", "e": "local", "t": "local"},
            {"c": True, "o": "http://api.example.com", "e": "hosted", "t": "cleartext"},
            {"c": False, "o": "", "e": "unconfigured", "t": "none"},
            {"c": False, "o": "", "e": "unconfigured", "t": "none"},
            {"c": False, "o": "", "e": "unconfigured", "t": "none"},
            {"c": True, "o": "http://localhost:3000", "e": "local", "t": "local"},
        ]

    def test_identity_from_me_never_invents_an_account(self):
        out = node("""
import { identityFromMe as f } from './app/lib/workspaceIdentity.ts';
const acct = { authenticated: true, tier: 'cell', plan: { name: 'Cell', tier: 'cell' },
  account: { id: 'acc_1', company: 'Acme GmbH', email: 'ops@acme.example', status: 'active', source: 'stripe' } };
const op = { authenticated: true, tier: 'cell', plan: { name: 'Cell', tier: 'cell' }, account: { id: 'operator', company: 'Op', email: '', status: 'active' } };
const anon = { authenticated: false, tier: 'free', plan: { name: 'Validator', tier: 'free' } };
console.log(JSON.stringify([f(null), f(anon), f(acct), f(op)]));
""")
        unknown, anon, acct, op = out
        assert unknown["state"] == "unknown" and "not" in unknown["ledger"]
        assert anon["state"] == "anonymous" and anon["tier"] == "free" and "none" in anon["ledger"]
        assert acct["state"] == "account" and "Acme GmbH" in acct["accountLabel"] and acct["ledger"] == "your account's own ledger"
        assert op["isOperator"] is True and "operator" in op["ledger"] and "not a customer ledger" in op["ledger"]

    def test_every_workspace_screen_mounts_the_identity_bar_and_the_journey(self):
        for rel in ("app/components/AssuranceWorkspace.tsx", "app/components/Console.tsx", "app/components/AiWorkspace.tsx"):
            body = text(rel)
            assert "<WorkspaceHeader" in body and "<JourneyNav" in body, rel

    def test_the_identity_bar_states_account_plan_origin_environment_and_records(self):
        body = text("app/components/assurance/WorkspaceHeader.tsx")
        for label in ("Account", "Plan", "API origin", "Environment", "Records shown"):
            assert f'label="{label}"' in body, label
        assert "Sign out of this tab" in body

    def test_the_ai_screen_does_not_claim_an_account_it_was_not_told(self):
        body = text("app/components/assurance/WorkspaceHeader.tsx")
        assert "not reported by this API" in body

    def test_demonstration_and_sample_data_is_labelled_where_it_appears(self):
        assert "DemoLabel" in text("app/components/FirstCell.tsx") and "Sample data" in text("app/components/FirstCell.tsx")
        ai = text("app/components/AiWorkspace.tsx")
        assert "isDemoSource(selected)" in ai and "Demonstration data" in ai
        assert "demoIds.includes(card.provenance.connection_id)" in ai
        assert "seeded_from_env" in text("app/components/ai/ConnectionsPanel.tsx")

    def test_the_new_labels_do_not_collide_with_the_stable_ones_the_e2e_specs_use(self):
        """getByLabel is a substring match: a second control named like 'API key', 'Connection' or
        'Message' on /ai or /console would make the existing specs ambiguous."""
        files = [*(COMP / "ai").glob("*.tsx"), COMP / "assurance" / "WorkspaceHeader.tsx",
                 COMP / "assurance" / "JourneyNav.tsx", COMP / "assurance" / "RegisterPanel.tsx"]
        for path in files:
            body = path.read_text(encoding="utf-8")
            names = re.findall(r"aria-label=\"([^\"]+)\"", body) + re.findall(r"<label[^>]*>([^<]+)</label>", body)
            names += re.findall(r"aria-labelledby=\"([^\"]+)\"", body)
            for name in names:
                assert not re.search(r"api key|connection|message", name, re.I), (path.name, name)


# ---------------------------------------------------------------------------
# 4. The journey names only what the product has
# ---------------------------------------------------------------------------
class TestJourney:
    CAPS = json.loads((ROOT / "public" / "capabilities.json").read_text(encoding="utf-8"))["capabilities"]

    def _routes_and_verbs(self):
        routes, verbs = set(), set()
        for c in self.CAPS:
            routes.update(c["surfaces"]["api"].get("names") or [])
            verbs.update(c["surfaces"]["cli"].get("names") or [])
        return routes, verbs

    def _journey(self):
        return node("""
import { JOURNEY, availability } from './app/lib/workspaceJourney.ts';
console.log(JSON.stringify({ steps: JOURNEY, a: JOURNEY.map(s => [availability(s, true), availability(s, false)]) }));
""")

    def test_the_seven_steps_are_in_the_customer_order(self):
        steps = self._journey()["steps"]
        assert [s["id"] for s in steps] == ["enrol", "collect", "verify", "advisory", "decision", "reverify", "passport"]

    def test_every_hosted_route_and_offline_verb_exists_in_the_capability_catalogue(self):
        routes, verbs = self._routes_and_verbs()
        for step in self._journey()["steps"]:
            for route in step["hosted"]:
                assert route in routes, (step["id"], route)
            for verb in step["offline"]:
                assert verb in verbs, (step["id"], verb)

    def test_availability_is_honest_about_hosting(self):
        out = self._journey()
        by_id = {s["id"]: a for s, a in zip(out["steps"], out["a"], strict=True)}
        assert by_id["collect"] == ["offline_only", "offline_only"], "the hosted service does not collect"
        for step in ("enrol", "verify", "advisory", "decision", "reverify", "passport"):
            assert by_id[step] == ["hosted", "offline_only"], step

    def test_the_decision_step_says_software_never_decides(self):
        step = next(s for s in self._journey()["steps"] if s["id"] == "decision")
        assert "never decides" in step["hostedNote"] and "named" in step["actor"].lower()

    def test_the_links_point_at_panels_that_exist(self):
        ids = set()
        for path in (COMP / "assurance").glob("*.tsx"):
            ids.update(re.findall(r'id="(aw-[a-z-]+)"', path.read_text(encoding="utf-8")))
        ids.add("aw-fleet")
        for step in self._journey()["steps"]:
            if step["href"]:
                assert step["href"].startswith("/assurance#"), step
                assert step["href"].split("#")[1] in ids, step

    def test_the_journey_never_says_a_thing_is_compliant_or_safe(self):
        body = text("app/lib/workspaceJourney.ts") + text("app/components/assurance/JourneyNav.tsx")
        assert not re.search(r"\b(compliant|certified|guarantee[sd]?|is safe|proves? safe)\b", body, re.I)


# ---------------------------------------------------------------------------
# 5. The platform panels call exactly the documented routes, and every state is drawn
# ---------------------------------------------------------------------------
class TestPlatformPanels:
    def test_the_routes_exist_in_the_platform_api(self):
        adapters = text("src/neuralbridge/api/routes/adapters.py")
        logs = text("src/neuralbridge/api/routes/logs.py")
        ai = text("src/neuralbridge/api/routes/ai.py")
        assert '@router.get("", summary="List registered adapters")' in adapters
        assert '@router.get("", summary="Query audit logs")' in logs
        assert '@router.post("/connections"' in ai and '@router.delete("/connections/{connection_id}"' in ai
        assert "/adapters" in code("app/components/ai/AdaptersPanel.tsx")
        assert "`/logs?" in code("app/components/ai/AuditPanel.tsx")
        panel = code("app/components/ai/ConnectionsPanel.tsx")
        assert "'/ai/connections'" in panel and "method: 'DELETE'" in panel and "method: 'POST'" in panel

    def test_the_audit_query_uses_only_parameters_the_route_accepts(self):
        logs = text("src/neuralbridge/api/routes/logs.py")
        for param in ("event_type", "actor", "start_date", "end_date", "limit", "offset"):
            assert re.search(rf"\b{param}\b.*=\s*Query", logs), param
            assert param in text("app/components/ai/AuditPanel.tsx"), param

    def test_the_bind_form_sends_exactly_the_fields_the_route_takes(self):
        ai = text("src/neuralbridge/api/routes/ai.py")
        model = re.search(r"class BindConnectionRequest\(BaseModel\):(.*?)\n\n\n", ai, re.S).group(1)
        fields = set(re.findall(r"^\s{4}(\w+):", model, re.M))
        sent = set(re.findall(r"\b(name|host|port|user|password|database|ssl_mode)\b(?=[:,])", code("app/components/ai/ConnectionsPanel.tsx").split("body: {")[1].split("});")[0]))
        assert fields == {"name", "host", "port", "user", "password", "database", "ssl_mode"}
        assert sent == fields

    def test_nothing_calls_the_operator_only_connection_store_or_the_withdrawn_compliance_routes(self):
        for path in sorted(list(COMP.rglob("*.tsx")) + list(APP.rglob("page.tsx"))):
            body = code(str(path.relative_to(ROOT)))
            assert not re.search(r"['`\"]/connections[/'`\"?]", body), path.name
            assert "/compliance/" not in body, path.name
            assert "latency_ms" not in body, path.name

    def test_each_panel_draws_its_states(self):
        frame = text("app/components/assurance/PanelFrame.tsx")
        for state in ("Skeleton", "Refusal", "Showing the last data received", "Not loaded: paste an API key above"):
            assert state in frame, state
        assert "<Skeleton" in frame and "unconfigured" in frame
        for rel in ("app/components/ai/AdaptersPanel.tsx", "app/components/ai/AuditPanel.tsx", "app/components/assurance/RegisterPanel.tsx"):
            body = text(rel)
            assert "PanelFrame" in body and "console-empty-note" in body, rel
        assert "adapters-empty" in text("app/components/ai/AdaptersPanel.tsx")
        assert "audit-empty" in text("app/components/ai/AuditPanel.tsx")
        assert "register-empty" in text("app/components/assurance/RegisterPanel.tsx")

    def test_an_answer_that_arrived_is_not_reported_as_unreachable(self):
        ai = text("app/components/AiWorkspace.tsx")
        assert "HTTP 401" in ai and "HTTP 402" in ai and "HTTP 403" in ai
        # Every fetch chain in the workspace has a catch: an unreachable API must not become an unhandled rejection.
        assert ai.count(".catch(") >= 4

    def test_the_register_view_records_nothing_and_says_the_platform_verifies_nothing(self):
        body = text("app/components/assurance/RegisterPanel.tsx")
        assert "method:" not in body and "POST" not in code("app/components/assurance/RegisterPanel.tsx")
        assert "not verified by the platform" in body and "declarations by named people" in body
        assert "/v1/register" in body

    def test_the_register_is_read_on_request_so_a_plan_refusal_is_met_when_asked(self):
        body = text("app/components/assurance/RegisterPanel.tsx")
        assert "register-load" in body and "useState(false)" in body

    def test_the_audit_log_says_where_the_trail_lives(self):
        body = text("app/components/ai/AuditPanel.tsx")
        assert "lives in the API process" in body and "does not re-verify" in body


# ---------------------------------------------------------------------------
# 6. Accessibility basics in the new components
# ---------------------------------------------------------------------------
class TestAccessibility:
    NEW = [*(COMP / "ai").glob("*.tsx"), COMP / "assurance" / "WorkspaceHeader.tsx",
           COMP / "assurance" / "JourneyNav.tsx", COMP / "assurance" / "RegisterPanel.tsx"]

    def test_every_form_control_has_a_label(self):
        for path in self.NEW:
            body = code(str(path.relative_to(ROOT)))
            for m in re.finditer(r"<(?:input|select)\b", body):
                attrs = body[m.end(): m.end() + 400]
                ident = re.search(r'\bid="([^"]+)"', attrs)
                assert ident, (path.name, attrs[:60])
                assert f'htmlFor="{ident.group(1)}"' in body, (path.name, ident.group(1))

    def test_tables_have_captions_and_scoped_headers(self):
        for path in self.NEW:
            body = path.read_text(encoding="utf-8")
            if "<table" in body:
                assert "<caption" in body, path.name
                assert 'scope="col"' in body, path.name

    def test_status_regions_are_announced(self):
        assert 'role="status"' in text("app/components/assurance/WorkspaceHeader.tsx")
        assert 'aria-label="Customer journey"' in text("app/components/assurance/JourneyNav.tsx")

    def test_no_horizontal_page_scroll_from_tables(self):
        css = text("app/components/assurance/workspace.module.css")
        assert "overflow-x: auto" in css and "overflow-wrap: anywhere" in css
        assert "focus-visible" in css


@pytest.mark.parametrize("rel", ["app/ai/page.tsx", "app/console/page.tsx", "app/assurance/page.tsx"])
def test_the_workspace_pages_still_exist(rel):
    assert (ROOT / rel).is_file()


def test_workspace_buttons_are_not_white_on_the_light_page():
    """.btn-outline is white text for dark bands; on the workspace's light surface it is invisible."""
    for path in sorted([*(COMP / "assurance").glob("*.tsx"), *(COMP / "ai").glob("*.tsx")]):
        assert "btn-outline" not in path.read_text(encoding="utf-8"), path.name
