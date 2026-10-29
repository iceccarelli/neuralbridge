"""One catalogue of everything this product can do, and where you can do it.

The same capability is reachable from the command line, the HTTP API and the MCP server, and the
website sells it. Those surfaces drifted before: a verifier existed on the API and not on MCP, a
route was added and the site page was not. This module is the single place where the pairing is
*declared*, and it is checked against the real surfaces so a declaration cannot go stale:

* every CLI command, API route and MCP tool that exists must belong to a capability;
* every surface a capability claims must exist;
* every surface a capability lacks must say why it lacks it, as one of two things:
  ``by_design`` (a human decision, offline by design, key custody, the account plane ...) or
  ``planned`` (a known gap that should be closed, not hidden).

What this does and does not establish. ``present`` means the command, route or tool exists in
this build. It does not say the three do exactly the same thing: that the CLI ``machinery
coverage`` and ``POST /v1/machinery/coverage`` are the *same* capability is a declaration a
person made and a reviewer can disagree with. The catalogue is generated, never hand-copied into
documentation, so what it states about a surface cannot outlive that surface.
"""

from __future__ import annotations

import argparse
import importlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["BY_DESIGN", "CAPABILITIES", "PLANNED", "SCHEMA", "Capability", "catalogue",
           "discover", "problems"]

SCHEMA = "assurance.capabilities/1"
SURFACES = ("cli", "api", "mcp")

#: Why a surface is missing. ``by_design`` is a decision; ``planned`` is a debt that is shown.
BY_DESIGN = "by_design"
PLANNED = "planned"


@dataclass(frozen=True)
class Capability:
    id: str
    summary: str
    cli: tuple[str, ...] = ()
    api: tuple[str, ...] = ()
    mcp: tuple[str, ...] = ()
    #: surface -> (BY_DESIGN | PLANNED, reason). Required for every surface left empty.
    gaps: dict[str, tuple[str, str]] = field(default_factory=dict)

    @property
    def service(self) -> str:
        return self.id.split(".", 1)[0]

    def claims(self, surface: str) -> tuple[str, ...]:
        return getattr(self, surface)


def _t(v: str | tuple[str, ...]) -> tuple[str, ...]:
    return (v,) if isinstance(v, str) else tuple(v)


def _c(id: str, summary: str, cli: str | tuple[str, ...] = (), api: str | tuple[str, ...] = (),
       mcp: str | tuple[str, ...] = (), gaps: dict[str, tuple[str, str]] | None = None
       ) -> Capability:
    return Capability(id, summary, _t(cli), _t(api), _t(mcp), dict(gaps or {}))


def _d(reason: str) -> tuple[str, str]:
    return (BY_DESIGN, reason)


def _p(reason: str) -> tuple[str, str]:
    return (PLANNED, reason)


_HUMAN = ("a named person's act, so no agent surface (the Article 14 track, a case closure and "
          "a case opened from third-party content are human decisions; software drafts)")
_WRITE = "writes the ledger of record; an agent is not offered a way to seal records"
_OFFLINE = "runs on the customer's own machine and opens no socket; there is no hosted equivalent"
_ACCOUNT = "the account plane (billing, keys, operators); not an assurance capability to automate"
_OPERATOR = ("operator tooling that works on the local account store file on the host; it opens no "
             "socket and is not an HTTP route")
_KEYS = "key custody: the private key is made and held on the operator's own machine"
_HTTP = "served over HTTP to callers who hold no checkout; the CLI works on local files"
_NO_MCP_YET = "no MCP tool yet; a read or verify that an agent could use"

CAPABILITIES: tuple[Capability, ...] = (
    # --- Article 14: CRA vulnerability and incident reporting ---------------------------------
    _c("art14.signal", "Open a case with the first thing anyone heard",
       "art14 signal", "POST /v1/cases/{case_id}/signal", gaps={"mcp": _d(_HUMAN)}),
    _c("art14.awareness", "Establish the moment every deadline runs from",
       "art14 awareness", "POST /v1/cases/{case_id}/awareness", gaps={"mcp": _d(_HUMAN)}),
    _c("art14.triage", "Work the reportability decision path",
       "art14 triage", "POST /v1/cases/{case_id}/triage", gaps={"mcp": _d(_HUMAN)}),
    _c("art14.availability", "Attach the product and Member State record the filing needs",
       "art14 availability", "POST /v1/cases/{case_id}/availability", gaps={"mcp": _d(_HUMAN)}),
    _c("art14.measure", "Record a corrective or mitigating measure becoming available",
       "art14 measure", "POST /v1/cases/{case_id}/measure", gaps={"mcp": _d(_HUMAN)}),
    _c("art14.filing", "Record a submission, validated against the platform field spec",
       "art14 file", "POST /v1/cases/{case_id}/filings", gaps={"mcp": _d(_HUMAN)}),
    _c("art14.user_notification", "Record the Article 14(8) notification to users",
       "art14 notify-users", "POST /v1/cases/{case_id}/user-notification",
       gaps={"mcp": _d(_HUMAN)}),
    _c("art14.validate", "Check a draft submission without recording it",
       "art14 validate", "POST /v1/spec/validate", "spec_validate"),
    _c("art14.fields", "The platform field specification for a track and stage",
       "art14 fields", "GET /v1/spec/fields", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("art14.case", "One case, with its deadlines",
       "art14 case", "GET /v1/cases/{case_id}", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("art14.case_ids", "List case ids", (), "GET /v1/cases", "register_cases",
       gaps={"cli": _d("`art14 register` shows every case, worst first, and is the CLI view")}),
    _c("art14.register", "Readiness across every case, worst first",
       "art14 register", "GET /v1/register", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("art14.breaches", "Deadlines missed or overdue (the CLI exits 1 on any)",
       "art14 register", "GET /v1/register/breaches", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("art14.export", "A verifiable evidence bundle for one case",
       "art14 export", "GET /v1/cases/{case_id}/export", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("art14.bridge", "Draft an Article 14 intake from an advisory",
       "bridge art14", gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),

    # --- evidence: the ledger, its verification and its attestations --------------------------
    _c("evidence.ledger_verify", "Verify the evidence chain",
       "art14 verify", "GET /v1/ledger/verify", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("evidence.verify", "Check an evidence file you were handed; stores nothing",
       "evidence verify", "POST /v1/evidence/verify", "evidence_verify"),
    _c("attest.keygen", "Make an Ed25519 key pair", "attest keygen",
       gaps={"api": _d(_KEYS), "mcp": _d(_KEYS)}),
    _c("attest.sign", "Attest the current head of a ledger",
       "attest sign", "POST /v1/ledger/attest",
       gaps={"mcp": _d("a signature is a named operator's act; the signing key is not an agent's")}),
    _c("attest.verify", "Check an attestation log",
       "attest verify", "POST /v1/ledger/attest/verify", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("attest.log", "Print the attestations, checking nothing",
       "attest log", "GET /v1/ledger/attest/log", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("attest.service_key", "The public key the hosted service counter-signs with",
       (), "GET /v1/ledger/attest/key",
       gaps={"cli": _d(_HTTP), "mcp": _p(_NO_MCP_YET)}),

    # --- machine: verifying a recorded run against a declared envelope ----------------------
    _c("machine.separation", "The protective separation distance, term by term",
       "machine separation", "POST /v1/machine/separation", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("machine.verify", "Verify a recorded run against a declared safety envelope",
       "machine verify", "POST /v1/machine/verify", "machine_verify"),
    _c("machine.check", "Re-verify a verification bundle somebody else sealed",
       "machine check", "POST /v1/machine/bundle/check", "machine_check"),
    _c("machine.recorder_sign", "Sign a trace as a recorder attestation",
       "machine recorder-sign", gaps={"api": _d(_KEYS), "mcp": _d(_KEYS)}),
    _c("machine.recorder_trust", "Add a recorder's PUBLIC key to your own trust file",
       "machine recorder-trust",
       gaps={"api": _d("trust is the verifier's own configuration; a request cannot supply it"),
             "mcp": _d("trust is the verifier's own configuration; a tool cannot supply it")}),
    _c("check.services", "The Machine Assurance Check service catalogue, machine-readable",
       (), "GET /v1/check/services", "services", gaps={"cli": _p("no CLI verb")}),
    _c("check.machine", "Ad-hoc check: one manifest, one advisory, no account",
       (), "POST /v1/check/machine", "machine_assurance_check", gaps={"cli": _p("no CLI verb")}),
    _c("check.fleet_machine", "Check an enrolled machine against its own ledger history",
       (), "POST /v1/check/fleet-machine", "fleet_machine_assurance",
       gaps={"cli": _p("no CLI verb")}),

    # --- machinery: the machine's software identity and its change history ------------------
    _c("machinery.manifest", "Seal a safety software manifest",
       "machinery record-manifest", "POST /v1/machinery/manifest", gaps={"mcp": _d(_WRITE)}),
    _c("machinery.intervention", "Seal an intervention record",
       "machinery record-change", "POST /v1/machinery/intervention", gaps={"mcp": _d(_WRITE)}),
    _c("machinery.diff", "Is the machine still the configuration you signed off?",
       "machinery diff", "POST /v1/machinery/diff", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("machinery.coverage", "Which safety functions a recorded verification still stands for",
       "machinery coverage", "POST /v1/machinery/coverage", "machinery_coverage"),
    _c("machinery.passport", "Seal the machine's whole evidence position",
       "machinery passport", "POST /v1/machinery/passport", gaps={"mcp": _d(_WRITE)}),
    _c("machinery.passport_check", "Re-verify a passport you did not produce",
       "machinery check", "POST /v1/machinery/passport/check", "machinery_passport_check"),

    # --- fleet: every machine at once, and what a supplier advisory means for them ------------
    _c("fleet.machines", "Every enrolled machine, worst coverage first",
       "fleet list", "GET /v1/fleet/machines", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("fleet.report", "The whole fleet on one page a plant manager can read",
       "report build", "GET /v1/fleet/report", "fleet_report"),
    _c("fleet.observations", "When each machine was last looked at, and did it work",
       (), "GET /v1/fleet/observations",
       gaps={"cli": _d("`watch status` shows the local run; the hosted view of pushed runs is HTTP"),
             "mcp": _p(_NO_MCP_YET)}),
    _c("fleet.advisory", "Which machines does this advisory touch?",
       "fleet advisory", "POST /v1/fleet/advisory",
       gaps={"mcp": _d("an advisory is third-party content; only a person acts on it")}),
    _c("fleet.advisory_signed", "Assess a signed supplier feed against the fleet, with its trust",
       "fleet advisory", "POST /v1/fleet/advisory/signed",
       gaps={"mcp": _d("an advisory is third-party content; only a person acts on it")}),
    _c("fleet.advisory_check", "Is this one machine affected by this advisory?",
       (), "POST /v1/fleet/advisory/check",
       gaps={"cli": _p("no CLI verb for the stateless one-machine form"),
             "mcp": _d("an advisory is third-party content; only a person acts on it")}),
    _c("fleet.import_csaf", "Translate a CSAF 2.0 advisory into our advisory format (inspect-only)",
       "fleet import-csaf", gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("fleet.declare", "Bind a Declaration of Conformity to a configuration",
       "fleet declare", "POST /v1/fleet/declare", gaps={"mcp": _d(_WRITE)}),
    _c("fleet.declaration", "Does the declaration still describe the machine?",
       "fleet declaration", "POST /v1/fleet/declaration/check", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("fleet.value", "Your assurance position, derived from your own ledger",
       "value report", "GET /v1/value", gaps={"mcp": _p(_NO_MCP_YET)}),

    # --- change: the Active Assurance Cases queue ----------------------------------------------
    _c("change.assess_drift", "Turn a manifest divergence into a case",
       "change assess-drift", "POST /v1/change/assess/drift", "change_assess_drift"),
    _c("change.assess_advisory", "Turn a fleet impact report into a case",
       "change assess-advisory", "POST /v1/change/assess/advisory",
       gaps={"mcp": _d("a case opened from third-party content is the attack the signed feed "
                       "exists to stop; only a person opens it")}),
    _c("change.assess_intervention", "Did a recorded intervention invalidate evidence?",
       "change assess-intervention", "POST /v1/change/assess/intervention",
       "change_assess_intervention"),
    _c("change.list", "The Active Assurance Cases queue",
       "change list", "GET /v1/change/cases", "change_cases"),
    _c("change.show", "One case in full",
       "change show", "GET /v1/change/cases/{case_id}", "change_case"),
    _c("change.claim", "OPEN to IN_REVIEW",
       "change claim", "POST /v1/change/cases/{case_id}/claim", "change_claim"),
    _c("change.advance", "Move to the next required stop",
       "change advance", "POST /v1/change/cases/{case_id}/advance", "change_advance"),
    _c("change.reverify", "Supply fresh verification evidence",
       "change reverify", "POST /v1/change/cases/{case_id}/reverification", "change_reverify"),
    _c("change.decide", "Close, reject or defer a case",
       "change decide", "POST /v1/change/cases/{case_id}/decision", gaps={"mcp": _d(_HUMAN)}),
    _c("change.resolve_decision", "Answer one of a case's open human questions",
       "change resolve-decision", "POST /v1/change/cases/{case_id}/resolve-decision",
       gaps={"mcp": _d(_HUMAN)}),
    _c("change.waive_reverification", "Close one re-verification entry WITHOUT evidence",
       "change waive-reverification", "POST /v1/change/cases/{case_id}/waive-reverification",
       gaps={"mcp": _d(_HUMAN)}),
    _c("change.resume", "DEFERRED to IN_REVIEW",
       "change resume", "POST /v1/change/cases/{case_id}/resume", gaps={"mcp": _d(_HUMAN)}),
    _c("change.replay", "Rebuild a case from the ledger alone and check every step",
       "change replay", "GET /v1/change/cases/{case_id}/replay", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("change.export", "A verifiable evidence bundle for one case",
       "change export", "GET /v1/change/cases/{case_id}/export", "change_export"),

    # --- supplier: signed advisory feeds, and the trust a reader puts in them ------------------
    _c("supplier.keygen", "An Ed25519 publishing key", "supplier keygen",
       gaps={"api": _d(_KEYS), "mcp": _d(_KEYS)}),
    _c("supplier.publish", "Sign an advisory into a feed",
       "supplier publish", "POST /v1/supplier/advisory",
       gaps={"mcp": _d("publishing an advisory is a named supplier's signed act")}),
    _c("supplier.withdraw", "Sign a withdrawal of an advisory", "supplier withdraw",
       gaps={"api": _p("the hosted feed has no withdrawal route"),
             "mcp": _d("withdrawing an advisory is a named supplier's signed act")}),
    _c("supplier.verify", "Check a feed file before acting on it", "supplier verify",
       gaps={"api": _d("`POST /v1/supplier/trust/evaluate` is the hosted form, under pinned keys"),
             "mcp": _p(_NO_MCP_YET)}),
    _c("supplier.list", "What stands in a feed file", "supplier list",
       gaps={"api": _d("`GET /v1/supplier/feed/{id}` serves the feed itself"),
             "mcp": _p(_NO_MCP_YET)}),
    _c("supplier.fetch", "Download a hosted feed",
       "supplier fetch", "GET /v1/supplier/feed/{supplier_account_id}",
       gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("supplier.trust_pin", "Trust this key for this supplier",
       "supplier trust pin", "POST /v1/supplier/trust/pin",
       gaps={"mcp": _d("pinning a key is a trust decision a named person makes")}),
    _c("supplier.trust_rotate", "Pin a new key and retire the old from a date",
       "supplier trust rotate", "POST /v1/supplier/trust/rotate",
       gaps={"mcp": _d("a trust decision a named person makes")}),
    _c("supplier.trust_revoke", "Stop trusting a key",
       "supplier trust revoke", "POST /v1/supplier/trust/revoke",
       gaps={"mcp": _d("a trust decision a named person makes")}),
    _c("supplier.trust_list", "Pinned keys and the decision history",
       "supplier trust list", "GET /v1/supplier/trust", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("supplier.trust_check", "What is this feed, state by state, under your pinned keys?",
       "supplier trust check", "POST /v1/supplier/trust/evaluate", gaps={"mcp": _p(_NO_MCP_YET)}),
    _c("supplier.trust_override", "Accept ONE untrusted advisory, attributed",
       "supplier trust override", "POST /v1/supplier/trust/override",
       gaps={"mcp": _d("an override is a named person's accountable act")}),
    _c("supplier.trust_baseline", "Accept a re-issued, trusted feed as the new rollback baseline",
       (), "POST /v1/supplier/trust/feed-baseline",
       gaps={"cli": _p("no CLI verb"),
             "mcp": _d("a trust decision a named person makes")}),

    # --- watch: the collector and what it reports ------------------------------------------------
    _c("watch.run", "One pass over every target", "watch run",
       gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("watch.status", "What the last run found", "watch status",
       gaps={"api": _d("the hosted view is `GET /v1/fleet/observations`"), "mcp": _d(_OFFLINE)}),
    _c("watch.push", "Report the latest sealed run to your own hosted ledger (opt-in)",
       "watch push", "POST /v1/watch/report", gaps={"mcp": _d(_WRITE)}),

    # --- billing: operator tooling for accounts provisioned outside Stripe ---------------------
    _c("billing.grant", "Create a manual-pilot account and print its API key once",
       "billing grant", gaps={"api": _d(_OPERATOR), "mcp": _d(_ACCOUNT)}),
    _c("billing.issue_key", "Print another key for an existing manual grant, once",
       "billing issue-key", gaps={"api": _d(_OPERATOR), "mcp": _d(_ACCOUNT)}),
    _c("billing.revoke_key", "Stop one key of a manual grant at once",
       "billing revoke-key", gaps={"api": _d(_OPERATOR), "mcp": _d(_ACCOUNT)}),
    _c("billing.extend", "Move a manual grant's last day",
       "billing extend", gaps={"api": _d(_OPERATOR), "mcp": _d(_ACCOUNT)}),
    _c("billing.end", "End a manual grant now: revoke every key",
       "billing end", gaps={"api": _d(_OPERATOR), "mcp": _d(_ACCOUNT)}),
    _c("billing.list", "Every account in the store: source, expiry, no secrets",
       "billing list", gaps={"api": _d(_OPERATOR), "mcp": _d(_ACCOUNT)}),

    # --- collect, kit, report: the offline pipeline -----------------------------------------------
    _c("collect.check_plan", "What a collection plan would catch, and miss", "collect check-plan",
       gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("collect.probe", "Which rules report an export's own noise", "collect probe",
       gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("collect.run", "Collect one machine", "collect run",
       gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("kit.init", "Write a runnable kit into a folder", "kit init",
       gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("kit.run", "Enrol every machine, offline", "kit run",
       gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("kit.check", "What the kit would do, touching nothing", "kit check",
       gaps={"api": _d(_OFFLINE), "mcp": _d(_OFFLINE)}),
    _c("report.demo", "Build a worked synthetic fleet and report on it", "report demo",
       gaps={"api": _d("a demonstration on invented data, nothing to host"),
             "mcp": _d("a demonstration on invented data, nothing to drive")}),

    # --- the public catalogue and the account plane -----------------------------------------------
    _c("catalogue.plans", "What is on sale, generated from the enforced entitlements",
       (), "GET /v1/plans", "plans", gaps={"cli": _d(_HTTP)}),
    _c("catalogue.capabilities", "This catalogue", "capabilities", "GET /v1/capabilities",
       "capabilities"),
    _c("account.checkout", "Start a subscription", (), "POST /v1/checkout",
       gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
    _c("account.checkout_complete", "Collect the key after paying", (), "GET /v1/checkout/complete",
       gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
    _c("account.billing_portal", "Manage your subscription", (), "POST /v1/billing/portal",
       gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
    _c("account.billing_webhook", "Stripe webhook (signature verified)", (),
       "POST /v1/billing/webhook", gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
    _c("account.me", "Your account, plan and usage", (), "GET /v1/me",
       gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
    _c("account.keys", "List, issue and revoke API keys", (),
       ("GET /v1/keys", "POST /v1/keys", "POST /v1/keys/revoke"),
       gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
    _c("account.operators", "List, create and disable operators", (),
       ("GET /v1/operators", "POST /v1/operators", "POST /v1/operators/{operator_id}/disable"),
       gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
    _c("account.usage", "What your account has used, and its spend limit", (),
       ("GET /v1/usage", "POST /v1/usage/limits"),
       gaps={"cli": _d(_ACCOUNT), "mcp": _d(_ACCOUNT)}),
)


# --------------------------------------------------------------------------------------------
# discovery: what the code really exposes today
# --------------------------------------------------------------------------------------------
_CLI_DOMAINS_MODULE = "assurance.cli"
_MCP_SOURCE = Path(__file__).resolve().parent / "mcp" / "server.py"
_MCP_TOOL = re.compile(
    r"@mcp\.tool\(\)\s*async def (\w+)\([^)]*\)[^:]*:\s*\"\"\"\s*"
    r"((?:GET|POST|PUT|PATCH|DELETE) \S+)", re.S)
#: CLI verbs that are not domain commands: the catalogue's own entry point.
_TOP_LEVEL_CLI = {"capabilities": "assurance.capabilities_cli"}


def _leaves(parser: argparse.ArgumentParser, prefix: tuple[str, ...]) -> list[tuple[str, ...]]:
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if not subs:
        return [prefix]
    out: list[tuple[str, ...]] = []
    for action in subs:
        for name, child in action.choices.items():
            out += _leaves(child, (*prefix, name))
    return out


def discover_cli() -> list[str]:
    domains = importlib.import_module(_CLI_DOMAINS_MODULE)._DOMAINS
    found: list[str] = []
    for domain, module in domains.items():
        if domain in _TOP_LEVEL_CLI:
            found.append(domain)
            continue
        mod = importlib.import_module(module)
        build = getattr(mod, "build_parser", None)
        if build is None:
            found.append(domain)            # a domain we cannot look inside is one opaque command
            continue
        found += [" ".join((domain, *leaf)) for leaf in _leaves(build(), ())]
    return sorted(found)


def discover_api(app: Any) -> dict[str, dict[str, Any]]:
    """``{"METHOD /path": {summary, tag}}`` for every ``/v1`` operation of the live app."""
    spec = app.openapi()
    out: dict[str, dict[str, Any]] = {}
    for path, item in spec.get("paths", {}).items():
        if not path.startswith("/v1"):
            continue
        for method, op in item.items():
            if method in ("get", "post", "put", "patch", "delete"):
                out[f"{method.upper()} {path}"] = {
                    "summary": op.get("summary", ""), "tag": (op.get("tags") or [""])[0]}
    return out


def discover_mcp() -> dict[str, str]:
    """``{tool name: "METHOD /path"}``, read from the server source (no MCP install needed)."""
    return dict(_MCP_TOOL.findall(_MCP_SOURCE.read_text(encoding="utf-8")))


def discover(app: Any) -> dict[str, Any]:
    return {"cli": discover_cli(), "api": discover_api(app), "mcp": discover_mcp()}




# --------------------------------------------------------------------------------------------
# checks: the table against the world
# --------------------------------------------------------------------------------------------
def problems(app: Any) -> list[str]:
    """Every way the declared catalogue and the real surfaces disagree. Empty means they agree."""
    found = discover(app)
    real = {"cli": set(found["cli"]), "api": set(found["api"]), "mcp": set(found["mcp"])}
    out: list[str] = []
    ids = [c.id for c in CAPABILITIES]
    out += [f"duplicate capability id {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]

    claimed: dict[str, set[str]] = {s: set() for s in SURFACES}
    for cap in CAPABILITIES:
        for surface in SURFACES:
            names = cap.claims(surface)
            claimed[surface].update(names)
            for name in names:
                if name not in real[surface]:
                    out.append(f"{cap.id}: claims {surface} {name!r}, which does not exist")
            if not names and surface not in cap.gaps:
                out.append(f"{cap.id}: has no {surface} surface and does not say why")
            if names and surface in cap.gaps:
                out.append(f"{cap.id}: declares {surface} absent but claims {names[0]!r}")
        for surface, (kind, reason) in cap.gaps.items():
            if surface not in SURFACES:
                out.append(f"{cap.id}: gap names an unknown surface {surface!r}")
            if kind not in (BY_DESIGN, PLANNED) or not reason.strip():
                out.append(f"{cap.id}: gap on {surface} needs a kind and a reason")

    for surface in SURFACES:
        for name in sorted(real[surface] - claimed[surface]):
            out.append(f"uncatalogued {surface}: {name!r} exists and belongs to no capability")

    # An MCP tool must wrap the API route its capability claims for the API.
    tool_route = discover_mcp()
    for cap in CAPABILITIES:
        for tool in cap.mcp:
            route = tool_route.get(tool)
            if route and cap.api and route not in cap.api:
                out.append(f"{cap.id}: MCP tool {tool!r} wraps {route}, not the API route claimed")
    return out


# --------------------------------------------------------------------------------------------
# the catalogue as data
# --------------------------------------------------------------------------------------------
def _gates(app: Any) -> dict[str, list[str]]:
    """API route -> the plan flags that gate it, read from the live dependency graph."""
    from fastapi.routing import APIRoute

    from assurance.api import deps

    def calls(dep: Any) -> set[Any]:
        found: set[Any] = set()
        for sub in dep.dependencies:
            found.add(sub.call)
            found |= calls(sub)
        return found

    def walk(routes: Any) -> Any:
        for route in routes:
            if isinstance(route, APIRoute):
                yield route
            elif hasattr(route, "original_router"):
                yield from walk(route.original_router.routes)
            elif hasattr(route, "routes"):
                yield from walk(route.routes)

    out: dict[str, list[str]] = {}
    for route in walk(app.routes):
        if route.path.startswith("/v1"):
            flags = sorted({name for fn, name in deps.ENTITLEMENT_GATES.items()
                            if fn in calls(route.dependant)})
            for method in route.methods - {"HEAD", "OPTIONS"}:
                out[f"{method} {route.path}"] = flags
    return out


def catalogue(app: Any) -> dict[str, Any]:
    """The catalogue with each surface's real status, ready to serve as JSON."""
    found = discover(app)
    gates = _gates(app)
    caps: list[dict[str, Any]] = []
    counts = {s: {"present": 0, "by_design": 0, "planned": 0} for s in SURFACES}
    for cap in CAPABILITIES:
        entry: dict[str, Any] = {"id": cap.id, "service": cap.service, "summary": cap.summary}
        for surface in SURFACES:
            names = cap.claims(surface)
            if names:
                present = [n for n in names if n in found[surface]]
                entry[surface] = {"status": "present", "names": list(names)}
                counts[surface]["present"] += 1
                if surface == "api":
                    entry[surface]["gates"] = {n: gates.get(n, []) for n in names}
                if not present:
                    entry[surface]["status"] = "declared_but_missing"
            else:
                kind, reason = cap.gaps.get(surface, (PLANNED, "undeclared"))
                entry[surface] = {"status": kind, "reason": reason}
                counts[surface][kind] += 1
        caps.append(entry)
    return {
        "schema": SCHEMA,
        "generated_from": "the live CLI parsers, the API's OpenAPI document and the MCP server "
                          "source; the pairing of surfaces is declared by people in "
                          "assurance/capabilities.py and checked against them",
        "capabilities": caps,
        "counts": counts,
        "surfaces_checked": {s: len(found[s]) for s in SURFACES},
        "limits": [
            "present means the command, route or tool exists; it does not prove the surfaces "
            "behave identically, only that a person declared them the same capability",
            "planned gaps are known and open; they are listed so they are not hidden",
        ],
    }
