"""The capability contract says, for every capability, where it runs; and the OpenAPI says it too.

Hosted, self-hosted, offline-only and operator-host-only are different promises. The catalogue
derives the mode from the surfaces a capability declares and the reason it gives for a missing
API route, so it cannot say "hosted" about something with no route. Nothing here says a
deployment exists: that is ``docs/GO-LIVE.md``.
"""

from __future__ import annotations

from assurance import capabilities
from assurance.api.service import app, create_app
from assurance.capabilities import CAPABILITIES, HOSTING_MODES

BY_ID = {c.id: c for c in CAPABILITIES}


def test_every_capability_has_a_known_mode_with_a_statement():
    for cap in CAPABILITIES:
        assert cap.hosting in HOSTING_MODES, cap.id
        assert capabilities.hosting(cap)["statement"] == HOSTING_MODES[cap.hosting]


def test_hosted_means_an_api_route_exists_and_nothing_else_does():
    for cap in CAPABILITIES:
        hosted = cap.hosting in ("hosted_only", "hosted_and_offline")
        assert hosted == bool(cap.api), cap.id
        assert (cap.hosting == "hosted_and_offline") == bool(cap.api and cap.cli), cap.id


def test_collection_the_kit_and_the_watch_run_are_offline_only():
    for cap_id in ("collect.run", "collect.probe", "collect.check_plan", "kit.run", "kit.init",
                   "kit.check", "watch.run", "watch.status", "fleet.import_csaf", "art14.bridge"):
        assert BY_ID[cap_id].hosting == "offline_only", cap_id
    # the only Watch thing the service does is record what the customer pushed
    assert BY_ID["watch.push"].hosting == "hosted_and_offline"
    assert BY_ID["fleet.observations"].hosting == "hosted_only"
    assert not [a for c in CAPABILITIES if c.id.startswith("watch.") for a in c.api
                if "run" in a or "schedule" in a]


def test_keys_trust_and_operator_tooling_are_never_described_as_hosted():
    for cap_id in ("attest.keygen", "supplier.keygen", "machine.recorder_sign",
                   "attest.trust_list_add"):
        assert BY_ID[cap_id].hosting == "operator_machine_only", cap_id
    for cap_id in ("ops.cycle", "tenant.export", "billing.grant", "intel.refresh",
                   "intel.ingest"):
        assert BY_ID[cap_id].hosting == "operator_host_only", cap_id


def test_the_catalogue_and_the_contract_carry_it():
    cat = capabilities.catalogue(app)
    assert cat["hosting_modes"] == HOSTING_MODES
    assert all(c["hosting"]["mode"] in HOSTING_MODES for c in cat["capabilities"])
    assert any("does not say a deployment exists" in x for x in cat["limits"])


def test_the_openapi_says_what_runs_where_and_that_there_is_no_hosted_watch():
    spec = create_app().openapi()
    text = spec["info"]["description"]
    assert "What runs where" in text and "no hosted scheduler" in text
    tags = {t["name"]: t["description"] for t in spec["tags"]}
    assert "There is no hosted Watch" in tags["watch"]
    assert "Nothing here fetches or records a feed" in tags["intel"]
    assert "store_freshness" in tags["intel"]
    assert "files nothing with ENISA" in tags["article 14"]
