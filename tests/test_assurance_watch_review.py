"""Findings from the independent adversarial review of S5, each pinned by a test.

1. a report cannot hide staleness by rewriting a cadence;
2. one tenant's report cannot stall the service, nor grow an account without bound;
3. a failed look is never recorded against a machine it does not name;
4. batch order is by instant, not by timestamp text;
5. a future-dated success cannot supersede a real later failure;
6. secret-shaped input is never echoed;
7. the mutants the first round missed;
8. idempotence holds across processes.
"""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
import time
from datetime import UTC, timedelta
from pathlib import Path

import pytest

from assurance.api import watch_routes
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch import ingest, push
from assurance.watch.cli import main as watch_main
from assurance.watch.runner import run_watch

from .test_assurance_watch_push import (  # noqa: F401  (fixtures)
    Recorder,
    _accounts,
    _cell,
    _client,
    _config,
    _env,
    _local,
    _plant,
    cli,
    use,
)
from .test_assurance_watch_report import (
    KEY_0412,
    KEY_0501,
    failed,
    good,
    iso,
    ledger_of,
    machine_row,
    make_manifest,
    now,
    observations,
    post,
    report,
)

SRC = Path(__file__).resolve().parents[1] / "src"
WATCH_B = "WATCH-OTHER"


def enroll(client, headers, tmp_path, serial, *, at=None, watch_id="WATCH-T", max_age_hours=None):
    """A real successful look, which is how a machine becomes known to the account."""
    at = at or now() - timedelta(minutes=30)
    r = post(client, headers, report(good(make_manifest(tmp_path, serial), at=at), started=at,
                                     watch_id=watch_id, max_age_hours=max_age_hours))
    assert r.json()["machines"][0]["outcome"] == "recorded", r.text
    return f"Grimaldi/AR-7#{serial}"


# =====================================================================
# 1. cadence
# =====================================================================

class TestCadenceCannotHideStaleness:
    def test_a_failed_only_report_for_another_machine_cannot_rewrite_the_cadence(
            self, client, cell, tmp_path):
        _, h = cell
        old = now() - timedelta(days=100)
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=old), started=old,
                               max_age_hours=24))
        assert machine_row(client, h, KEY_0412)["stale"] is True
        enroll(client, h, tmp_path, "0501", at=now() - timedelta(hours=3), max_age_hours=24)
        post(client, h, report(failed("0501", at=now() - timedelta(hours=1)),
                               max_age_hours=720, watch_id="WATCH-T"))
        row = machine_row(client, h, KEY_0412)
        assert row["stale"] is True and row["cadence_hours"] == 24

    def test_the_repro_value_is_no_longer_accepted_at_all(self, client, cell, tmp_path):
        _, h = cell
        for hours in (8784, 721, 0.5, 0, -1):
            r = post(client, h, report(failed("0412", at=now() - timedelta(minutes=2)),
                                       max_age_hours=hours))
            assert r.status_code == 422, hours
        for hours, serial in ((1, "0412"), (720, "0501")):
            assert machine_row(client, h, enroll(client, h, tmp_path, serial, max_age_hours=hours)
                               )["cadence_hours"] == hours

    def test_a_second_watch_cannot_change_another_watchs_machines(self, client, cell, tmp_path):
        _, h = cell
        enroll(client, h, tmp_path, "0412", at=now() - timedelta(hours=50), max_age_hours=24)
        enroll(client, h, tmp_path, "0501", at=now() - timedelta(hours=1), watch_id=WATCH_B,
               max_age_hours=720)
        a, b = machine_row(client, h, KEY_0412), machine_row(client, h, KEY_0501)
        assert (a["stale"], a["cadence_hours"]) == (True, 24)
        assert (b["stale"], b["cadence_hours"]) == (False, 720)

    def test_when_two_watches_reported_a_machine_the_shorter_cadence_judges_it(
            self, client, cell, tmp_path):
        _, h = cell
        enroll(client, h, tmp_path, "0412", at=now() - timedelta(hours=60), max_age_hours=24)
        post(client, h, report(good(make_manifest(tmp_path, "0412"), at=now() - timedelta(hours=30)),
                               started=now() - timedelta(hours=30), watch_id=WATCH_B,
                               max_age_hours=720))
        row = machine_row(client, h, KEY_0412)
        assert row["cadence_hours"] == 24 and row["stale"] is True

    def test_a_cadence_comes_only_from_a_successful_look_of_that_machine(self, client, cell, tmp_path):
        _, h = cell
        enroll(client, h, tmp_path, "0412", at=now() - timedelta(hours=100))
        post(client, h, report(failed("0412", at=now() - timedelta(hours=1)), max_age_hours=720))
        row = machine_row(client, h, KEY_0412)
        assert row["cadence_hours"] == 168 and row["cadence_declared"] is False
        assert row["stale"] is False                    # 100 h < 168 h default; not stretched to 720


    def test_only_a_successful_look_stores_a_cadence(self, client, cell, tmp_path):
        acct, h = cell
        enroll(client, h, tmp_path, "0412", at=now() - timedelta(hours=3), max_age_hours=24)
        post(client, h, report(failed("0412", at=now() - timedelta(hours=1)), max_age_hours=720))
        bodies = [e.evidence().body for e in ledger_of(acct).entries(kind="watch.observation")]
        assert [b["cadence_hours"] for b in bodies] == [24.0, None]


# =====================================================================
# 2. the service and its bounds
# =====================================================================

class TestTheServiceIsNotStalled:
    def test_the_route_runs_in_the_threadpool_not_on_the_event_loop(self):
        assert not inspect.iscoroutinefunction(watch_routes.post_report)

    def test_an_account_cannot_track_more_machines_than_the_limit(
            self, client, cell, tmp_path, monkeypatch):
        _, h = cell
        monkeypatch.setattr(ingest, "MAX_MACHINES_PER_ACCOUNT", 2)
        enroll(client, h, tmp_path, "0412")
        enroll(client, h, tmp_path, "0501")
        r = post(client, h, report(good(make_manifest(tmp_path, "0602"), at=now() - timedelta(minutes=5))))
        m = r.json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "account_machine_limit")
        assert len(observations(client, h)["machines"]) == 2
        # An already-known machine can still be reported.
        again = post(client, h, report(failed("0412", at=now() - timedelta(minutes=2))))
        assert again.json()["machines"][0]["outcome"] == "recorded"

    def test_a_report_cannot_introduce_more_new_machines_than_the_limit(
            self, client, cell, tmp_path, monkeypatch):
        _, h = cell
        monkeypatch.setattr(ingest, "MAX_NEW_MACHINES_PER_REPORT", 1)
        t = now() - timedelta(minutes=5)
        r = post(client, h, report(good(make_manifest(tmp_path, "0412"), at=t),
                                   good(make_manifest(tmp_path, "0501"), at=t)))
        assert [m["outcome"] for m in r.json()["machines"]] == ["recorded", "refused"]
        assert r.json()["machines"][1]["reason"] == "too_many_new_machines"


# =====================================================================
# 3. a failure belongs to the machine it names
# =====================================================================

class TestFailuresNeverCreateGhosts:
    def test_a_failure_for_an_unenrolled_machine_is_refused_and_creates_no_row(
            self, client, cell, tmp_path):
        acct, h = cell
        m = post(client, h, report(failed("0999", at=now() - timedelta(minutes=2)))).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "unenrolled_machine")
        assert observations(client, h)["machines"] == []
        assert len(ledger_of(acct)) == 0

    def test_a_bare_serial_resolves_to_the_one_enrolled_key(self, client, cell, tmp_path):
        _, h = cell
        enroll(client, h, tmp_path, "0412", at=now() - timedelta(hours=200))
        entry = failed("0412", at=now() - timedelta(minutes=2), key="")
        m = post(client, h, report(entry)).json()["machines"][0]
        assert m["outcome"] == "recorded" and m["machine_key"] == KEY_0412
        machines = observations(client, h)["machines"]
        assert [x["machine"] for x in machines] == [KEY_0412]        # no ghost row "0412"
        assert machines[0]["last_attempt_succeeded"] is False and machines[0]["stale"] is True

    def test_a_bare_serial_that_matches_two_enrolled_machines_is_refused(
            self, client, cell, tmp_path):
        _, h = cell
        enroll(client, h, tmp_path, "0412")
        other = make_manifest(tmp_path, "0412")
        other["machine"]["model"] = "AR-8"
        post(client, h, report(good(other, at=now() - timedelta(minutes=20))))
        m = post(client, h, report(failed("0412", at=now() - timedelta(minutes=2), key=""))
                 ).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "ambiguous_serial")

    def test_a_typo_in_the_key_is_refused_not_recorded_as_a_new_machine(self, client, cell, tmp_path):
        _, h = cell
        enroll(client, h, tmp_path, "0412")
        m = post(client, h, report(failed("0412", at=now() - timedelta(minutes=2),
                                          key="Grimaldi/AR7#0412"))).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "unenrolled_machine")
        assert [x["machine"] for x in observations(client, h)["machines"]] == [KEY_0412]
        assert machine_row(client, h, KEY_0412)["last_attempt_succeeded"] is True


# =====================================================================
# 4. order by instant
# =====================================================================

class TestOrderIsByInstant:
    def test_an_offset_spelling_does_not_reorder_the_batch(self, client, cell, tmp_path):
        _, h = cell
        enroll(client, h, tmp_path, "0412", at=now() - timedelta(hours=9))
        earlier = now() - timedelta(hours=5)
        later = now() - timedelta(hours=3)
        # Same instant as `earlier`, spelled at +14:00: as text it sorts after `later`.
        spelled = (earlier.astimezone(UTC) + timedelta(hours=14)).strftime("%Y-%m-%dT%H:%M:%S+14:00")
        e1 = failed("0412", at=earlier)
        e1["observed_at"] = spelled
        e2 = failed("0412", at=later)
        r = post(client, h, report(e2, e1)).json()
        assert [m["outcome"] for m in r["machines"]] == ["recorded", "recorded"]
        assert r["machines"][1]["observed_at"] == iso(earlier)         # stored as UTC Z
        row = machine_row(client, h, KEY_0412)
        assert row["last_attempt_at"] == iso(later)


# =====================================================================
# 5. future-dated success
# =====================================================================

class TestAFutureSuccessCannotMaskARealFailure:
    def test_the_skew_is_a_minute(self):
        assert ingest.FUTURE_SKEW == timedelta(seconds=60)

    def test_two_minutes_ahead_is_refused(self, client, cell, tmp_path):
        _, h = cell
        m = post(client, h, report(good(make_manifest(tmp_path), at=now() + timedelta(minutes=2)))
                 ).json()["machines"][0]
        assert (m["outcome"], m["reason"]) == ("refused", "observed_at_in_future")

    def test_a_success_stamped_ahead_does_not_supersede_a_later_real_failure(
            self, client, cell, tmp_path):
        _, h = cell
        ahead = now() + timedelta(seconds=45)
        first = post(client, h, report(good(make_manifest(tmp_path), at=ahead, keep_taken_at=False),
                                       started=now()))
        assert first.json()["machines"][0]["outcome"] == "recorded"
        # A real failure a few seconds later by the client's own (slightly fast) clock.
        later = post(client, h, report(failed("0412", at=now() + timedelta(seconds=3)))).json()
        assert later["machines"][0]["outcome"] == "recorded", later
        row = machine_row(client, h, KEY_0412)
        assert row["last_attempt_succeeded"] is False
        # And the success is never displayed as happening in the future.
        assert row["last_successful_observation_at"] <= iso(now() + timedelta(seconds=1))


# =====================================================================
# 6. secrets are never echoed
# =====================================================================

SECRETS = ["asr_Zk3x9Qw7Lm2Pd8Vn4Rt6Yb1Hc5Gf0JsAe", "sk_live_51Hx9Zk3x9Qw7Lm2Pd8",
           "whsec_Zk3x9Qw7Lm2Pd8Vn4Rt6Yb1Hc5G", "Zk3x9Qw7Lm2Pd8Vn4Rt6Yb1Hc5Gf0JsAe"]


class TestSecretShapedInputIsNeverEchoed:
    @pytest.mark.parametrize("secret", SECRETS)
    def test_key_env_holding_a_key(self, plant, local, config, capsys, secret):
        run_watch(config, local, now=now() - timedelta(hours=1))
        code = watch_main(["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
                           "--api-url", "https://api.example.com", "--key-env", secret])
        out, err = capsys.readouterr()
        assert code == 2 and secret not in out + err and "--key-env" in err

    @pytest.mark.parametrize("secret", SECRETS)
    def test_a_key_typed_into_ledger_or_config(self, plant, local, config, capsys, secret):
        run_watch(config, local, now=now() - timedelta(hours=1))
        common = ["--api-url", "https://api.example.com", "--key-env", "NB_X"]
        code = watch_main(["push", str(plant / "watch.json"), "--ledger", secret, *common])
        out, err = capsys.readouterr()
        assert code == 2 and secret not in out + err and "--ledger" in err
        code = watch_main(["push", secret, "--ledger", str(plant / "register.db"), *common])
        out, err = capsys.readouterr()
        assert code == 2 and secret not in out + err

    @pytest.mark.parametrize("secret", SECRETS)
    def test_dry_run_does_not_print_a_key_given_as_the_key_env_name(
            self, plant, local, config, capsys, secret):
        run_watch(config, local, now=now() - timedelta(hours=1))
        code = watch_main(["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
                           "--api-url", "https://api.example.com", "--key-env", secret, "--dry-run"])
        out, err = capsys.readouterr()
        assert code == 2 and secret not in out + err

    def test_a_key_typed_into_api_url(self, plant, local, config, capsys):
        secret = SECRETS[0]
        run_watch(config, local, now=now() - timedelta(hours=1))
        code = watch_main(["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
                           "--api-url", secret, "--key-env", "NB_X"])
        out, err = capsys.readouterr()
        assert code == 2 and secret not in out + err

    def test_an_ordinary_missing_env_var_name_is_still_named(self, plant, local, config, capsys,
                                                             monkeypatch):
        run_watch(config, local, now=now() - timedelta(hours=1))
        monkeypatch.delenv("NB_PLAIN_NAME", raising=False)
        code = watch_main(["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
                           "--api-url", "https://api.example.com", "--key-env", "NB_PLAIN_NAME"])
        assert code == 2 and "NB_PLAIN_NAME" in capsys.readouterr().err


# =====================================================================
# 7. the mutants the first round missed
# =====================================================================

def _push_argv(plant, *extra):
    return ["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
            "--api-url", "https://api.example.com", *extra]


class TestTheArgumentParserDoesNotLeak:
    def test_an_unrecognized_key_argument_is_not_echoed_even_with_every_required_option(
            self, plant, local, config, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        with pytest.raises(SystemExit) as e:
            watch_main(_push_argv(plant, "--key-env", "FOO", "--key", "asr_x_leaky_value_123"))
        assert e.value.code == 2
        captured = capsys.readouterr()
        assert "asr_x_leaky_value_123" not in captured.out + captured.err

    @pytest.mark.parametrize("flag,value", [("--key-e", "NB_ASSURANCE_KEY"), ("--api-ur", "https://x.example"),
                                            ("--dry", None), ("--max-body", "5000")])
    def test_abbreviations_are_rejected_directly(self, plant, local, config, capsys, flag, value):
        run_watch(config, local, now=now() - timedelta(hours=1))
        argv = ["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db")]
        if flag != "--api-ur":
            argv += ["--api-url", "https://api.example.com"]
        if flag != "--key-e":
            argv += ["--key-env", "NB_ASSURANCE_KEY"]
        argv += [flag, *([value] if value else [])]
        with pytest.raises(SystemExit) as e:
            watch_main(argv)
        assert e.value.code == 2


class TestAnIncompleteLookNeverSendsAManifest:
    def test_client_side(self, plant, local, config, client, cell, monkeypatch, capsys):
        (plant / "0412" / "plc-project.zip").unlink()                     # the plan's required item
        run = run_watch(config, local, now=now() - timedelta(hours=1))
        out = next(o for o in run.outcomes if o.serial == "0412")
        assert out.collection_complete is False and out.status != "uncollectable"
        monkeypatch.setenv("NB_ASSURANCE_KEY", cell[1]["X-API-Key"])
        rec = use(monkeypatch, Recorder(client))
        plan = push.build_plan(config, local)
        entry = next(m for b in plan.bodies for m in b["machines"]
                     if m["serial"] == "0412" and m["status"] == "incomplete")
        assert entry["manifest"] is None and entry["collection_complete"] is False
        assert "ITM-PLC" in entry["missing_items"]
        assert rec.requests == []


# =====================================================================
# 8. idempotence across processes
# =====================================================================

_CHILD = """
import json, sys
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch.ingest import ingest_report
body = json.load(open(sys.argv[2]))
r = ingest_report(EvidenceLedger(sys.argv[1]), body, actor=Actor('t', 'r', 'automation'))
print(sum(1 for m in r.results if m.outcome == 'recorded'))
"""


class TestAcrossProcesses:
    def test_a_second_process_waits_for_the_ledgers_ingest_lock(self, tmp_path):
        import fcntl

        from .test_assurance_watch_report import _plain

        ledger = EvidenceLedger(tmp_path / "x.db")
        body = _plain(report(failed("0412", at=now() - timedelta(minutes=5)),
                             good(make_manifest(tmp_path), at=now() - timedelta(minutes=5))))
        bodyfile = tmp_path / "body.json"
        bodyfile.write_text(json.dumps(body))
        lock = open(ingest.lock_path(ledger), "a+")                        # noqa: SIM115
        fcntl.flock(lock, fcntl.LOCK_EX)
        child = subprocess.Popen([sys.executable, "-c", _CHILD, str(ledger.path), str(bodyfile)],  # noqa: S603
                                 env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
                                 stdout=subprocess.PIPE, text=True)
        time.sleep(1.5)
        assert child.poll() is None, "the child ingested while another process held the lock"
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
        assert child.wait(timeout=30) == 0

    def test_concurrent_processes_write_one_set_of_records(self, tmp_path):
        from .test_assurance_watch_report import _plain

        ledger = EvidenceLedger(tmp_path / "y.db")
        t = now() - timedelta(minutes=5)
        body = _plain(report(*[good(make_manifest(tmp_path, f"{n:04d}"), at=t) for n in range(8)]))
        bodyfile = tmp_path / "body.json"
        bodyfile.write_text(json.dumps(body))
        kids = [subprocess.Popen([sys.executable, "-c", _CHILD, str(ledger.path), str(bodyfile)],  # noqa: S603
                                 env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
                                 stdout=subprocess.PIPE, text=True) for _ in range(5)]
        recorded = sum(int(k.communicate()[0].strip()) for k in kids)
        assert recorded == 8
        assert len(ledger.entries(kind="watch.observation")) == 8
        assert ledger.verify_chain()[0] is True


def test_the_example_does_not_leave_the_key_in_shell_history():
    text = (Path(__file__).resolve().parents[1] / "deploy/assurance/WATCH.md").read_text()
    assert "export NB_ASSURANCE_KEY=..." not in text and "read -rs" in text
