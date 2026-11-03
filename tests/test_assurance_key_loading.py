"""The hosted service key is judged by ONE rule, wherever it is loaded.

The signing key counter-signs the anchors tenants rely on. Before this rule only the
``attest`` CLI refused a loose key; the API (and the supplier / machine CLIs, and
preflight's loader) read it with no check. Now :meth:`SigningKey.load` itself opens the
file ``O_NOFOLLOW`` and judges the *open descriptor*: regular file, owned by the running
account (or root), no group/other access, in a directory neither can write. A sticky
shared directory such as ``/tmp`` is not acceptable for a service key.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import logging
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from assurance.attest import keys as keys_module
from assurance.attest.custody import key_file_problems, require_private_key_file
from assurance.attest.keys import SigningKey, SigningKeyError, UnsafeSigningKeyError
from assurance.attest.preflight import run_preflight

pytestmark = pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")

OPERATOR_KEY = "operator-key-test"


def make_key(tmp_path: Path, *, file_mode=0o600, dir_mode=0o700, name="service.pem") -> Path:
    """A key created the safe way (0600, exclusive), then put into the requested state."""
    directory = tmp_path / f"keys-{file_mode:o}-{dir_mode:o}"
    directory.mkdir(mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / name
    SigningKey.generate().save(path)
    os.chmod(path, file_mode)
    os.chmod(directory, dir_mode)
    return path


def raw_seed_hex(path: Path) -> str:
    key = SigningKey.load(path, check_permissions=False)
    return key.private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()


def bad_cases(tmp_path: Path) -> dict[str, Path]:
    cases = {
        "world-readable file": make_key(tmp_path, file_mode=0o644),
        "group-readable file": make_key(tmp_path, file_mode=0o640),
        "group-writable parent": make_key(tmp_path, dir_mode=0o770),
        "world-writable parent": make_key(tmp_path, dir_mode=0o702),
        "sticky world-writable parent": make_key(tmp_path, dir_mode=0o1777),
    }
    target = make_key(tmp_path, name="real.pem")
    link = target.parent / "link.pem"
    link.symlink_to(target)
    cases["symlink"] = link
    return cases


# -------------------------------------------------------------------------------------
# the loader
# -------------------------------------------------------------------------------------
class TestLoaderRule:
    def test_an_owner_only_key_in_an_owner_only_directory_loads(self, tmp_path):
        path = make_key(tmp_path)
        assert SigningKey.load(path).fingerprint
        assert key_file_problems(path) == []
        os.chmod(path, 0o400)
        assert SigningKey.load(path).fingerprint

    def test_every_unsafe_state_is_refused_as_unsafe(self, tmp_path):
        for name, path in bad_cases(tmp_path).items():
            with pytest.raises(UnsafeSigningKeyError):
                SigningKey.load(path)
            assert key_file_problems(path), name
            with pytest.raises(UnsafeSigningKeyError):
                require_private_key_file(path)

    def test_a_missing_key_is_missing_not_unsafe(self, tmp_path):
        with pytest.raises(SigningKeyError) as excinfo:
            SigningKey.load(tmp_path / "nope.pem")
        assert not isinstance(excinfo.value, UnsafeSigningKeyError)
        with pytest.raises(SigningKeyError) as excinfo:
            SigningKey.load(tmp_path / "no-such-dir" / "nope.pem")
        assert not isinstance(excinfo.value, UnsafeSigningKeyError)

    def test_a_symlink_is_refused_even_when_its_target_is_perfect(self, tmp_path):
        target = make_key(tmp_path)
        link = target.parent / "link.pem"
        link.symlink_to(target)
        with pytest.raises(UnsafeSigningKeyError, match="symbolic link"):
            SigningKey.load(link)

    def test_a_directory_or_fifo_is_not_a_key_file(self, tmp_path):
        directory = tmp_path / "d"
        directory.mkdir(mode=0o700)
        with pytest.raises(UnsafeSigningKeyError, match="not a regular file"):
            SigningKey.load(directory)
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo, 0o600)
        with pytest.raises(UnsafeSigningKeyError, match="not a regular file"):
            SigningKey.load(fifo)

    def test_the_file_that_is_judged_is_the_file_that_is_read(self, tmp_path, monkeypatch):
        """Swap the path for another file after the open: the bytes come from the open fd."""
        path = make_key(tmp_path)
        other = make_key(tmp_path, name="other.pem")
        wanted = SigningKey.load(path).fingerprint
        assert SigningKey.load(other).fingerprint != wanted
        real_fstat = os.fstat
        state = {"done": False}

        def swap_then_fstat(fd):
            result = real_fstat(fd)
            if not state["done"] and stat.S_ISREG(result.st_mode):
                state["done"] = True
                os.replace(other, path)
            return result

        monkeypatch.setattr(keys_module.os, "fstat", swap_then_fstat)
        assert SigningKey.load(path).fingerprint == wanted

    def test_a_key_owned_by_another_account_is_refused(self, tmp_path, monkeypatch):
        # No chown (needs root): run as euid 1000 and report the key file as owned by 4242.
        path = make_key(tmp_path)
        real = os.fstat

        def stranger(fd):
            r = real(fd)
            if stat.S_ISREG(r.st_mode):
                fields = {n: getattr(r, n) for n in dir(r) if n.startswith("st_")}
                fields["st_uid"] = 4242
                return SimpleNamespace(**fields)
            return r

        monkeypatch.setattr(keys_module.os, "fstat", stranger)
        monkeypatch.setattr(keys_module.os, "geteuid", lambda: 1000)
        with pytest.raises(UnsafeSigningKeyError, match="owned by another account"):
            SigningKey.load(path)
        assert any("owned by another" in p for p in key_file_problems(path))

    def test_a_directory_owned_by_another_account_is_refused(self, tmp_path, monkeypatch):
        path = make_key(tmp_path)
        real = os.fstat

        def stranger_dir(fd):
            r = real(fd)
            if stat.S_ISDIR(r.st_mode):
                fields = {n: getattr(r, n) for n in dir(r) if n.startswith("st_")}
                fields["st_uid"] = 4242
                return SimpleNamespace(**fields)
            return r

        monkeypatch.setattr(keys_module.os, "fstat", stranger_dir)
        monkeypatch.setattr(keys_module.os, "geteuid", lambda: 1000)
        with pytest.raises(UnsafeSigningKeyError, match="directory"):
            SigningKey.load(path)

    def test_ownership_logic_with_a_stubbed_fstat(self, tmp_path, monkeypatch):
        """The owner rule, testable without root: report the file as owned by a stranger."""
        path = make_key(tmp_path)
        real = os.fstat

        def stranger(fd):
            r = real(fd)
            if stat.S_ISREG(r.st_mode):
                fields = {n: getattr(r, n) for n in dir(r) if n.startswith("st_")}
                fields["st_uid"] = 4242
                return SimpleNamespace(**fields)
            return r

        monkeypatch.setattr(keys_module.os, "fstat", stranger)
        monkeypatch.setattr(keys_module.os, "geteuid", lambda: 1000)
        with pytest.raises(UnsafeSigningKeyError, match="owned by another account"):
            SigningKey.load(path)

    def test_the_test_only_switch_is_an_argument_not_an_environment_variable(
            self, tmp_path, monkeypatch):
        path = make_key(tmp_path, file_mode=0o644)
        for var in ("ASSURANCE_ALLOW_LOOSE_KEY", "ASSURANCE_ATTEST_SKIP_CHECKS",
                    "NEURALBRIDGE_INSECURE_KEYS"):
            monkeypatch.setenv(var, "1")
        with pytest.raises(UnsafeSigningKeyError):
            SigningKey.load(path)
        assert SigningKey.load(path, check_permissions=False).fingerprint

    def test_an_oversize_file_is_refused_not_read_whole(self, tmp_path):
        path = make_key(tmp_path)
        path.write_bytes(b"x" * (70 * 1024))
        with pytest.raises(SigningKeyError, match="too large"):
            SigningKey.load(path)

    def test_errors_carry_no_key_bytes_and_no_directory(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)
        for name, path in bad_cases(tmp_path).items():
            seed = raw_seed_hex(path)
            body = "".join(ln for ln in path.read_text().splitlines()
                           if ln and not ln.startswith("-----"))
            with pytest.raises(UnsafeSigningKeyError) as excinfo:
                SigningKey.load(path)
            text = str(excinfo.value) + " ".join(key_file_problems(path))
            assert str(path.parent) not in text, name
            assert str(tmp_path) not in text, name
            assert body not in text and seed not in text and "PRIVATE KEY" not in text
        assert str(tmp_path) not in caplog.text
        # a caller's label replaces even the basename
        with pytest.raises(UnsafeSigningKeyError) as excinfo:
            SigningKey.load(make_key(tmp_path, file_mode=0o666), label="the key file")
        assert "service.pem" not in str(excinfo.value) and "the key file" in str(excinfo.value)


# -------------------------------------------------------------------------------------
# preflight and the loader cannot disagree
# -------------------------------------------------------------------------------------
class TestPreflightEqualsLoader:
    def test_the_verdicts_match_for_every_case(self, tmp_path):
        cases = {"good": make_key(tmp_path), **bad_cases(tmp_path)}
        for name, path in cases.items():
            try:
                SigningKey.load(path)
                loader_accepts = True
            except UnsafeSigningKeyError:
                loader_accepts = False
            report = run_preflight({}, key_file=path)
            perm = [c.status for c in report.checks if c.name == "key.permissions"]
            assert perm == (["ok"] if loader_accepts else ["fail"]), name
            assert report.counter_signing is loader_accepts, name
            assert (key_file_problems(path) == []) is loader_accepts, name

    def test_a_refused_key_is_reported_as_unsafe_and_never_loaded(self, tmp_path):
        path = make_key(tmp_path, file_mode=0o644)
        report = run_preflight({}, key_file=path)
        load = [c for c in report.checks if c.name == "key.load"]
        assert load and load[0].status == "fail"
        assert "attestation_key_unsafe" in load[0].detail
        assert not report.service_fingerprint


# -------------------------------------------------------------------------------------
# the API path
# -------------------------------------------------------------------------------------
@pytest.fixture()
def api(tmp_path, monkeypatch):
    for name in ("ASSURANCE_ATTEST_KEY", "ASSURANCE_ATTEST_KEY_PEM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as client:
        yield client, monkeypatch


HEAD = {"ledger_length": 1, "head_seq": 1, "head_link_hash": hashlib.sha256(b"h").hexdigest()}


class TestApiRefusesUnsafeKey:
    def test_a_0644_key_is_503_attestation_key_unsafe_on_both_routes(self, api, tmp_path):
        client, monkeypatch = api
        path = make_key(tmp_path, file_mode=0o644)
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(path))
        get = client.get("/v1/ledger/attest/key")
        post = client.post("/v1/ledger/attest", json=HEAD, headers={"X-API-Key": OPERATOR_KEY})
        for response in (get, post):
            assert response.status_code == 503
            detail = response.json()["detail"]
            assert detail["error"] == "attestation_key_unsafe"
            assert str(tmp_path) not in response.text and "service.pem" not in response.text
            assert "chmod 600" in detail["detail"]
            assert "PRIVATE KEY" not in response.text
        logs = tmp_path / "attestations"
        assert not logs.exists() or not list(logs.iterdir()), "it signed with an unsafe key"

    @pytest.mark.parametrize("case", ["group-writable parent", "sticky world-writable parent",
                                      "symlink", "group-readable file"])
    def test_other_unsafe_states_are_the_same_503(self, api, tmp_path, case):
        client, monkeypatch = api
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(bad_cases(tmp_path)[case]))
        response = client.get("/v1/ledger/attest/key")
        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "attestation_key_unsafe"
        assert str(tmp_path) not in response.text

    def test_no_key_and_an_unusable_key_keep_their_own_codes(self, api, tmp_path):
        client, monkeypatch = api
        assert client.get("/v1/ledger/attest/key").json()["detail"]["error"] == (
            "no_attestation_key_configured")
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(tmp_path / "missing.pem"))
        assert client.get("/v1/ledger/attest/key").json()["detail"]["error"] == (
            "attestation_key_unusable")
        garbage = make_key(tmp_path)
        garbage.write_text("not a key\n")
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(garbage))
        assert client.get("/v1/ledger/attest/key").json()["detail"]["error"] == (
            "attestation_key_unusable")

    def test_a_safe_key_still_signs(self, api, tmp_path):
        client, monkeypatch = api
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(make_key(tmp_path)))
        assert client.get("/v1/ledger/attest/key").status_code == 200
        assert client.post("/v1/ledger/attest", json=HEAD,
                           headers={"X-API-Key": OPERATOR_KEY}).status_code == 200

    def test_the_supplier_and_machine_clis_use_the_same_loader(self):
        """Their ``SigningKey.load`` calls are unchanged; the rule lives in the loader."""
        from assurance.machine import cli as machine_cli
        from assurance.supplier import cli as supplier_cli

        for module in (machine_cli, supplier_cli):
            source = inspect.getsource(module)
            assert "SigningKey.load(" in source and "check_permissions" not in source
