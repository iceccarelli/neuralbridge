"""Key history: which public keys signed, and when each was in force.

After a rotation a verifier holding only today's key called every earlier genuine anchor
"foreign" (exit 1), ``choose_anchor`` found no anchor for any account, and ``anchor-all`` refused
every log. ``assurance.attest.keyset.v1`` is the public-key-only file that carries the history;
the key that checks an anchor is chosen BY THE FINGERPRINT it names.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta

import pytest

from assurance.attest import AttestationLog, SigningKey, attest
from assurance.attest.anchor import choose_anchor
from assurance.attest.anchor_all import anchor_all
from assurance.attest.keyset import KEYSET_FORMAT, Keyset, KeysetError
from assurance.cli import main as cli_main
from assurance.core import Actor, Evidence, Origin
from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.evidence import EvidenceLedger
from assurance.evidence.verify_export import ANCHORED, verify_export


def _ev(n: int) -> Evidence:
    return Evidence(kind="t.record", body={"n": n}, actor=Actor("a.person", "engineer"),
                    origin=Origin("unit-test")).seal()


def _t(base, **delta) -> str:
    return format_utc(base + timedelta(**delta))


class Rotation:
    """K1 signs (attestation 1), is retired; K2 signs onto the same log (attestation 2, rotating)."""

    def __init__(self, root):
        self.root = root
        self.ledger = EvidenceLedger(root / "l.db")
        for i in range(4):
            self.ledger.append(_ev(i), subject="CASE")
        self.k1, self.k2 = SigningKey.generate(), SigningKey.generate()
        self.log = AttestationLog(root / "log.jsonl")
        t0 = utc_now()
        self.t0 = t0
        self.first = attest(self.ledger, self.k1, self.log, now=t0 + timedelta(seconds=5))
        for i in range(4, 6):
            self.ledger.append(_ev(i), subject="CASE")
        self.second = attest(self.ledger, self.k2, self.log, rotating=True,
                             now=t0 + timedelta(hours=2))
        self.pub1 = self.pub(self.k1, "k1.pub")
        self.pub2 = self.pub(self.k2, "k2.pub")
        self.retired_at = _t(t0, hours=1)

    def pub(self, key, name):
        path = self.root / name
        path.write_text(key.verifying.pem(), encoding="utf-8")
        return path

    def keyset(self, *, k1="retired", k1_from=None, k1_until=None, k2_from=None,
               name="ks.json"):
        entries = [
            self._entry(self.k1, k1, k1_from or _t(self.t0, days=-30),
                        k1_until if k1_until is not None else
                        (self.retired_at if k1 == "retired" else None), "first era"),
            self._entry(self.k2, "active", k2_from or self.retired_at, None, "second era")]
        doc = {"format": KEYSET_FORMAT, "keys": entries}
        path = self.root / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    @staticmethod
    def _entry(key, status, start, until, label):
        e = {"fingerprint": key.fingerprint, "public_key_pem": key.verifying.pem(),
             "status": status, "effective_from": start, "label": label}
        if until:
            e["effective_until"] = until
        return e

    def bundle(self, anchor, name="b.json"):
        path = self.root / name
        path.write_text(json.dumps(self.ledger.export(anchor=anchor.to_dict())),
                        encoding="utf-8")
        return str(path)


@pytest.fixture()
def rot(tmp_path):
    return Rotation(tmp_path)


def _verify(*args):
    return cli_main(["evidence", "verify", *args])


class TestAfterARotation:
    def test_one_key_still_calls_the_earlier_era_foreign_exactly_as_before(self, rot, capsys):
        assert _verify(rot.bundle(rot.first), "--public-key", str(rot.pub2)) == 1
        assert "foreign anchor" in capsys.readouterr().out

    def test_a_keyset_checks_each_anchor_under_the_key_it_names(self, rot, capsys):
        ks = str(rot.keyset())
        # the older era's anchor leaves 2 records unsigned: checked, but only partly anchored
        assert _verify(rot.bundle(rot.first), "--keyset", ks) == 3
        assert capsys.readouterr().out.startswith("CONSISTENT, SIGNED ONLY UP TO seq 4")
        assert _verify(rot.bundle(rot.second), "--keyset", ks) == 0
        assert capsys.readouterr().out.startswith("VERIFIED — anchored to a signed head")
        r = verify_export(json.loads(open(rot.bundle(rot.second)).read()),
                          keyset=Keyset.load(ks))
        assert r.ok and r.completeness == ANCHORED
        assert rot.k2.fingerprint in " ".join(r.verified)

    def test_two_public_keys_are_a_keyset_without_history(self, rot, capsys):
        assert _verify(rot.bundle(rot.second), "--public-key", str(rot.pub1),
                       "--public-key", str(rot.pub2)) == 0
        capsys.readouterr()

    def test_an_unlisted_fingerprint_is_not_established_never_foreign_never_ok(self, rot, capsys):
        only_k1 = rot.root / "only1.json"
        only_k1.write_text(json.dumps({"format": KEYSET_FORMAT, "keys": [
            rot._entry(rot.k1, "active", _t(rot.t0, days=-30), None, "")]}))
        r = verify_export(json.loads(open(rot.bundle(rot.second)).read()),
                          keyset=Keyset.load(only_k1))
        assert not r.ok and r.problems == () and r.completeness != ANCHORED
        assert any("not in your keyset" in u for u in r.unestablished), r.unestablished
        assert _verify(rot.bundle(rot.second), "--keyset", str(only_k1)) == 3
        assert "NOT ESTABLISHED" in capsys.readouterr().out

    def test_a_revoked_key_is_a_problem_whatever_date_the_anchor_carries(self, rot, capsys):
        ks = rot.keyset(k1="revoked", k1_until=rot.retired_at)
        assert _verify(rot.bundle(rot.first), "--keyset", str(ks)) == 1
        assert "REVOKED" in capsys.readouterr().out

    def test_a_retired_key_signing_after_retirement_is_a_problem(self, rot, capsys):
        early = rot.keyset(k1_until=_t(rot.t0, seconds=1))        # retired before it signed
        assert _verify(rot.bundle(rot.first), "--keyset", str(early)) == 1
        assert "after key" in capsys.readouterr().out

    def test_a_key_not_yet_in_force_is_a_problem(self, rot, capsys):
        late = rot.keyset(k1_from=_t(rot.t0, hours=1), k1_until=_t(rot.t0, hours=3))
        assert _verify(rot.bundle(rot.first), "--keyset", str(late)) == 1
        assert "before key" in capsys.readouterr().out

    def test_the_key_is_chosen_by_fingerprint_not_tried_in_turn(self, rot):
        """An anchor that NAMES k1 but was signed by k2 must not verify just because k2 is listed."""
        doc = json.loads(open(rot.bundle(rot.second)).read())
        doc["anchor"]["key_fingerprint"] = rot.k1.fingerprint
        wide = rot.keyset(k1="active", k2_from=_t(rot.t0, days=-30))
        r = verify_export(doc, keyset=Keyset.load(wide))
        assert not r.ok and any("signature does not verify" in p for p in r.problems)

    def test_expect_fingerprint_with_a_keyset(self, rot, capsys):
        ks = str(rot.keyset())
        bundle = rot.bundle(rot.second)
        assert _verify(bundle, "--keyset", ks, "--expect-fingerprint", rot.k2.fingerprint,
                       "--expect-fingerprint", rot.k1.fingerprint) == 0
        # the anchor's signer (k2) is not among the keys you wrote down
        assert _verify(bundle, "--keyset", ks, "--expect-fingerprint", rot.k1.fingerprint) == 1
        # you expected a key the keyset does not hold
        assert _verify(bundle, "--keyset", ks, "--expect-fingerprint", "0" * 16) == 1
        capsys.readouterr()

    def test_a_key_given_twice_is_a_usage_error(self, rot, capsys):
        assert _verify(rot.bundle(rot.second), "--keyset", str(rot.keyset()),
                       "--public-key", str(rot.pub2)) == 2
        assert "given twice" in capsys.readouterr().err

    def test_a_keyset_is_never_read_from_the_bundle(self, rot):
        doc = json.loads(open(rot.bundle(rot.second)).read())
        doc["keyset"] = rot.keyset().read_text()
        assert not verify_export(doc, keyset=Keyset.load(rot.keyset())).ok

    def test_trusted_key_and_keyset_together_are_refused(self, rot):
        with pytest.raises(ValueError, match="not both"):
            verify_export({}, trusted_key=rot.k1.verifying, keyset=Keyset.load(rot.keyset()))


class TestAttestVerifyAndChooseAnchor:
    def test_attest_verify_spans_the_rotation_with_a_keyset(self, rot, capsys):
        base = ["attest", "verify", "--log", str(rot.log.path)]
        assert cli_main([*base, "--public-key", str(rot.pub2)]) == 1          # one key: as before
        capsys.readouterr()
        assert cli_main([*base, "--keyset", str(rot.keyset())]) == 0
        capsys.readouterr()
        assert cli_main([*base, "--keyset", str(rot.keyset(k1="revoked"))]) == 1
        assert "REVOKED" in capsys.readouterr().out
        assert cli_main([*base, "--keyset", str(rot.keyset(k1_until=_t(rot.t0, seconds=1)))]) == 1
        capsys.readouterr()

    def test_attest_verify_needs_some_key(self, rot, capsys):
        assert cli_main(["attest", "verify", "--log", str(rot.log.path)]) == 2
        capsys.readouterr()

    def test_choose_anchor_after_a_rotation(self, rot):
        records = rot.log.read()
        assert choose_anchor(records, rot.k2.verifying).anchor is None      # as before
        got = choose_anchor(records, Keyset.load(rot.keyset()))
        assert got.anchor is not None and got.anchor["sequence"] == 2
        assert choose_anchor(records, Keyset.load(rot.keyset(k1="revoked"))).anchor is None


class TestAnchorAllAfterARotation:
    def _data(self, rot, tmp_path):
        data = tmp_path / "data"
        (data / "tenants").mkdir(parents=True)
        (data / "attestations").mkdir()
        led = EvidenceLedger(data / "tenants" / "acc_0123456789abcdef.db")
        for i in range(3):
            led.append(_ev(i), subject="X")
        log = AttestationLog(data / "attestations" / "acc_0123456789abcdef.jsonl")
        attest(led, rot.k1, log, now=rot.t0 - timedelta(days=3))
        return data, led, log

    def test_without_rotating_every_log_is_refused_as_before(self, rot, tmp_path):
        data, _, log = self._data(rot, tmp_path)
        report = anchor_all(data, rot.k2)
        assert report.exit_code == 1 and report.count("refused") == 1
        assert len(log.read()) == 1

    def test_rotating_needs_a_keyset_because_freshness_cannot_otherwise_be_judged(
            self, rot, tmp_path):
        data, _, log = self._data(rot, tmp_path)
        with pytest.raises(ValueError, match="--rotating needs --keyset"):
            anchor_all(data, rot.k2, rotating=True)
        assert len(log.read()) == 1

    def test_the_signing_key_must_be_active_in_the_keyset(self, rot, tmp_path):
        data, _, log = self._data(rot, tmp_path)
        with pytest.raises(ValueError, match="not an `active` key"):
            anchor_all(data, rot.k1, keyset=Keyset.load(rot.keyset()), rotating=True)
        assert len(log.read()) == 1

    def test_rotating_with_a_keyset_continues_the_log_and_then_leaves_it_alone(
            self, rot, tmp_path):
        data, _, log = self._data(rot, tmp_path)
        ks = Keyset.load(rot.keyset())
        first = anchor_all(data, rot.k2, keyset=ks, rotating=True,
                           now=parse_utc(rot.second.attested_at))
        assert first.exit_code == 0 and first.count("anchored") == 1, first.outcomes
        assert [r.key_fingerprint for r in log.read()] == [
            rot.k1.fingerprint, rot.k2.fingerprint]
        again = anchor_all(data, rot.k2, keyset=ks, rotating=True,
                           now=parse_utc(rot.second.attested_at))
        assert again.count("fresh") == 1 and len(log.read()) == 2     # no record per run


class TestAnchorAllRefusesALogItCannotVerify:
    def test_a_keyset_missing_an_earlier_era_refuses_and_appends_nothing(self, rot, tmp_path):
        data = tmp_path / "data"
        (data / "tenants").mkdir(parents=True)
        (data / "attestations").mkdir()
        led = EvidenceLedger(data / "tenants" / "acc_0123456789abcdef.db")
        for i in range(3):
            led.append(_ev(i), subject="X")
        k0 = SigningKey.generate()
        log = AttestationLog(data / "attestations" / "acc_0123456789abcdef.jsonl")
        attest(led, k0, log, now=rot.t0 - timedelta(days=3))
        before = log.path.read_bytes()
        only_k2 = Keyset.from_keys([rot.k2.verifying])
        for _ in range(4):
            report = anchor_all(data, rot.k2, keyset=only_k2, rotating=True,
                                now=parse_utc(rot.second.attested_at))
            assert report.exit_code == 1 and report.count("refused") == 1
            assert "does not verify under the keyset" in report.outcomes[0].detail
            assert report.count("anchored") == 0
        assert log.path.read_bytes() == before            # not one record was appended
        dry = anchor_all(data, rot.k2, keyset=only_k2, rotating=True, dry_run=True,
                         now=parse_utc(rot.second.attested_at))
        assert dry.exit_code == 1


class TestKeysetCli:
    def test_add_then_check_round_trips_and_refuses_a_wrong_fingerprint(self, rot, capsys):
        ks = rot.root / "built.json"
        add = ["attest", "keyset", "add", "--keyset", str(ks)]
        assert cli_main([*add, "--public-key", str(rot.pub1), "--fingerprint",
                         rot.k1.fingerprint, "--status", "retired",
                         "--effective-from", _t(rot.t0, days=-30),
                         "--effective-until", rot.retired_at, "--label", "first era"]) == 0
        assert cli_main([*add, "--public-key", str(rot.pub2), "--fingerprint",
                         rot.k2.fingerprint, "--status", "active",
                         "--effective-from", rot.retired_at]) == 0
        assert cli_main([*add, "--public-key", str(rot.pub2), "--fingerprint",
                         rot.k1.fingerprint, "--status", "active",
                         "--effective-from", rot.retired_at]) == 2          # not that key's
        capsys.readouterr()
        assert cli_main(["attest", "keyset", "check", "--keyset", str(ks)]) == 0
        out = capsys.readouterr().out
        assert "no private key material" in out and rot.k1.fingerprint in out
        assert _verify(rot.bundle(rot.second), "--keyset", str(ks)) == 0
        capsys.readouterr()
        # adding a retired key without its end date is refused and leaves the file as it was
        before = ks.read_text()
        assert cli_main([*add, "--public-key", str(rot.pub1), "--fingerprint",
                         rot.k1.fingerprint, "--status", "retired",
                         "--effective-from", rot.retired_at]) == 2
        assert ks.read_text() == before
        capsys.readouterr()


class TestTheLoaderFailsClosed:
    def _doc(self, rot):
        return json.loads(rot.keyset().read_text())

    def _load(self, rot, doc):
        path = rot.root / "x.json"
        path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
        return Keyset.load(path)

    def test_the_valid_file_loads(self, rot):
        ks = Keyset.load(rot.keyset())
        assert ks.fingerprints == tuple(sorted([rot.k1.fingerprint, rot.k2.fingerprint]))
        assert Keyset.from_dict(ks.to_dict()).fingerprints == ks.fingerprints

    @pytest.mark.parametrize("name,edit,message", [
        ("unknown top field", lambda d: d.update(extra=1), "does not define"),
        ("unknown key field", lambda d: d["keys"][0].update(secret="x"), "does not define"),  # noqa: S106
        ("other version", lambda d: d.update(format="assurance.attest.keyset.v2"), "unsupported"),
        ("no version", lambda d: d.pop("format"), "unsupported"),
        ("empty", lambda d: d.update(keys=[]), "no keys"),
        ("keys not a list", lambda d: d.update(keys={}), "must be a list"),
        ("status", lambda d: d["keys"][0].update(status="trusted"), "status must be"),
        ("type", lambda d: d["keys"][0].update(fingerprint=5), "must be text"),
        ("fingerprint form", lambda d: d["keys"][0].update(fingerprint="ABCD"), "16 lower-case"),
        ("fingerprint is not the key's",
         lambda d: d["keys"][0].update(fingerprint="0" * 16), "is not the key's"),
        ("duplicate key", lambda d: d["keys"].append(dict(d["keys"][0])), "given twice"),
        ("bad time", lambda d: d["keys"][0].update(effective_from="2026-01-01"), "YYYY-MM-DD"),
        ("not a date", lambda d: d["keys"][0].update(effective_from="2026-13-45T00:00:00Z"),
         "not a real date"),
        ("empty window", lambda d: d["keys"][0].update(effective_until=d["keys"][0][
            "effective_from"]), "not after"),
        ("retired without end", lambda d: d["keys"][0].pop("effective_until"), "needs effective_until"),
        ("active with an end", lambda d: d["keys"][1].update(effective_until="2099-01-01T00:00:00Z"),
         "no end"),
        ("label type", lambda d: d["keys"][0].update(label=3), "label"),
        ("garbage key", lambda d: d["keys"][0].update(public_key_pem="nope"), "PEM"),
    ])
    def test_each_refusal(self, rot, name, edit, message):
        doc = self._doc(rot)
        edit(doc)
        with pytest.raises(KeysetError, match=message):
            self._load(rot, doc)

    def test_private_key_material_refuses_the_whole_file(self, rot):
        from cryptography.hazmat.primitives import serialization

        pem = rot.k1.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        for where in ("label", "extra", "escaped"):
            doc = self._doc(rot)
            if where == "label":
                doc["keys"][0]["label"] = pem
            elif where == "extra":
                doc["private_key"] = pem
            text = json.dumps(doc)
            if where == "escaped":
                text = text.replace('"first era"', '"-----BEGIN \\u0050RIVATE KEY-----"')
            with pytest.raises(KeysetError, match="private key material") as exc:
                self._load(rot, text)
            assert pem.splitlines()[1] not in str(exc.value)

    def test_a_repeated_json_name_is_refused(self, rot):
        text = json.dumps(self._doc(rot))
        with pytest.raises(KeysetError, match="repeats the name"):
            self._load(rot, '{"format": "x", ' + text[1:])

    def test_not_json_not_utf8_too_big_and_missing(self, rot):
        with pytest.raises(KeysetError, match="not valid JSON"):
            self._load(rot, "{")
        bad = rot.root / "bad.json"
        bad.write_bytes(b"\xff\xfe")
        with pytest.raises(KeysetError, match="UTF-8"):
            Keyset.load(bad)
        with pytest.raises(KeysetError, match="too large"):
            self._load(rot, " " * (300 * 1024))
        with pytest.raises(KeysetError, match="cannot be read"):
            Keyset.load(rot.root / "nope.json")

    def test_a_non_ed25519_key_is_refused(self, rot):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        doc = self._doc(rot)
        doc["keys"][0]["public_key_pem"] = pem
        with pytest.raises(KeysetError, match="Ed25519"):
            self._load(rot, doc)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_a_saved_keyset_is_a_plain_public_file(rot):
    path = Keyset.load(rot.keyset()).save(rot.root / "saved.json")
    assert (path.stat().st_mode & 0o777) == 0o644
    assert "PRIVATE" not in path.read_text().upper()
