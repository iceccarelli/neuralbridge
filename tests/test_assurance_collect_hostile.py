"""Collection against a folder nobody trusts.

A customer's export folder is data from a laptop that has been through a vendor
tool, a USB stick and a technician. The collector's duty is narrow and absolute:
it may report a digest, or it may report that it could not — INCOMPLETE — and it
may never report a clean-looking digest for something it did not fully read.
Every case here is a way an item could come out looking collected when it was
not, or a way a hostile file could hang or exhaust the process doing the reading.
"""

from __future__ import annotations

import json
import os
import struct
import zipfile
from pathlib import Path

import pytest

import assurance.collect.collector as collector_mod
import assurance.collect.normalise as normalise_mod
from assurance.collect.collector import CollectionError, collect
from assurance.collect.normalise import (
    NormalisationError,
    Normaliser,
    Rule,
    normalise_bytes,
    normalise_file,
)
from assurance.collect.plan import CollectionPlan, ItemSpec, VersionSource
from assurance.collect.volatility import probe
from assurance.core.evidence import Actor
from assurance.machinery.manifest import ItemKind, SafetyFunction

ENG = Actor("a.integrator", "safety engineer")

FUNCS = (SafetyFunction("SF-01", "Protective stop", "PL d", verified_by=("speed_limit",)),)


def spec(item_id="ITM-A", source="a.cfg", rule=None, required=True, **kw):
    return ItemSpec(item_id=item_id, kind=ItemKind.SAFETY_CONFIGURATION, name=item_id,
                    source=source, supplier="S", implements=("SF-01",),
                    rule=rule or Rule(), required=required, **kw)


def plan(*items):
    return CollectionPlan(plan_id="P", manufacturer="M", model="X", items=items,
                          functions=FUNCS)


def run(p, root, **kw):
    return collect(p, root, serial="1", taken_by=ENG, **kw)


def zip_with(path: Path, members: dict[str, bytes], extra=None):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
        for name, data in (extra or []):
            z.writestr(name, data)
    return path


ZIP_RULE = Rule(kind=Normaliser.ZIP_MEMBERS, members=("main.st",), note="build noise")


# =====================================================================
# "a rule that drops bytes must carry a note" — and mean it
# =====================================================================

class TestTheNoteIsEnforced:
    @pytest.mark.parametrize("kind,extra", [
        (Normaliser.TEXT_EXCLUDING, {"patterns": ("^#",)}),
        (Normaliser.JSON_EXCLUDING, {"keys": ("a",)}),
        (Normaliser.ZIP_MEMBERS, {"members": ("m",)}),
    ])
    @pytest.mark.parametrize("note", ["", "   ", "\n\t"])
    def test_every_dropping_rule_refuses_an_empty_or_blank_note(self, kind, extra, note):
        with pytest.raises(NormalisationError, match="note"):
            Rule(kind=kind, note=note, **extra)

    @pytest.mark.parametrize("payload", [
        {"kind": "text_excluding", "patterns": ["^#"]},
        {"kind": "json_excluding", "keys": ["a"]},
        {"kind": "zip_members", "members": ["m"]},
    ])
    def test_a_rule_loaded_from_a_plan_file_is_held_to_it_too(self, payload):
        with pytest.raises(NormalisationError, match="note"):
            Rule.from_dict(payload)

    def test_a_raw_rule_carrying_patterns_would_claim_a_drop_it_does_not_make(self):
        """raw hashes every byte. A pattern list on it is a rule that looks like it
        excludes something and does not, and it would change the fingerprint."""
        with pytest.raises(NormalisationError, match="raw"):
            Rule(kind=Normaliser.RAW, patterns=("^#",))

    def test_a_raw_rule_carrying_keys_or_members_is_refused(self):
        with pytest.raises(NormalisationError, match="raw"):
            Rule(kind=Normaliser.RAW, keys=("a",))
        with pytest.raises(NormalisationError, match="raw"):
            Rule(kind=Normaliser.RAW, members=("a",))

    def test_the_plan_hash_moves_when_a_note_is_added_to_the_plan(self):
        a = plan(spec(rule=Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=("^#",),
                                note="stamp")))
        b = plan(spec(rule=Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=("^#",),
                                note="a different reason")))
        assert a.content_hash() != b.content_hash()      # the note is on the record

    def test_an_unknown_encoding_is_refused_at_declaration_not_at_hash_time(self):
        with pytest.raises(NormalisationError, match="encoding"):
            Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=("^#",), note="x",
                 encoding="klingon-8")

    def test_an_unsafe_archive_member_name_is_refused_at_declaration(self):
        for bad in ("../evil", "/etc/passwd", "a/../../b", "a\\b", "a\x00b"):
            with pytest.raises(NormalisationError, match="member"):
                Rule(kind=Normaliser.ZIP_MEMBERS, members=(bad,), note="x")


# =====================================================================
# the archive
# =====================================================================

class TestHostileArchives:
    def test_a_member_listed_twice_is_refused_because_two_readers_would_differ(
            self, tmp_path):
        p = tmp_path / "a.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("main.st", b"BENIGN")
            with pytest.warns(UserWarning):
                z.writestr("main.st", b"HOSTILE")
        with pytest.raises(NormalisationError, match="more than once"):
            normalise_file(p, ZIP_RULE)

    def test_a_duplicated_member_nobody_declared_does_not_matter(self, tmp_path):
        p = tmp_path / "a.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("main.st", b"CODE")
            z.writestr("junk.txt", b"1")
            with pytest.warns(UserWarning):
                z.writestr("junk.txt", b"2")
        assert normalise_file(p, ZIP_RULE).digest

    def test_a_symlink_member_is_refused_not_hashed_as_its_target_name(self, tmp_path):
        p = tmp_path / "a.zip"
        with zipfile.ZipFile(p, "w") as z:
            info = zipfile.ZipInfo("main.st")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            z.writestr(info, b"/etc/passwd")
        with pytest.raises(NormalisationError, match="symbolic link"):
            normalise_file(p, ZIP_RULE)

    def test_a_declared_directory_is_refused(self, tmp_path):
        p = tmp_path / "a.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr(zipfile.ZipInfo("main.st/"), b"")
        rule = Rule(kind=Normaliser.ZIP_MEMBERS, members=("main.st/",), note="x")
        with pytest.raises(NormalisationError, match="directory"):
            normalise_file(p, rule)

    def test_a_traversal_named_entry_is_never_extracted_or_followed(self, tmp_path):
        """Nothing is ever extracted, so '../evil' cannot write; it is also not
        silently ignored when it is the thing a rule names (refused at declaration)."""
        p = zip_with(tmp_path / "a.zip", {"main.st": b"CODE"},
                     extra=[("../evil.txt", b"pwned")])
        before = set(os.listdir(tmp_path))
        assert normalise_file(p, ZIP_RULE).digest
        assert set(os.listdir(tmp_path)) == before
        assert not (tmp_path.parent / "evil.txt").exists()

    def test_a_member_declared_larger_than_the_cap_is_refused_before_it_is_read(
            self, tmp_path, monkeypatch):
        p = zip_with(tmp_path / "a.zip", {"main.st": b"x" * 5000})
        monkeypatch.setattr(normalise_mod, "MAX_ARCHIVE_MEMBER_BYTES", 1000)
        with pytest.raises(NormalisationError, match="too large|exceeds"):
            normalise_file(p, ZIP_RULE)

    def test_the_total_of_the_declared_members_is_capped_too(self, tmp_path, monkeypatch):
        p = zip_with(tmp_path / "a.zip", {"a": b"x" * 600, "b": b"y" * 600})
        monkeypatch.setattr(normalise_mod, "MAX_ARCHIVE_TOTAL_BYTES", 1000)
        rule = Rule(kind=Normaliser.ZIP_MEMBERS, members=("a", "b"), note="x")
        with pytest.raises(NormalisationError, match="total"):
            normalise_file(p, rule)

    def test_a_real_bomb_is_refused_without_inflating_it(self, tmp_path, monkeypatch):
        """50 MB of zeros compresses to ~50 kB. The declared size says so up front."""
        p = tmp_path / "bomb.zip"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("main.st", b"\0" * 50_000_000)
        assert p.stat().st_size < 200_000
        monkeypatch.setattr(normalise_mod, "MAX_ARCHIVE_MEMBER_BYTES", 10_000_000)
        with pytest.raises(NormalisationError):
            normalise_file(p, ZIP_RULE)

    def test_a_forged_small_declared_size_cannot_make_the_reader_inflate_more(
            self, tmp_path, monkeypatch):
        """The central directory says 10 bytes; the stream holds 10 MB. The reader
        stops at the declared size, so the digest is of what was declared."""
        p = tmp_path / "lie.zip"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("main.st", b"A" * 10_000_000)
        raw = bytearray(p.read_bytes())
        # patch the file_size field in both headers to 10
        local = raw.find(b"PK\x03\x04")
        central = raw.find(b"PK\x01\x02")
        struct.pack_into("<I", raw, local + 22, 10)
        struct.pack_into("<I", raw, central + 24, 10)
        p.write_bytes(bytes(raw))
        monkeypatch.setattr(normalise_mod, "MAX_ARCHIVE_MEMBER_BYTES", 1000)
        try:
            r = normalise_file(p, ZIP_RULE)
        except NormalisationError:
            return          # refused: fine
        assert r.bytes_hashed <= 1000

    def test_an_encrypted_member_is_refused_not_crashed_on(self, tmp_path):
        p = zip_with(tmp_path / "a.zip", {"main.st": b"CODE"})
        raw = bytearray(p.read_bytes())
        local = raw.find(b"PK\x03\x04")
        central = raw.find(b"PK\x01\x02")
        raw[local + 6] |= 0x01
        raw[central + 8] |= 0x01
        p.write_bytes(bytes(raw))
        with pytest.raises(NormalisationError, match="encrypted"):
            normalise_file(p, ZIP_RULE)

    def test_a_corrupt_member_is_refused_not_crashed_on(self, tmp_path):
        p = tmp_path / "a.zip"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_STORED) as z:
            z.writestr("main.st", b"CODECODECODE")
        raw = bytearray(p.read_bytes())
        i = raw.find(b"CODECODECODE")
        raw[i + 2] ^= 0xFF                   # flip a byte: the CRC no longer matches
        p.write_bytes(bytes(raw))
        with pytest.raises(NormalisationError, match="CRC|corrupt|read"):
            normalise_file(p, ZIP_RULE)

    def test_a_truncated_archive_is_refused(self, tmp_path):
        p = zip_with(tmp_path / "a.zip", {"main.st": b"CODE" * 100})
        p.write_bytes(p.read_bytes()[:-30])
        with pytest.raises(NormalisationError):
            normalise_file(p, ZIP_RULE)

    def test_an_archive_with_an_absurd_number_of_entries_is_refused(
            self, tmp_path, monkeypatch):
        p = zip_with(tmp_path / "a.zip", {f"f{i}": b"x" for i in range(20)} | {
            "main.st": b"CODE"})
        monkeypatch.setattr(normalise_mod, "MAX_ARCHIVE_ENTRIES", 10)
        with pytest.raises(NormalisationError, match="entries"):
            normalise_file(p, ZIP_RULE)

    def test_a_declared_member_that_is_missing_makes_the_result_incomplete(
            self, tmp_path):
        p = zip_with(tmp_path / "a.zip", {"other": b"x"})
        r = normalise_file(p, ZIP_RULE)
        assert not r.complete
        assert any("is not in the archive" in w for w in r.warnings)

    def test_a_non_zip_file_under_a_zip_rule_is_refused(self, tmp_path):
        p = tmp_path / "a.zip"
        p.write_bytes(b"this is not a zip")
        with pytest.raises(NormalisationError, match="archive"):
            normalise_file(p, ZIP_RULE)


# =====================================================================
# text and JSON
# =====================================================================

TEXT_RULE = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=("^#",), note="stamp")
JSON_RULE = Rule(kind=Normaliser.JSON_EXCLUDING, keys=("export.ts",), note="stamp")


class TestHostileText:
    def test_a_file_over_the_text_cap_is_refused_not_read(self, tmp_path, monkeypatch):
        p = tmp_path / "t.cfg"
        p.write_bytes(b"x" * 5000)
        monkeypatch.setattr(normalise_mod, "MAX_TEXT_BYTES", 1000)
        with pytest.raises(NormalisationError, match="too large|exceeds"):
            normalise_file(p, TEXT_RULE)

    def test_one_endless_line_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(normalise_mod, "MAX_LINE_CHARS", 100)
        with pytest.raises(NormalisationError, match="line"):
            normalise_bytes(b"a" * 1000, TEXT_RULE)

    def test_a_text_file_whose_every_line_is_dropped_is_not_a_digest(self):
        r = normalise_bytes(b"# a\n# b\n", TEXT_RULE)
        assert r.dropped_everything
        assert not r.usable

    def test_unicode_line_separators_stay_inside_a_line(self):
        """splitlines() broke on form feed and U+2028, so changing one into a
        newline changed nothing. Only CR, LF and CRLF are line ends."""
        a = normalise_bytes(b"A\x0cB\n", TEXT_RULE).digest
        b = normalise_bytes(b"A\nB\n", TEXT_RULE).digest
        c = normalise_bytes("A B\n".encode(), TEXT_RULE).digest
        assert len({a, b, c}) == 3

    def test_crlf_lf_and_cr_are_one_text(self):
        digs = {normalise_bytes(t, TEXT_RULE).digest
                for t in (b"a\nb\n", b"a\r\nb\r\n", b"a\rb\r")}
        assert len(digs) == 1

    def test_a_binary_file_under_a_text_rule_is_refused(self, tmp_path):
        p = tmp_path / "t.bin"
        p.write_bytes(b"\xff\xfe\x00\x01binary")
        with pytest.raises(NormalisationError, match="binary"):
            normalise_file(p, TEXT_RULE)

    def test_a_bom_is_not_silently_stripped(self):
        with_bom = normalise_bytes(b"\xef\xbb\xbfa\n", TEXT_RULE).digest
        without = normalise_bytes(b"a\n", TEXT_RULE).digest
        assert with_bom != without

    def test_a_utf16_file_needs_the_utf16_encoding_declared(self, tmp_path):
        p = tmp_path / "t.cfg"
        p.write_bytes("a\nb\n".encode("utf-16"))
        with pytest.raises(NormalisationError):
            normalise_file(p, TEXT_RULE)
        ok = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=("^#",), note="x",
                  encoding="utf-16")
        assert normalise_file(p, ok).digest


class TestHostileJson:
    def test_duplicate_keys_are_refused_because_one_of_them_would_vanish(self):
        with pytest.raises(NormalisationError, match="duplicate"):
            normalise_bytes(b'{"limit": 100, "limit": 900}', JSON_RULE)

    def test_a_nested_duplicate_is_refused_too(self):
        with pytest.raises(NormalisationError, match="duplicate"):
            normalise_bytes(b'{"a": {"x": 1, "x": 2}}', JSON_RULE)

    def test_deep_nesting_is_an_error_not_a_crash(self):
        deep = b"[" * 50_000 + b"]" * 50_000
        with pytest.raises(NormalisationError):
            normalise_bytes(deep, JSON_RULE)

    def test_a_huge_integer_is_an_error_not_a_crash(self):
        with pytest.raises(NormalisationError):
            normalise_bytes(b'{"a": ' + b"9" * 20000 + b"}", JSON_RULE)

    @pytest.mark.parametrize("const", [b"NaN", b"Infinity", b"-Infinity"])
    def test_non_standard_constants_are_refused(self, const):
        with pytest.raises(NormalisationError, match="constant|JSON"):
            normalise_bytes(b'{"a": ' + const + b"}", JSON_RULE)

    def test_a_non_utf8_json_file_is_refused(self):
        with pytest.raises(NormalisationError):
            normalise_bytes(b"\xff\xfe{}", JSON_RULE)

    def test_a_json_file_over_the_cap_is_refused(self, tmp_path, monkeypatch):
        p = tmp_path / "j.json"
        p.write_bytes(b'{"a": "' + b"x" * 5000 + b'"}')
        monkeypatch.setattr(normalise_mod, "MAX_TEXT_BYTES", 1000)
        with pytest.raises(NormalisationError, match="too large|exceeds"):
            normalise_file(p, JSON_RULE)

    def test_a_missing_key_is_still_a_warning(self):
        r = normalise_bytes(b'{"a": 1}', JSON_RULE)
        assert r.warnings and r.complete

    def test_a_version_read_survives_hostile_json(self):
        v = VersionSource(kind="json", value="a.b")
        assert v.read(b"[" * 50_000) == ""
        assert v.read(b'{"a": {"b": ' + b"9" * 20000 + b"}}") == ""


class TestRawFiles:
    def test_an_empty_file_is_not_a_digest(self, tmp_path):
        p = tmp_path / "fw.bin"
        p.write_bytes(b"")
        r = normalise_file(p, Rule())
        assert r.dropped_everything and not r.usable

    def test_a_raw_file_is_streamed_and_capped(self, tmp_path, monkeypatch):
        p = tmp_path / "fw.bin"
        p.write_bytes(b"x" * 5000)
        monkeypatch.setattr(normalise_mod, "MAX_RAW_BYTES", 1000)
        with pytest.raises(NormalisationError, match="too large|exceeds"):
            normalise_file(p, Rule())

    def test_a_raw_digest_is_the_sha256_of_the_bytes(self, tmp_path):
        import hashlib
        p = tmp_path / "fw.bin"
        data = os.urandom(3_000_000)
        p.write_bytes(data)
        assert normalise_file(p, Rule()).digest == hashlib.sha256(data).hexdigest()

    def test_a_directory_where_a_file_was_expected_is_refused_not_raised(self, tmp_path):
        with pytest.raises(NormalisationError, match="read"):
            normalise_file(tmp_path, Rule())

    def test_a_file_that_vanishes_is_refused_not_raised(self, tmp_path):
        with pytest.raises(NormalisationError, match="read"):
            normalise_file(tmp_path / "gone.bin", Rule())


# =====================================================================
# the collector: INCOMPLETE, never 'unchanged'
# =====================================================================

class TestCollectionReportsIncompleteNotClean:
    def test_an_empty_root_is_refused(self, tmp_path):
        with pytest.raises(CollectionError, match="matched nothing"):
            run(plan(spec()), tmp_path)

    def test_an_item_that_hashed_to_nothing_is_incomplete(self, tmp_path):
        (tmp_path / "a.cfg").write_bytes(b"")
        (tmp_path / "b.cfg").write_bytes(b"x")
        r = run(plan(spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg")), tmp_path)
        assert not r.complete
        assert {o.item_id: o.status for o in r.outcomes} == {
            "ITM-A": "unreadable", "ITM-B": "collected"}
        assert r.manifest.item("ITM-A") is None

    def test_a_zip_missing_its_declared_member_is_incomplete_not_collected(
            self, tmp_path):
        zip_with(tmp_path / "p.zip", {"other": b"x"})
        (tmp_path / "b.cfg").write_bytes(b"x")
        r = run(plan(spec("ITM-P", "p.zip", rule=ZIP_RULE), spec("ITM-B", "b.cfg")),
                tmp_path)
        assert not r.complete
        assert r.manifest.item("ITM-P") is None
        assert any("not in the archive" in o.detail for o in r.outcomes
                   if o.item_id == "ITM-P")

    def test_a_file_that_cannot_be_read_is_unreadable_not_a_crash(
            self, tmp_path, monkeypatch):
        (tmp_path / "a.cfg").write_bytes(b"x")
        (tmp_path / "b.cfg").write_bytes(b"y")
        real_open = Path.open

        def deny(self, *a, **k):
            if self.name == "a.cfg":
                raise PermissionError(13, "Permission denied", str(self))
            return real_open(self, *a, **k)

        monkeypatch.setattr(Path, "open", deny)
        r = run(plan(spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg")), tmp_path)
        assert not r.complete
        assert r.outcomes[0].status == "unreadable"
        assert "read" in r.outcomes[0].detail

    def test_a_symlink_pointing_outside_the_root_is_refused(self, tmp_path):
        outside = tmp_path / "outside.cfg"
        outside.write_bytes(b"secret")
        root = tmp_path / "root"
        root.mkdir()
        (root / "a.cfg").symlink_to(outside)
        (root / "b.cfg").write_bytes(b"x")
        r = run(plan(spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg")), root)
        assert not r.complete
        a = next(o for o in r.outcomes if o.item_id == "ITM-A")
        assert a.status == "unreadable" and "outside" in a.detail

    def test_a_symlink_inside_the_root_is_followed(self, tmp_path):
        (tmp_path / "real.cfg").write_bytes(b"x")
        (tmp_path / "a.cfg").symlink_to(tmp_path / "real.cfg")
        r = run(plan(spec("ITM-A", "a.cfg")), tmp_path)
        assert r.complete

    def test_a_dangling_symlink_is_missing_not_hashed(self, tmp_path):
        (tmp_path / "a.cfg").symlink_to(tmp_path / "nowhere")
        (tmp_path / "b.cfg").write_bytes(b"x")
        r = run(plan(spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg")), tmp_path)
        assert not r.complete
        assert {o.item_id: o.status for o in r.outcomes}["ITM-A"] == "missing"

    def test_too_many_files_for_one_item_is_incomplete(self, tmp_path, monkeypatch):
        for i in range(6):
            (tmp_path / f"f{i}.cfg").write_bytes(b"x")
        (tmp_path / "b.cfg").write_bytes(b"x")
        monkeypatch.setattr(collector_mod, "MAX_FILES_PER_ITEM", 3)
        r = run(plan(spec("ITM-A", "f*.cfg"), spec("ITM-B", "b.cfg")), tmp_path)
        a = next(o for o in r.outcomes if o.item_id == "ITM-A")
        assert a.status == "unreadable" and "files" in a.detail
        assert not r.complete

    def test_too_many_bytes_for_one_item_is_incomplete(self, tmp_path, monkeypatch):
        for i in range(3):
            (tmp_path / f"f{i}.cfg").write_bytes(b"x" * 400)
        (tmp_path / "b.cfg").write_bytes(b"x")
        monkeypatch.setattr(collector_mod, "MAX_ITEM_BYTES", 1000)
        r = run(plan(spec("ITM-A", "f*.cfg"), spec("ITM-B", "b.cfg")), tmp_path)
        assert next(o for o in r.outcomes if o.item_id == "ITM-A").status == "unreadable"

    def test_a_time_budget_stops_the_collection_and_says_so(self, tmp_path, monkeypatch):
        for n in "abc":
            (tmp_path / f"{n}.cfg").write_bytes(b"x")
        ticks = iter([0.0, 0.0, 0.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0])
        monkeypatch.setattr(collector_mod, "_now", lambda: next(ticks))
        r = run(plan(spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg"),
                     spec("ITM-C", "c.cfg")), tmp_path, max_seconds=10.0)
        assert not r.complete
        statuses = {o.item_id: o.status for o in r.outcomes}
        assert statuses["ITM-A"] == "collected"
        assert statuses["ITM-C"] == "unreadable"
        assert any("time budget" in o.detail for o in r.outcomes)

    def test_a_version_scan_is_capped_and_does_not_reread_unbounded(
            self, tmp_path, monkeypatch):
        (tmp_path / "a.cfg").write_bytes(b"version=1.2\n" + b"x" * 100)
        monkeypatch.setattr(collector_mod, "MAX_VERSION_SCAN_BYTES", 1000)
        s = spec("ITM-A", "a.cfg", version=VersionSource(kind="regex",
                                                         value=r"version=([\d.]+)"))
        r = run(plan(s), tmp_path)
        assert r.manifest.item("ITM-A").version == "1.2"      # inside the cap
        (tmp_path / "a.cfg").write_bytes(b"version=1.2\n" + b"x" * 5000)
        r = run(plan(s), tmp_path)
        assert r.manifest.item("ITM-A").version == ""          # larger than the scan: not guessed
        assert any("version" in w for w in r.outcomes[0].warnings)

    def test_the_manifest_is_never_claimed_from_a_partial_read(self, tmp_path):
        (tmp_path / "a.cfg").write_bytes(b"x")
        (tmp_path / "p.zip").write_bytes(b"not a zip")
        r = run(plan(spec("ITM-A", "a.cfg"),
                     spec("ITM-P", "p.zip", rule=ZIP_RULE)), tmp_path)
        assert not r.complete
        assert "INCOMPLETE" in r.summary()
        assert r.to_dict()["complete"] is False

    def test_the_cli_exits_nonzero_on_an_incomplete_collection(self, tmp_path, capsys):
        from assurance.collect.cli import main
        (tmp_path / "a.cfg").write_bytes(b"x")
        (tmp_path / "b.cfg").write_bytes(b"")
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan(
            spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg")).to_dict()), encoding="utf-8")
        code = main(["run", str(plan_path), "--root", str(tmp_path), "--serial", "1",
                     "--actor", "a.person"])
        assert code == 1


# =====================================================================
# the probe: stable means every rule was exercised and held
# =====================================================================

class TestProbeDoesNotCallAnUnexercisedPlanStable:
    def test_a_plan_whose_files_are_in_neither_export_is_incomplete_not_stable(
            self, tmp_path):
        (tmp_path / "mon").mkdir()
        (tmp_path / "tue").mkdir()
        r = probe(plan(spec()), tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "incomplete"
        assert r.unexercised == ("ITM-A",)

    def test_one_rule_exercised_and_one_not_is_incomplete(self, tmp_path):
        for d in ("mon", "tue"):
            (tmp_path / d).mkdir()
            (tmp_path / d / "a.cfg").write_bytes(b"same")
        r = probe(plan(spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg")),
                  tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "incomplete"
        assert [i.item_id for i in r.items] == ["ITM-A"]

    def test_a_rule_that_cannot_run_makes_it_incomplete(self, tmp_path):
        for d in ("mon", "tue"):
            (tmp_path / d).mkdir()
            (tmp_path / d / "a.cfg").write_bytes(b"\xff\xfe\x00")
        s = spec("ITM-A", "a.cfg", rule=TEXT_RULE)
        r = probe(plan(s), tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "incomplete"

    def test_volatile_outranks_incomplete(self, tmp_path):
        for d, c in (("mon", b"1"), ("tue", b"2")):
            (tmp_path / d).mkdir()
            (tmp_path / d / "a.cfg").write_bytes(c)
        r = probe(plan(spec("ITM-A", "a.cfg"), spec("ITM-B", "b.cfg")),
                  tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "volatile"

    def test_every_rule_exercised_and_stable_is_stable(self, tmp_path):
        for d in ("mon", "tue"):
            (tmp_path / d).mkdir()
            (tmp_path / d / "a.cfg").write_bytes(b"same")
        r = probe(plan(spec("ITM-A", "a.cfg")), tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "stable"
        assert r.unexercised == ()

    def test_the_cli_exits_nonzero_for_incomplete(self, tmp_path):
        from assurance.collect.cli import main
        (tmp_path / "mon").mkdir()
        (tmp_path / "tue").mkdir()
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan(spec()).to_dict()), encoding="utf-8")
        assert main(["probe", str(plan_path), "--first", str(tmp_path / "mon"),
                     "--second", str(tmp_path / "tue")]) != 0
