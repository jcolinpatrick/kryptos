"""Tests for the attack script standardization library (scripts/lib/)."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure scripts/ package is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from scripts.lib.header import (
    ScriptHeader,
    parse_header,
    has_standard_header,
    has_attack_function,
    extract_legacy_description,
)
from scripts.lib.exhaustion import (
    load,
    save,
    update,
    record_run,
    reconcile,
)
from scripts.lib.discover import (
    discover_scripts,
    build_manifest,
    filter_manifest,
)


# ── Header parsing tests ────────────────────────────────────────────────────

class TestHeaderParsing:
    """Tests for scripts/lib/header.py."""

    def _write_script(self, tmp_path, name, content):
        p = tmp_path / name
        p.write_text(content)
        return str(p)

    def test_parse_standard_header(self, tmp_path):
        path = self._write_script(tmp_path, "test.py", '''\
#!/usr/bin/env python3
"""
Cipher: Vigenere
Family: polyalphabetic
Status: exhausted
Keyspace: 26^1 through 26^7
Last run: 2026-03-04
Best score: 623.7 (quadgram)
"""
import sys
''')
        header = parse_header(path)
        assert header is not None
        assert header.cipher == "Vigenere"
        assert header.family == "polyalphabetic"
        assert header.status == "exhausted"
        assert header.keyspace == "26^1 through 26^7"
        assert header.last_run == "2026-03-04"
        assert header.best_score == "623.7 (quadgram)"
        assert header.validate() == []

    def test_parse_minimal_header(self, tmp_path):
        path = self._write_script(tmp_path, "test.py", '''\
"""
Cipher: Caesar
Family: substitution
Status: active
"""
''')
        header = parse_header(path)
        assert header is not None
        assert header.cipher == "Caesar"
        assert header.status == "active"
        assert header.keyspace == ""  # optional, defaults to empty

    def test_parse_missing_required_field(self, tmp_path):
        path = self._write_script(tmp_path, "test.py", '''\
"""
Cipher: Caesar
Status: active
"""
''')
        # Missing Family — should return None
        header = parse_header(path)
        assert header is None

    def test_parse_legacy_no_header(self, tmp_path):
        path = self._write_script(tmp_path, "test.py", '''\
"""E-FRAC-05: Width-9 Columnar + Column-Dependent Mixed Alphabets.

Tests whether width-9 columnar transposition combined with arbitrary
column-dependent substitution alphabets works.
"""
import itertools
''')
        header = parse_header(path)
        assert header is None  # No standard fields

    def test_parse_invalid_status(self, tmp_path):
        path = self._write_script(tmp_path, "test.py", '''\
"""
Cipher: Caesar
Family: substitution
Status: maybe
"""
''')
        header = parse_header(path)
        assert header is not None
        errors = header.validate()
        assert len(errors) == 1
        assert "maybe" in errors[0]

    def test_has_standard_header(self, tmp_path):
        good = self._write_script(tmp_path, "good.py", '''\
"""
Cipher: X
Family: y
Status: active
"""
''')
        bad = self._write_script(tmp_path, "bad.py", '''\
"""Just a description."""
''')
        assert has_standard_header(good) is True
        assert has_standard_header(bad) is False

    def test_has_attack_function(self, tmp_path):
        with_fn = self._write_script(tmp_path, "a.py", '''\
def attack(ciphertext, **params):
    return []
''')
        without_fn = self._write_script(tmp_path, "b.py", '''\
def main():
    pass
''')
        assert has_attack_function(with_fn) is True
        assert has_attack_function(without_fn) is False

    def test_extract_legacy_description(self, tmp_path):
        path = self._write_script(tmp_path, "test.py", '''\
"""E-FRAC-05: Width-9 Columnar Analysis.

More details here.
"""
''')
        desc = extract_legacy_description(path)
        assert desc == "E-FRAC-05: Width-9 Columnar Analysis."

    def test_to_docstring_roundtrip(self, tmp_path):
        header = ScriptHeader(
            cipher="Vigenere",
            family="polyalphabetic",
            status="active",
            keyspace="26^7",
            last_run="2026-03-04",
            best_score="100.0",
        )
        docstring = header.to_docstring()
        # Write and re-parse
        path = self._write_script(tmp_path, "test.py", docstring + "\nimport sys\n")
        reparsed = parse_header(path)
        assert reparsed is not None
        assert reparsed.cipher == header.cipher
        assert reparsed.family == header.family
        assert reparsed.status == header.status

    def test_to_dict(self):
        header = ScriptHeader(
            cipher="Caesar", family="substitution", status="exhausted",
        )
        d = header.to_dict()
        assert d["cipher"] == "Caesar"
        assert d["family"] == "substitution"
        assert d["status"] == "exhausted"


# ── Exhaustion log tests ────────────────────────────────────────────────────

class TestExhaustionLog:
    """Tests for scripts/lib/exhaustion.py."""

    def test_load_nonexistent(self, tmp_path):
        data = load(str(tmp_path / "nope.json"))
        assert data == {}

    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "log.json")
        data = {"caesar": {"status": "exhausted", "best": 3.0}}
        save(data, path)
        loaded = load(path)
        assert loaded == data

    def test_update_creates_entry(self, tmp_path):
        path = str(tmp_path / "log.json")
        entry = update("vigenere_7", status="active", keyspace="26^7", path=path)
        assert entry["status"] == "active"
        assert entry["keyspace"] == "26^7"
        # Verify persisted
        data = load(path)
        assert "vigenere_7" in data

    def test_update_preserves_existing(self, tmp_path):
        path = str(tmp_path / "log.json")
        update("test", status="active", keyspace="100", best=50.0, path=path)
        # Update only status
        entry = update("test", status="exhausted", path=path)
        assert entry["status"] == "exhausted"
        assert entry["keyspace"] == "100"
        assert entry["best"] == 50.0

    def test_update_invalid_status(self, tmp_path):
        path = str(tmp_path / "log.json")
        with pytest.raises(ValueError, match="Invalid status"):
            update("test", status="maybe", path=path)

    def test_record_run_updates_best(self, tmp_path):
        path = str(tmp_path / "log.json")
        update("test", status="active", best=100.0, path=path)
        # Better score
        entry = record_run("test", 200.0, path=path)
        assert entry["best"] == 200.0
        # Worse score — best should not decrease
        entry = record_run("test", 50.0, path=path)
        assert entry["best"] == 200.0

    def test_record_run_sets_date(self, tmp_path):
        from datetime import date
        path = str(tmp_path / "log.json")
        entry = record_run("test", 100.0, path=path)
        assert entry["last_run"] == date.today().isoformat()

    def test_reconcile_detects_status_mismatch(self):
        headers = {
            "script_a": {"status": "active", "family": "grille"},
        }
        log = {
            "script_a": {"status": "exhausted", "family": "grille"},
        }
        mismatches = reconcile(headers, log)
        assert len(mismatches) == 1
        assert "status mismatch" in mismatches[0]
        assert "log is authoritative" in mismatches[0]

    def test_reconcile_detects_missing_entries(self):
        headers = {"a": {"status": "active", "family": "x"}}
        log = {"b": {"status": "active"}}
        mismatches = reconcile(headers, log)
        assert any("missing from exhaustion log" in m for m in mismatches)
        assert any("no script header found" in m for m in mismatches)

    def test_reconcile_clean(self):
        headers = {"a": {"status": "active", "family": "x"}}
        log = {"a": {"status": "active", "family": "x"}}
        mismatches = reconcile(headers, log)
        assert mismatches == []


# ── Discovery tests ─────────────────────────────────────────────────────────

class TestDiscovery:
    """Tests for scripts/lib/discover.py."""

    def _make_scripts(self, tmp_path):
        """Create a mini scripts directory with mixed scripts."""
        # Standard header + attack()
        (tmp_path / "good.py").write_text('''\
"""
Cipher: Caesar
Family: substitution
Status: exhausted
Keyspace: 0-25
Last run: 2026-01-01
Best score: 3.0
"""
def attack(ciphertext, **params):
    return [(3.0, "HELLO", "Caesar ROT-1")]
''')
        # Legacy (no header, no attack)
        (tmp_path / "legacy.py").write_text('''\
"""E-FRAC-99: Some old experiment."""
def main():
    pass
if __name__ == "__main__":
    main()
''')
        # Skip __init__
        (tmp_path / "__init__.py").write_text("")

    def test_discover_scripts(self, tmp_path):
        self._make_scripts(tmp_path)
        scripts = discover_scripts(str(tmp_path))
        names = [s.name for s in scripts]
        assert "good.py" in names
        assert "legacy.py" in names
        assert "__init__.py" not in names

    def test_build_manifest(self, tmp_path):
        self._make_scripts(tmp_path)
        manifest = build_manifest(str(tmp_path))
        assert len(manifest) == 2

        good = next(e for e in manifest if e["script_id"] == "good")
        assert good["has_header"] is True
        assert good["has_attack_fn"] is True
        assert good["family"] == "substitution"
        assert good["status"] == "exhausted"

        legacy = next(e for e in manifest if e["script_id"] == "legacy")
        assert legacy["has_header"] is False
        assert legacy["has_attack_fn"] is False

    def test_filter_by_family(self, tmp_path):
        self._make_scripts(tmp_path)
        manifest = build_manifest(str(tmp_path))
        filtered = filter_manifest(manifest, family="substitution")
        assert len(filtered) == 1
        assert filtered[0]["script_id"] == "good"

    def test_filter_by_status(self, tmp_path):
        self._make_scripts(tmp_path)
        manifest = build_manifest(str(tmp_path))
        filtered = filter_manifest(manifest, status="exhausted")
        assert len(filtered) == 1

    def test_filter_by_attack_fn(self, tmp_path):
        self._make_scripts(tmp_path)
        manifest = build_manifest(str(tmp_path))
        filtered = filter_manifest(manifest, has_attack_fn=True)
        assert len(filtered) == 1
        assert filtered[0]["script_id"] == "good"

    def test_filter_by_min_score(self, tmp_path):
        self._make_scripts(tmp_path)
        log = {"good": {"status": "exhausted", "family": "substitution", "best": 3.0}}
        manifest = build_manifest(str(tmp_path), log)
        above = filter_manifest(manifest, min_score=2.0)
        assert len(above) == 1
        below = filter_manifest(manifest, min_score=5.0)
        assert len(below) == 0

    def test_manifest_with_exhaustion_log(self, tmp_path):
        self._make_scripts(tmp_path)
        log = {
            "legacy": {
                "status": "promising",
                "family": "fractionation",
                "best": 15.0,
            }
        }
        manifest = build_manifest(str(tmp_path), log)
        legacy = next(e for e in manifest if e["script_id"] == "legacy")
        # Exhaustion log should override defaults
        assert legacy["status"] == "promising"
        assert legacy["family"] == "fractionation"


# ── Integration: example script ─────────────────────────────────────────────

class TestExampleScript:
    """Test the example standardized script."""

    def test_example_has_header(self):
        example = PROJECT_ROOT / "scripts" / "examples" / "e_caesar_standard.py"
        if not example.exists():
            pytest.skip("Example script not found")
        header = parse_header(str(example))
        assert header is not None
        assert header.cipher == "Caesar (ROT-N)"
        assert header.family == "substitution"
        assert header.status == "exhausted"
        assert header.validate() == []

    def test_example_has_attack(self):
        example = PROJECT_ROOT / "scripts" / "examples" / "e_caesar_standard.py"
        if not example.exists():
            pytest.skip("Example script not found")
        assert has_attack_function(str(example)) is True

    def test_example_attack_returns_correct_type(self):
        example = PROJECT_ROOT / "scripts" / "examples" / "e_caesar_standard.py"
        if not example.exists():
            pytest.skip("Example script not found")

        import importlib.util
        spec = importlib.util.spec_from_file_location("example", str(example))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        from kryptos.kernel.constants import CT
        results = mod.attack(CT)
        assert isinstance(results, list)
        assert len(results) == 25  # ROT-1 through ROT-25
        for score, pt, method in results:
            assert isinstance(score, float)
            assert isinstance(pt, str)
            assert len(pt) == 97
            assert isinstance(method, str)
        # Should be sorted descending
        scores = [r[0] for r in results]
        assert scores == sorted(scores, reverse=True)
