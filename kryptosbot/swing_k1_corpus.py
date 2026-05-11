"""Swing K-1 corpus loader (Tier A and Tier B). See docs/superpowers/specs/2026-05-11-key-tape-m2-m5-keystream-recovery-design.md section 6."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Literal

REPO_ROOT = Path(__file__).resolve().parent.parent
TIER_A_PATH = REPO_ROOT / "data" / "swing_k1" / "tier_a_manifest.json"
TIER_B_PATH = REPO_ROOT / "data" / "swing_k1" / "tier_b_manifest.json"


@dataclass(frozen=True)
class CorpusEntry:
    id: str
    kind: Literal["inline_plaintext", "file"]
    sha256: str
    _text: str  # cached normalized text
    path: str | None = None

    def text(self) -> str:
        return self._text


@dataclass(frozen=True)
class Corpus:
    tier: Literal["A", "B"]
    manifest_hash: str
    entries: list[CorpusEntry]


def _normalize_text(raw: str) -> str:
    """Strip non-letters, uppercase."""
    return "".join(c for c in raw.upper() if c.isalpha())


def _load_manifest(path: Path, tier: Literal["A", "B"]) -> Corpus:
    with open(path, "rb") as f:
        raw_bytes = f.read()
    manifest_hash = hashlib.sha256(raw_bytes).hexdigest()
    manifest = json.loads(raw_bytes.decode("utf-8"))
    entries: list[CorpusEntry] = []
    for raw_entry in manifest.get("entries", []):
        if raw_entry["kind"] == "inline_plaintext":
            text = _normalize_text(raw_entry["text"])
            sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            entries.append(
                CorpusEntry(
                    id=raw_entry["id"],
                    kind="inline_plaintext",
                    sha256=sha,
                    _text=text,
                )
            )
        elif raw_entry["kind"] == "file":
            file_path = REPO_ROOT / raw_entry["path"]
            with open(file_path, "rb") as fh:
                disk_bytes = fh.read()
            disk_sha = hashlib.sha256(disk_bytes).hexdigest()
            if disk_sha != raw_entry["sha256"]:
                raise ValueError(
                    f"corpus tier {tier}: hash mismatch for {file_path} "
                    f"(manifest {raw_entry['sha256']}, disk {disk_sha})"
                )
            text = _normalize_text(disk_bytes.decode("utf-8", errors="ignore"))
            entries.append(
                CorpusEntry(
                    id=raw_entry["id"],
                    kind="file",
                    sha256=disk_sha,
                    _text=text,
                    path=str(file_path.relative_to(REPO_ROOT)),
                )
            )
        else:
            raise ValueError(f"unknown corpus entry kind: {raw_entry['kind']}")
    return Corpus(tier=tier, manifest_hash=manifest_hash, entries=list(entries))


def load_tier_a() -> Corpus:
    return _load_manifest(TIER_A_PATH, "A")


def load_tier_b() -> Corpus:
    return _load_manifest(TIER_B_PATH, "B")
