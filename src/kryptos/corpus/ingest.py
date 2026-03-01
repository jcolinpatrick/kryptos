"""Source text ingestion for the Egyptological corpus pipeline.

Handles:
    - Local text files (reference/ directory)
    - Project Gutenberg downloads with caching
    - Paragraph-level segmentation with chapter detection
    - OCR artifact cleanup
"""
from __future__ import annotations

import os
import re
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple

from kryptos.corpus.schema import CorpusPassage, Provenance
from kryptos.corpus.normalize import EgyptNormalizer


# ── Gutenberg URL patterns ──────────────────────────────────────────────
# Try multiple URL formats; Gutenberg restructures periodically.

GUTENBERG_URL_PATTERNS = [
    "https://www.gutenberg.org/cache/epub/{id}/pg{id}.txt",
    "https://www.gutenberg.org/files/{id}/{id}-0.txt",
    "https://www.gutenberg.org/files/{id}/{id}.txt",
]

# ── Curated Egyptological Gutenberg texts ────────────────────────────────
# (gutenberg_id, title, author)
# Selected for density of Egyptological names and transliteration-adjacent
# Latin spellings.  IDs verified against Gutenberg catalog where possible.

EGYPT_GUTENBERG_BOOKS: List[Tuple[int, str, str]] = [
    # Carter / Tutankhamun
    (59783, "Tutankhamen and the Discovery of His Tomb", "G. Elliot Smith"),
    # Budge — prolific Egyptologist, dense transliteration
    (4363, "The Egyptian Book of the Dead (Papyrus of Ani)", "E.A.W. Budge"),
    (17325, "Tutankhamen: Amenism, Atenism, and Egyptian Monotheism",
     "E.A.W. Budge"),
    (15932, "The Gods of the Egyptians Vol 1", "E.A.W. Budge"),
    (15934, "The Gods of the Egyptians Vol 2", "E.A.W. Budge"),
    # Rawlinson — Victorian Egypt history
    (14400, "History of Ancient Egypt Vol 1", "George Rawlinson"),
    (14766, "History of Ancient Egypt Vol 2", "George Rawlinson"),
    # Petrie — field archaeologist
    (12268, "Ten Years' Digging in Egypt", "W.M.F. Petrie"),
    (7359, "Religion and Conscience in Ancient Egypt", "W.M.F. Petrie"),
    # Maspero — Egyptology survey
    (14914, "Manual of Egyptian Archaeology", "Gaston Maspero"),
    (16653, "The Dawn of Civilization", "Gaston Maspero"),
    # Breasted — standard history
    (6867, "Ancient Times: A History of the Early World", "J.H. Breasted"),
    # Weigall — Akhenaten biography
    (10058, "The Life and Times of Akhnaton", "Arthur Weigall"),
    # Edwards — Nile travel narrative (popular 1877)
    (8500, "A Thousand Miles Up the Nile", "Amelia B. Edwards"),
    # Erman — comprehensive reference
    (65536, "Life in Ancient Egypt", "Adolf Erman"),
    # Sayce — archaeology overview
    (16661, "Fresh Light from the Ancient Monuments", "A.H. Sayce"),
]


class TextIngester:
    """Loads, cleans, and segments Egyptological source texts."""

    def __init__(self, cache_dir: str = "results/egypt_corpus/downloads"):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    # ── Local file loading ───────────────────────────────────────────

    def load_local(
        self,
        path: str,
        title: str,
        author: str,
        is_ocr: bool = False,
    ) -> List[CorpusPassage]:
        """Load a local text file and segment into passages."""
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read()

        if is_ocr:
            raw = EgyptNormalizer.clean_ocr(raw)

        basename = os.path.basename(path)
        return self._segment(raw, basename, title, author, gutenberg_id=None)

    # ── Gutenberg downloading ────────────────────────────────────────

    def download_gutenberg(
        self,
        book_id: int,
        title: str,
        author: str,
    ) -> Optional[List[CorpusPassage]]:
        """Download a Gutenberg text, cache locally, segment into passages.

        Returns None if all URL patterns fail.
        """
        cache_path = os.path.join(self.cache_dir, f"pg{book_id}.txt")

        # Check cache first
        if os.path.exists(cache_path):
            with open(cache_path, encoding="utf-8", errors="replace") as f:
                raw = f.read()
        else:
            raw = self._fetch_gutenberg(book_id)
            if raw is None:
                return None
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(raw)

        # Strip Gutenberg header/footer
        raw = self._strip_gutenberg_wrapper(raw)

        return self._segment(
            raw, f"pg{book_id}.txt", title, author, gutenberg_id=book_id
        )

    def _fetch_gutenberg(self, book_id: int) -> Optional[str]:
        """Try multiple URL patterns to fetch a Gutenberg text."""
        for pattern in GUTENBERG_URL_PATTERNS:
            url = pattern.format(id=book_id)
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "KryptosBot/1.0 (research)"},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    # Try UTF-8 first, fall back to latin-1
                    data = resp.read()
                    try:
                        return data.decode("utf-8")
                    except UnicodeDecodeError:
                        return data.decode("latin-1")
            except (urllib.error.URLError, urllib.error.HTTPError, OSError):
                continue
        return None

    @staticmethod
    def _strip_gutenberg_wrapper(text: str) -> str:
        """Remove Project Gutenberg header and footer."""
        # Find start marker
        start_markers = [
            "*** START OF THE PROJECT GUTENBERG EBOOK",
            "*** START OF THIS PROJECT GUTENBERG EBOOK",
            "***START OF THE PROJECT GUTENBERG EBOOK",
        ]
        for marker in start_markers:
            idx = text.upper().find(marker.upper())
            if idx != -1:
                # Skip to end of the marker line
                newline = text.find("\n", idx)
                if newline != -1:
                    text = text[newline + 1:]
                break

        # Find end marker
        end_markers = [
            "*** END OF THE PROJECT GUTENBERG EBOOK",
            "*** END OF THIS PROJECT GUTENBERG EBOOK",
            "***END OF THE PROJECT GUTENBERG EBOOK",
            "End of the Project Gutenberg EBook",
            "End of Project Gutenberg",
        ]
        for marker in end_markers:
            idx = text.upper().find(marker.upper())
            if idx != -1:
                text = text[:idx]
                break

        return text.strip()

    # ── Passage segmentation ─────────────────────────────────────────

    def _segment(
        self,
        text: str,
        source_file: str,
        title: str,
        author: str,
        gutenberg_id: Optional[int],
    ) -> List[CorpusPassage]:
        """Split text into passages (paragraph-level).

        Each passage is a contiguous block of text separated by blank lines.
        Very short passages (< 20 chars alpha) are merged with neighbors.
        Chapter headings are detected and stored in provenance.
        """
        # Split on double-newlines (blank lines)
        blocks = re.split(r"\n\s*\n", text)

        passages = []
        current_chapter = ""
        line_counter = 1

        for block in blocks:
            block = block.strip()
            if not block:
                continue

            # Count lines for provenance
            block_lines = block.count("\n") + 1
            line_start = line_counter
            line_end = line_counter + block_lines - 1
            line_counter = line_end + 1

            # Detect chapter headings
            chapter_match = re.match(
                r"^(?:CHAPTER|Chapter|BOOK|Book|PART|Part)"
                r"[\s.:]*([IVXLC\d]+\.?.*?)$",
                block.split("\n")[0],
            )
            if chapter_match:
                current_chapter = block.split("\n")[0].strip()

            # Skip very short blocks (likely headers, page numbers)
            alpha = re.sub(r"[^A-Za-z]", "", block)
            if len(alpha) < 20:
                continue

            passage_id = f"{source_file}:{line_start}"
            prov = Provenance(
                source_file=source_file,
                title=title,
                author=author,
                gutenberg_id=gutenberg_id,
                chapter=current_chapter,
                line_start=line_start,
                line_end=line_end,
                original_text=block[:500],  # truncate for storage
            )

            passage = CorpusPassage(
                passage_id=passage_id,
                raw=block,
                provenance=prov,
                raw_alpha_length=len(alpha),
            )
            passages.append(passage)

        return passages

    # ── Batch ingestion ──────────────────────────────────────────────

    def ingest_all_local(self, reference_dir: str) -> Dict[str, List[CorpusPassage]]:
        """Load all known local Egyptological source files.

        Returns dict of filename → passage list.
        """
        results = {}

        # Carter Vol 1 (OCR from Cambridge Library Collection PDF)
        carter_v1 = os.path.join(reference_dir, "carter_vol1.txt")
        if os.path.exists(carter_v1):
            passages = self.load_local(
                carter_v1,
                title="The Tomb of Tut-Ankh-Amen Vol 1",
                author="Howard Carter & A.C. Mace",
                is_ocr=True,
            )
            results["carter_vol1.txt"] = passages

        # Carter Gutenberg (Elliot Smith commentary)
        carter_gut = os.path.join(reference_dir, "carter_gutenberg.txt")
        if os.path.exists(carter_gut):
            passages = self.load_local(
                carter_gut,
                title="Tutankhamen and the Discovery of His Tomb",
                author="G. Elliot Smith",
                is_ocr=False,
            )
            results["carter_gutenberg.txt"] = passages

        return results

    def ingest_gutenberg_batch(
        self,
        books: Optional[List[Tuple[int, str, str]]] = None,
    ) -> Dict[str, List[CorpusPassage]]:
        """Download and segment a batch of Gutenberg texts.

        Uses the curated EGYPT_GUTENBERG_BOOKS list by default.
        Returns dict of filename → passage list.  Skips failed downloads.
        """
        if books is None:
            books = EGYPT_GUTENBERG_BOOKS

        results = {}
        for book_id, title, author in books:
            passages = self.download_gutenberg(book_id, title, author)
            if passages is not None:
                key = f"pg{book_id}.txt"
                results[key] = passages
            # else: download failed, skip silently (reported by caller)

        return results
