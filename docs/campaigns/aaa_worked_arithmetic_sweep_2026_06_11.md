# Pre-registration: AAA targeted sweep for worked cipher arithmetic (2026-06-11)

**STATUS: CANCELLED 2026-06-11 before triage completed**, on Colin's firsthand testimony that the public AAA deposit is purged of cipher calculations with folders restricted (see docs/archive_aaa_doctrine.md curation caveat). No results were read. Chain-of-custody manifest + cluster index preserved in the run directory. Follow-up: SPEC-F (restricted-folder access inquiry).

**Run:** `analysis_runs/aaa_worked_arithmetic_sweep_2026_06_11/`
**Motivation:** the verified "Beaufort cipher" menu entry in Sanborn's hand
(IMG_1569) is a bare family name with no extractable parameters (admission
rule 3 fails). The only upgrade path is a WORKED page: actual cipher
computation in the archive. The AAA index covers ~80 of 534 images and has
produced three phantoms; prior careful reads (49 crypto-actionable re-reads
2026-06-05, SPEC-E 1223-1235) were not hunting computation. Scope is
therefore ALL 534 images, with prior-read overlap noted, not skipped.

**Target definition (frozen).** "Worked cipher arithmetic" = any page
showing letters/numbers being TRANSFORMED by a procedure, including:
letter-over-letter encipherment rows (PT/CT/key alignments), modular
addition/subtraction with letters or alphabet indices, tableau lookups or
traced paths, keystream rows, frequency tallies, columnar/route worksheets
(text written into numbered or reordered columns), alphabet-indexing
computations, grille/mask constructions. NOT: prose notes, bare lists of
terms, sketches, finished tableaus with no working, photos of objects.

**Protocol.**
1. Chain of custody: SHA-256 manifest of all 534 HEIC originals before
   analysis; triage views (max 1300 px) derived, originals untouched.
2. Duplicate clustering (dHash) so near-duplicate shots are reviewed as
   clusters, not independent finds.
3. TRIAGE (workflow fan-out): independent agents, ~12 images each, classify
   every image against the frozen target definition and transcribe any
   cipher-relevant terms verbatim. Agents are NOT told about Beaufort or
   any expected finding (un-primed; describe-first discipline).
4. VERIFY: every triage candidate gets an independent second agent doing a
   full-resolution tiled read of that single image: confirm/refute the
   procedure, transcribe visible working, note cross-shot persistence
   within its duplicate cluster. Adjudicator (me) spot-checks all
   CONFIRMED pages on pixels.
5. Deliverables per the sweep-kryptos-photo-corpus contract: manifest.csv,
   cluster_index.json, findings.jsonl, review_queue.md, corpus_summary.md.

**Decision rules (frozen).**
- CONFIRMED worked-arithmetic page → review queue, ranked by
  parameter-bearing content (does it show a key, alphabet, tableau path,
  or method name attached to working?). Any parameter-bearing page becomes
  a candidate admission-gate provenance item via ITS OWN preregistration.
- Zero confirmed pages → MEASURED_NULL for the corpus: the archive (as
  photographed) contains no worked cipher computation, and the Beaufort
  menu entry stays a bare name with likelihood ratio ~1.
- No K4 compute is licensed by this run either way.
