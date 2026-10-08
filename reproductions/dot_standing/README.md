# DOT-STANDING reproductions

Every DOT-STANDING elimination published on [kryptosbot.com](https://www.kryptosbot.com/browse/) can be
re-run from this directory with one command, and the runner checks the result against the
published record. If you find a page whose command does not reproduce, please
[open an issue](https://github.com/jcolinpatrick/kryptos/issues/new).

```bash
pip install -r reproductions/dot_standing/requirements.txt    # numpy, pydantic
PYTHONPATH=src python3 -u scripts/dot_standing/dot_standing_001_hill_cipher_direct.py
python3 reproductions/dot_standing/reproduce.py --all          # every published campaign
python3 reproductions/dot_standing/reproduce.py --verify-only --all   # SHA-256 checks only
```

Each `scripts/dot_standing/dot_standing_NNN_*.py` is a thin wrapper around
`reproduce.py DOT-STANDING-NNN`. Exit status 0 means the result reproduced.

## Where these came from

The searches ran on 2026-10-05 and 2026-10-06 in Colin's private `cryptolab` repository, inside
a standing campaign queue ("Dot") that freezes each search's code by SHA-256, runs planted
controls, and requires an independent review before a single pass over the K4 ciphertext. The
queue itself (planning, review, custody and scheduling) stays private. What is here is
everything needed to repeat the science: the search code, the inputs it read, and the record
it wrote.

All of these are **scoped exact-compatibility nulls**: within the frozen scope in each
`records/dot_standing_NNN/spec.json`, no setting is consistent with the 24 known plaintext
letters at their carved positions (1-based 22-34 and 64-74). There is no language model and no
score threshold. A null says nothing about settings outside that scope.

## What the runner does

For one campaign, `reproduce.py`:

1. checks the SHA-256 of every file it will use against `campaigns.json`;
2. builds a fresh work directory with the original layout;
3. rebuilds any transposition route bank the search reads, and checks the rebuilt bank's
   SHA-256 against the bank that was used;
4. runs the target pass, then compares the output with `records/dot_standing_NNN/target.json`.

The comparison is strict. Every key the search code writes must be equal to the published value.
Only timing keys are ignored (`campaigns.json` `volatile_key_regex`). A key that is present only in the
published record is accepted only when it is on that campaign's declared `annotations` list, which
holds bookkeeping that the private queue added after the pass (for example
`worker_records_verified`). The runner prints those keys each time so that you can see them.

## Code: frozen, redacted, shimmed

`campaigns.json` labels every file that a campaign loads:

| Kind | Directory | Meaning |
|---|---|---|
| `frozen` | `frozen/` | The search probes, byte-identical to the files that ran. Most are listed in the run's own `freeze.json`; `frozen_at_run` names those that are. |
| `redacted` | `redacted/` | Six cryptolab library modules the probes call (`hill_cipher`, `transposition`, `alphabets`, `cribsolve`, `cribsolve_perm`, package `__init__`). Comments and docstrings are removed because they carried notes about unrelated private work. The redaction is mechanical: the executable syntax tree is checked to be identical to the original, whose SHA-256 is recorded as `original_sha256`. |
| `shim` | `shims/` | Five small stand-ins for modules that these searches import but never use: `research_bridge/k4.py` (gives only the 97-letter ciphertext, which is checked against SHA-256 `eea81357...`), `tools/fitness.py` and `tools/transforms.py` (these **raise an error if called**, so a successful replay is evidence that no language scoring or general transform engine took part), and two package `__init__` files. |

None of the frozen-at-run or redacted library files was modified after the run that used it
(file modification times were checked against each run's start).

## Other declared differences from the original run

- **Paths.** The frozen code names absolute paths on the original machine. The runner rewrites
  exactly the prefixes listed in `campaigns.json` `rewrites`, in the work-directory copy only.
- **Replay clock.** The frozen code refuses to run after its authorization window
  (`time.time() < 1791329400`, 2026-10-06 23:30 UTC). The runner installs a `sitecustomize.py`
  that starts `time.time()` at the original run's start instant (`epoch`) and lets it advance in
  real time. Nothing else is changed.
- **Launch commands.** Campaigns 010-030 run the launch command recorded by the queue, verbatim
  apart from the path rewrites. These include its custody wrappers, which only write extra
  per-worker records. The launch commands for 001-008 were not logged; the manifest names the
  inferred call (`target.source`). An inferred call is accepted only because its output matches
  the record. For 003 and 004, the queue called `target_task` once per base configuration; a
  one-line loop does the same.
- **Scope through the environment.** `unit_polynomial_probe.py` reads its degree and periods
  from environment variables. DOT-STANDING-022 sets them as its spec requires (`env` in the
  manifest). Without them the probe would silently re-run DOT-STANDING-021's scope. The strict
  comparison catches that.
- **Workers.** `--workers N` resizes the worker pool of probes that read `K4_NUMERIC_WORKERS`
  or `K4_WORKERS`. That changes speed, not scope.
- **Records.** `records/*/target.json` is the record as written, except the queue's
  `subscription_usage` accounting key, which is removed from DOT-STANDING-004 and 006
  (`reference_stripped_keys`; the original record's SHA-256 is `original_record_sha256`).
  `RESULTS.md` is published unchanged, so its SHA-256 matches the one cited on each page.

Tested with Python 3.12.3, numpy 2.4.3, and pydantic 2.11.10 in a clean virtual environment that
contains nothing else.

## Not here yet

The 2026-10-07 standing run also produced 23 word-dictionary, OCR running-key and procedural
campaigns (DOT-STANDING-032 to 065). Their pages are held back from kryptosbot.com until their
reproductions are published here. Several of them use a running key drawn from an OCR of a
Howard Carter text (public domain; Carter died in 1939), which will be published with them.
