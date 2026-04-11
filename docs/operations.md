# Operations & Deployment

Full operational reference for `kryptosbot.com` and supporting systems. Referenced from [CLAUDE.md](../CLAUDE.md).

## Supporting Systems

- **`ops/site_builder/`** — Builds `kryptosbot.com` → `site/` (gitignored). Config: `overrides.toml`.
- **`ops/api/`** — FastAPI backend: theory classifier (`classifier.py`), submission queue (`queue.py`), admin CLI (`admin.py`). Mounts `site/` as static. Requires `venv/`.
- **`kryptosbot/`** — Claude Agent SDK multi-agent runner. Ops guide: `ops/RUNBOOK.md`. Has its own `pyproject.toml` with `claude-agent-sdk` dependency.
  - `solve.py` — Original entry point (single-agent).
  - `campaign_v2.py` — **Active campaign runner**: Phases 1–5 (free compute: row key forensics, fractionation, state machines), Phase 6+ (Opus-guided, API budget). Entry: `PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py`. Supports `--local-only`, `--dry-run`.
  - `monitor.py` — Live campaign dashboard: `python3 kryptosbot/monitor.py [--interval 1]`. Scans `results/campaigns/` for active sessions.
  - `polybius_scorer.py` — Polybius coordinate extraction and crib scoring.
- **`bench/`** — Benchmark suite (tier0–tier3). CLI: `bench/cli.py run|score|generate`. Tests: `tests/test_bench*.py`.
- **`reports/`** — 45+ synthesis files from experiment campaigns. Summary JSONs (`*.summary.json`), audit matrices, synthesis markdown. Key file: [`reports/final_synthesis.md`](../reports/final_synthesis.md).
- **`archive/`** — `legacy_harness/` (old agent code), `session_reports/` (historical outputs).
- **`bin/`** — Specialized cipher engines (antipodes, cylinder rotation) — historical hypothesis testing.
- **`external/`** — Imported external research (enigmator, patrickkellogg-Kryptos) — not maintained.

## Service Management

The live site (`kryptosbot.com`) runs on this same machine:

```bash
# Service management
sudo systemctl status|restart kryptosbot-api.service   # API on 127.0.0.1:8321
journalctl -u kryptosbot-api -f                         # API logs (live tail)

# Nginx (reverse proxy, SSL via Let's Encrypt, rate limiting: 10 req/s per IP)
sudo nginx -t && sudo systemctl reload nginx

# 30-min CI/CD cron (flock prevents overlap, checksum-based rebuild)
# Crontab: */30 * * * * flock -n /tmp/kryptosbot-cron.lock ops/deploy/cron_update.sh
ops/deploy/cron_update.sh --force    # Force rebuild
ops/deploy/cron_update.sh --dry-run  # Skip git commit

# Scheduled prompts and health checks
ops/scheduled/run-prompt.sh ops/scheduled/nightly-review.txt
ops/scheduled/health-check.sh     # Zero-cost morning health check (replaces Claude briefing)

# Traffic analysis
ops/tools/analyze_traffic.sh      # Bot vs human breakdown from nginx logs
```

## Log Locations

- API: `journalctl -u kryptosbot-api`
- Cron: `logs/cron_update.log`
- Scheduled prompts: `logs/scheduler.log`, `logs/scheduled_output_*.log`

## Environment Files

TWO `.env` files — don't confuse them:
- `.env` (root) — `ANTHROPIC_API_KEY`, `KBOT_CLASSIFY_API_KEY`, `NTFY_TOPIC` (push notifications for theory submissions)
- `kryptosbot/.env` — API key for Agent SDK campaigns (see `kryptosbot/.env.template`)

## Deployment Infrastructure

- **`ops/deploy/`** — Production deployment: systemd unit, nginx config, setup script, 30-min cron CI/CD loop.
- **`ops/scheduled/`** — Non-interactive Claude Code prompts (nightly review) + shell health check via `health-check.sh`.
- **`ops/tools/`** — Ops utilities: `analyze_traffic.sh` (nginx log analysis, bot detection), `generate_quadgrams.py`.

## Site Builder & API Commands

```bash
# Site builder
source venv/bin/activate && python3 ops/site_builder/build.py

# API server
source venv/bin/activate && python3 ops/site_builder/serve.py

# Theory admin
python3 ops/api/admin.py list|test|publish|reject <id>

# Service
sudo systemctl status|restart kryptosbot-api.service
```
