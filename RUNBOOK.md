# kryptosbot.com Daily Runbook

## 1. Check for new submissions

```bash
cd ~/kryptos
python3 api/admin.py list
```

If nothing pending, you're done. Otherwise continue below.

---

## 2. Triage each theory

Read the theory text. Decide: **test it**, **reject it**, or **skip for now**.

### Reject (already covered, nonsensical, etc.)

```bash
python3 api/admin.py reject <id> "Reason here"
```

Common reasons:
- `"Covered by e-poly-01 (Vigenere sweeps)"`
- `"Too vague to test"`
- `"Violates 26-letter constraint (Playfair/Bifid impossible)"`

### Mark as testing (you plan to run it)

```bash
python3 api/admin.py test <id>
```

---

## 3. Test a theory

### Option A: Quick test with existing scripts

```bash
# Search for related scripts
PYTHONPATH=src python3 run_attack.py --list --verbose | grep -i "<keyword>"

# Run one
PYTHONPATH=src python3 -u scripts/<family>/<script>.py
```

### Option B: Write a new experiment

1. Create `scripts/<family>/e_<topic>_<nn>_<name>.py`
2. Import from `kryptos.kernel.constants` (never hardcode CT/cribs)
3. Implement `attack()` returning `[(score, plaintext, method), ...]`
4. Run it:
   ```bash
   PYTHONPATH=src python3 -u scripts/<family>/e_<topic>_<nn>_<name>.py
   ```

### Option C: Use the workbench

Go to https://kryptosbot.com/workbench/ and test interactively.

---

## 4. Record the result

### If eliminated (score < 18, no signal)

```bash
# Mark the theory as published (meaning: tested and result added to site)
python3 api/admin.py publish <id> "Eliminated as e-xxx-yy, score 0/24"
```

### If promising (score >= 18)

Investigate further before closing. Keep it as "testing."

### Rebuild the site (if you added a new elimination)

```bash
source venv/bin/activate
python3 site_builder/build.py
```

The site serves from `site/` directly — no restart needed.

---

## 5. Push updates (optional, keeps GitHub in sync)

```bash
git add scripts/<new_script>.py
git commit -m "Add elimination: <description>"
git push
```

---

## Quick reference

| Command | What it does |
|---|---|
| `python3 api/admin.py list` | Show pending theories |
| `python3 api/admin.py all` | Show ALL theories (any status) |
| `python3 api/admin.py count` | Just the pending count |
| `python3 api/admin.py test <id>` | Mark as "testing" |
| `python3 api/admin.py publish <id> [note]` | Mark as published |
| `python3 api/admin.py reject <id> [reason]` | Reject with reason |

## Notifications

Novel theories trigger a push notification via ntfy. To manage:

- **Phone app**: ntfy (Android/iOS), subscribed to your private topic
- **Topic**: Set in `~/kryptos/.env` as `NTFY_TOPIC`
- **Silence**: Remove `NTFY_TOPIC` from `.env` and restart the service

## Service management

```bash
sudo systemctl status kryptosbot-api.service    # Check if running
sudo systemctl restart kryptosbot-api.service    # Restart after code changes
sudo journalctl -u kryptosbot-api -f             # Tail live logs
```
