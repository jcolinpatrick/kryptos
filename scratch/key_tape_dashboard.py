"""Side-channel ledger dashboard for the live key_tape integration check.

Polls db/theory_ledger.sqlite every 10s without disturbing the running
controller. Shows what the broken k4_monitor.py would have shown if it
had a log file: total theories, key_tape family activity, recent
verdicts, and any high-score hits.

Run: PYTHONPATH=src python3 scratch/key_tape_dashboard.py

Press Ctrl-C to stop.
"""
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

DB_PATH = "/home/cpatrick/kryptos/db/theory_ledger.sqlite"
# DB stores family as the kernel kind name (lowercase). The controller's
# landscape display maps it to "Finite Key Tape (OTP-like)" — those are
# UI labels, not stored values.
KEY_TAPE_FAMILY = "key_tape"
REFRESH_SEC = 10

# ANSI clear-screen + cursor-home (avoids os.system shell call)
CLEAR_SCREEN = "\033[2J\033[H"


def query_one(conn, sql, params=()):
    cur = conn.execute(sql, params)
    row = cur.fetchone()
    return row[0] if row else None


def query_all(conn, sql, params=()):
    cur = conn.execute(sql, params)
    return cur.fetchall()


def fmt_age(ts_iso):
    if not ts_iso:
        return "—"
    try:
        ts = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        delta_s = (datetime.now(timezone.utc) - ts).total_seconds()
        if delta_s < 60:
            return f"{int(delta_s)}s ago"
        if delta_s < 3600:
            return f"{int(delta_s / 60)}m{int(delta_s % 60)}s ago"
        return f"{int(delta_s / 3600)}h{int((delta_s % 3600) / 60)}m ago"
    except Exception:
        return ts_iso


def render(conn, baseline):
    print(CLEAR_SCREEN, end="")
    print("== key_tape integration dashboard ==============================================")
    print(f"   ledger:    {DB_PATH}")
    print(f"   refresh:   every {REFRESH_SEC}s · Ctrl-C to stop")
    print(f"   baseline:  captured at {baseline['captured_at']}")
    print("=================================================================================")
    print()

    total = query_one(conn, "SELECT COUNT(*) FROM theories")
    last_write = query_one(conn, "SELECT MAX(created_at) FROM theories")
    delta_total = total - baseline["total"]

    print(f"THEORIES   total {total}    Δ since dashboard start: +{delta_total}")
    print(f"           last write: {fmt_age(last_write)}")
    print()

    kt_total = query_one(
        conn, "SELECT COUNT(*) FROM theories WHERE family = ?", (KEY_TAPE_FAMILY,)
    )
    kt_delta = kt_total - baseline["key_tape_total"]
    kt_last = query_one(
        conn,
        "SELECT MAX(created_at) FROM theories WHERE family = ?",
        (KEY_TAPE_FAMILY,),
    )
    flag = "  *** NEW key_tape ACTIVITY ***" if kt_delta > 0 else ""
    print(f"KEY_TAPE   family count {kt_total}    Δ since start: +{kt_delta}{flag}")
    print(f"           last key_tape write: {fmt_age(kt_last)}")
    print()

    print("RECENT (last 60 min, by family):")
    rows = query_all(
        conn,
        """
        SELECT family, COUNT(*) AS n, MAX(best_score) AS best
        FROM theories
        WHERE created_at > datetime('now', '-60 minutes')
        GROUP BY family
        ORDER BY n DESC
        LIMIT 10
        """,
    )
    if rows:
        for family, n, best in rows:
            best_str = f"{best:.1f}" if best is not None else "—"
            print(f"  {family:35s}  +{n:3d}    best ngram: {best_str}")
    else:
        print("  (no theories in last 60 min)")
    print()

    print("TOP SCORES (last 60 min):")
    rows = query_all(
        conn,
        """
        SELECT hypothesis_id, family, best_score, status, title
        FROM theories
        WHERE created_at > datetime('now', '-60 minutes')
        ORDER BY best_score DESC
        LIMIT 5
        """,
    )
    if rows:
        for hid, family, score, status, title in rows:
            score_str = f"{score:.2f}" if score is not None else "—"
            title_short = (title or "")[:60]
            warn = "  <-- !!" if (score is not None and score >= 18) else ""
            print(f"  {hid[:12]}  {family[:18]:18s}  score={score_str:>6s}  {status[:12]:12s}  {title_short}{warn}")
    else:
        print("  (no theories in last 60 min)")
    print()

    print("VERDICTS (last 60 min):")
    rows = query_all(
        conn,
        """
        SELECT json_extract(critic_verdict, '$.decision') AS verdict, COUNT(*)
        FROM theories
        WHERE created_at > datetime('now', '-60 minutes')
          AND critic_verdict != '{}'
        GROUP BY verdict
        ORDER BY 2 DESC
        """,
    )
    if rows:
        for verdict, n in rows:
            print(f"  {verdict or '(none)':30s}  {n}")
    else:
        print("  (no verdicts in last 60 min)")
    print()

    # NOTE: kernel-override count comes from log-parsing, not the ledger
    # schema. k4_monitor.py displays "6 KERNEL OVR lifetime" by scanning
    # long_run_*.log; we can't reproduce that without a log file. Skipping.

    signal_count = query_one(
        conn,
        "SELECT COUNT(*) FROM theories WHERE best_score >= 18",
    )
    signal_delta = signal_count - baseline["signal_count"]
    flag = "  ⚡ NEW SIGNAL HIT ⚡" if signal_delta > 0 else ""
    print(f"SIGNAL-RANGE (best_score >= 18) lifetime: {signal_count}    Δ since start: +{signal_delta}{flag}")
    print()

    print(f"-- last refresh {datetime.now().strftime('%H:%M:%S')} --")


def capture_baseline(conn):
    return {
        "captured_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": query_one(conn, "SELECT COUNT(*) FROM theories"),
        "key_tape_total": query_one(
            conn,
            "SELECT COUNT(*) FROM theories WHERE family = ?",
            (KEY_TAPE_FAMILY,),
        ),
        "signal_count": query_one(
            conn,
            "SELECT COUNT(*) FROM theories WHERE best_score >= 18",
        ),
    }


def main():
    if not os.path.exists(DB_PATH):
        print(f"ERROR: ledger not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    # Open in read-only mode so we never lock the controller's writes
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2.0)
    try:
        baseline = capture_baseline(conn)
        while True:
            render(conn, baseline)
            time.sleep(REFRESH_SEC)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
