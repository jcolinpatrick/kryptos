#!/usr/bin/env python3
"""Admin CLI for managing the kryptosbot.com theory queue.

Usage:
    python3 api/admin.py list                    # Show all pending theories
    python3 api/admin.py all                     # Show ALL theories (any status)
    python3 api/admin.py test <id>               # Mark theory as "testing"
    python3 api/admin.py publish <id> [note]     # Mark as published (tested & added to site)
    python3 api/admin.py reject <id> [reason]    # Reject with optional reason
    python3 api/admin.py count                   # Count pending theories
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.queue import init_db, get_pending, update_status, _get_connection, DB_PATH


def list_pending():
    """Show all pending theories."""
    theories = get_pending()
    if not theories:
        print("No pending theories.")
        return
    print(f"\n{'='*70}")
    print(f"PENDING THEORIES ({len(theories)})")
    print(f"{'='*70}")
    for t in theories:
        print(f"\n  ID: {t['id']}")
        print(f"  Submitted: {t['timestamp']}")
        print(f"  Theory: {t['theory_text'][:200]}")
        if len(t['theory_text']) > 200:
            print(f"           ...({len(t['theory_text'])} chars total)")
        print(f"  Status: {t['status']}")
        print(f"  {'-'*60}")


def list_all():
    """Show all theories regardless of status."""
    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT id, theory_text, timestamp, status FROM theories ORDER BY timestamp DESC"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        print("No theories in database.")
        return

    print(f"\n{'='*70}")
    print(f"ALL THEORIES ({len(rows)})")
    print(f"{'='*70}")
    for r in rows:
        status_marker = {
            'pending': '⏳',
            'testing': '🔬',
            'published': '✅',
            'rejected': '❌',
        }.get(r['status'], '?')
        print(f"\n  {status_marker} [{r['id']}] {r['status'].upper()} — {r['timestamp'][:16]}")
        print(f"     {r['theory_text'][:120]}")


def count_pending():
    """Print count of pending theories."""
    theories = get_pending()
    print(len(theories))


def mark_testing(theory_id: int):
    """Mark a theory as being tested."""
    update_status(theory_id, "testing")
    print(f"Theory #{theory_id} marked as TESTING.")


def mark_published(theory_id: int, note: str = ""):
    """Mark a theory as published (tested and added to site)."""
    update_status(theory_id, "published")
    print(f"Theory #{theory_id} marked as PUBLISHED.")
    if note:
        print(f"  Note: {note}")


def mark_rejected(theory_id: int, reason: str = ""):
    """Reject a theory."""
    update_status(theory_id, "rejected")
    print(f"Theory #{theory_id} REJECTED.")
    if reason:
        print(f"  Reason: {reason}")


def main():
    init_db()

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "list":
        list_pending()
    elif cmd == "all":
        list_all()
    elif cmd == "count":
        count_pending()
    elif cmd == "test" and len(sys.argv) >= 3:
        mark_testing(int(sys.argv[2]))
    elif cmd == "publish" and len(sys.argv) >= 3:
        note = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else ""
        mark_published(int(sys.argv[2]), note)
    elif cmd == "reject" and len(sys.argv) >= 3:
        reason = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else ""
        mark_rejected(int(sys.argv[2]), reason)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
