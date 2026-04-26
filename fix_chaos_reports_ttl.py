"""
fix_chaos_reports_ttl.py — patch the expired_credential test
==============================================================

The chaos test used ttl_ms=100 but Acreo's delegate signature is ttl_hours.
0.0001 hours = 360ms — short enough to expire by the time we verify, long
enough to create the report.

Idempotent.
"""

import sys
import shutil
from pathlib import Path

TARGET = Path("chaos_reports.py")

FIND = "    short_cred = a.delegate(operator, bot, ['transact'], scope=['*'],\n                             ttl_ms=100)"
REPLACE = "    short_cred = a.delegate(operator, bot, ['transact'], scope=['*'],\n                             ttl_hours=0.0001)"
MARKER = "ttl_hours=0.0001"


def main():
    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found.")
        sys.exit(2)

    content = TARGET.read_text(encoding="utf-8")

    if MARKER in content:
        print("Already applied — ttl_hours fix is in place.")
        return

    if FIND not in content:
        print("SKIP — anchor not found. Showing current text around expired_credential:")
        for i, line in enumerate(content.splitlines(), 1):
            if "expired_credential" in line.lower() or "short_cred" in line:
                print(f"  {i}: {line}")
        sys.exit(1)

    shutil.copy(TARGET, Path("chaos_reports.py.bak-ttl"))
    print("Backup: chaos_reports.py.bak-ttl")

    TARGET.write_text(content.replace(FIND, REPLACE, 1), encoding="utf-8")
    print("APPLIED: ttl_ms=100 → ttl_hours=0.0001")
    print()
    print("Run: python chaos_reports.py")


if __name__ == "__main__":
    main()
