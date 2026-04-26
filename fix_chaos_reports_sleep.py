"""
fix_chaos_reports_sleep.py — fix the expired_credential test timing
====================================================================

The test creates a credential with ttl_hours=0.0001 (~360ms) then sleeps
200ms before verify. At verify time the credential has ~160ms left and is
still valid — so the test fails to actually test expiration.

Fix: sleep 500ms instead of 200ms. Credential is definitely expired at
verify time. The protocol's c.valid() check fires and the report is
correctly rejected.

Idempotent.
"""

import sys
import shutil
from pathlib import Path

TARGET = Path("chaos_reports.py")

FIND = "    time.sleep(0.2)  # let credential expire"
REPLACE = "    time.sleep(0.5)  # let credential expire (longer than 360ms ttl)"
MARKER = "time.sleep(0.5)  # let credential expire"


def main():
    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found.")
        sys.exit(2)

    content = TARGET.read_text(encoding="utf-8")

    if MARKER in content:
        print("Already applied.")
        return

    if FIND not in content:
        print("SKIP — could not find current sleep line.")
        sys.exit(1)

    shutil.copy(TARGET, Path("chaos_reports.py.bak-sleep"))
    print("Backup: chaos_reports.py.bak-sleep")

    TARGET.write_text(content.replace(FIND, REPLACE, 1), encoding="utf-8")
    print("APPLIED: sleep 0.2 → 0.5")
    print()
    print("Run: python chaos_reports.py")


if __name__ == "__main__":
    main()
