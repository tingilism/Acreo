"""
fix_pq_d1c_findings.py — close two D-1c chaos test findings
=============================================================

Two patches:
  1. verify_proposal credential signature check is suite-aware.
     Was: bare _verify(issuer_pub, ...) — fails for PQ credentials.
     Now: dispatches via cred.crypto_suite same as Verifier.verify does.

  2. Identity._x25519_keypair raises if called on a PQ identity.
     Was: silently runs SHA-512 of PQ seed and produces a 64-char X25519
          key from PQ key material, claiming post-quantum security but
          actually operating in classical X25519 group. Wrong.
     Now: explicit AcreoError. Sealed messaging on PQ identities is
          deferred to D-2 (ML-KEM).

Anchors verified against lines 983 (verify_proposal cred check) and
596 (_x25519_keypair method head).

Usage:
    python fix_pq_d1c_findings.py
"""

import sys
import shutil
from pathlib import Path

ACREO = Path("acreo.py")


# ─── P1: verify_proposal credential signature dispatch ──────────────
P1_ANCHOR = """        if not _verify(issuer_pub, bytes.fromhex(_challenge(cred_payload)), c.signature):
            return fail('proposal_credential_signature_invalid')"""

P1_NEW = """        # Stage D-1c follow-up: suite-aware credential signature check
        # in verify_proposal (was bare _verify, now dispatches by cred.crypto_suite)
        prop_cred_suite = getattr(c, 'crypto_suite', 'ed25519')
        prop_cred_challenge = _challenge(cred_payload)
        if prop_cred_suite == 'ed25519':
            prop_cred_sig_ok = _verify(issuer_pub,
                                        bytes.fromhex(prop_cred_challenge),
                                        c.signature)
        elif prop_cred_suite == 'ml-dsa-65':
            prop_cred_sig_ok = _verify_pq(bytes.fromhex(issuer_pub),
                                           bytes.fromhex(prop_cred_challenge),
                                           bytes.fromhex(c.signature))
        else:
            prop_cred_sig_ok = False
        if not prop_cred_sig_ok:
            return fail('proposal_credential_signature_invalid')"""

P1_MARKER = "# Stage D-1c follow-up: suite-aware credential signature check"


# ─── P2: _x25519_keypair raises on PQ identity ──────────────────────
# Inject the suite check at the start of the method body, AFTER the
# existing docstring and the existing 'if self.kind not in' check.
# Use a precise anchor that includes the existing kind-check line so
# we can inject right after it.

P2_ANCHOR = """        if self.kind not in ('user', 'agent'):
            raise AcreoError(\"only user/agent identities have private keys\")
        if not hasattr(self, '_x25519_cache'):"""

P2_NEW = """        if self.kind not in ('user', 'agent'):
            raise AcreoError(\"only user/agent identities have private keys\")
        # Stage D-1c follow-up: PQ identities don't have a sound X25519
        # derivation. Sealed messaging for PQ identities is D-2 (ML-KEM).
        if getattr(self, 'crypto_suite', 'ed25519') != 'ed25519':
            raise AcreoError(
                f'sealed messaging not yet supported for crypto_suite='
                f'{self.crypto_suite!r} (D-2 will add ML-KEM)')
        if not hasattr(self, '_x25519_cache'):"""

P2_MARKER = "# Stage D-1c follow-up: PQ identities don't have a sound X25519"


PATCHES = [
    ("1. verify_proposal cred sig dispatch by suite", P1_ANCHOR, P1_NEW, P1_MARKER),
    ("2. _x25519_keypair raises on PQ identity", P2_ANCHOR, P2_NEW, P2_MARKER),
]


def main():
    if not ACREO.exists():
        print(f"ERROR: {ACREO} not found.")
        sys.exit(2)

    content = ACREO.read_text(encoding="utf-8")
    backup = Path("acreo.py.bak-pq-d1c-fix")
    shutil.copy(ACREO, backup)
    print(f"Backup: {backup}\n")

    patched = content
    for i, (name, anchor, new, marker) in enumerate(PATCHES, 1):
        if marker in patched:
            print(f"  [{i}] {name}: ALREADY APPLIED")
            continue
        if anchor not in patched:
            print(f"  [{i}] {name}: SKIP — anchor not found")
            print(f"      anchor first line: {anchor.splitlines()[0][:80]!r}")
            print(f"\nReverting from backup.")
            shutil.copy(backup, ACREO)
            sys.exit(1)
        patched = patched.replace(anchor, new, 1)
        print(f"  [{i}] {name}: APPLIED")

    ACREO.write_text(patched, encoding="utf-8")

    written = ACREO.read_text(encoding="utf-8")
    missing = [m for _, _, _, m in PATCHES if m not in written]
    if missing:
        print(f"\nVerification FAILED. Missing markers:")
        for m in missing:
            print(f"  - {m[:70]}")
        shutil.copy(backup, ACREO)
        print("Reverted from backup.")
        sys.exit(1)

    print(f"\n✓ All 2 markers verified.")
    print()
    print("D-1c findings closed. Run regression + chaos suites:")
    print("  python acreo.py")
    print("  python chaos_test.py")
    print("  python chaos_heartbeat.py")
    print("  python test_proposal.py")
    print("  python chaos_negotiation_v2.py")
    print("  python test_sealed.py")
    print("  python chaos_reports.py")
    print("  python chaos_anonymous.py")
    print("  python test_pq_smoke.py")
    print("  python chaos_postquantum.py  # all 12 should now pass")


if __name__ == "__main__":
    main()
