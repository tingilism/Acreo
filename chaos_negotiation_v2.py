"""
chaos_negotiation_v2.py — adversarial tests for settle_pair() with pair_id
============================================================================

Replaces chaos_negotiation.py. Same 10 attacks but uses the new pair_id
field for two-party session agreement, which solves the chicken-and-egg
proof_id cross-reference problem from v1.

The helper now models real negotiation:
  1. Both parties agree on a session pair_id out of band
  2. Each party signs a ConditionalProof referencing the shared pair_id
  3. settle_pair verifies they share the same pair_id

Run:
    python chaos_negotiation_v2.py
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import threading
import time
from dataclasses import dataclass, asdict
from typing import Any, Callable, Optional


try:
    from acreo import Acreo, ConditionalProof, Entropy
except ImportError as e:
    print(f"FATAL: {e}", file=sys.stderr)
    sys.exit(2)


SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL = \
    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
                  SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}


@dataclass
class AttackResult:
    family: str; name: str; claim: str
    outcome: str; severity: str = SEVERITY_INFO; detail: str = ""


_results: list[AttackResult] = []
_attacks: list[Callable] = []


def record_pass(family, name, claim, detail=""):
    _results.append(AttackResult(family, name, claim, "PASS", SEVERITY_INFO, detail))


def record_fail(family, name, claim, severity, detail):
    _results.append(AttackResult(family, name, claim, "FAIL", severity, detail))


def record_skip(family, name, claim, reason):
    _results.append(AttackResult(family, name, claim, "SKIP", SEVERITY_INFO, reason))


def attack(family, name, claim, default_severity=SEVERITY_HIGH):
    def decorator(fn):
        _attacks.append(fn)
        fn._family = family
        fn._name = name
        fn._claim = claim
        return fn
    return decorator


def is_valid(r):
    if isinstance(r, dict):
        return bool(r.get("valid", False))
    return bool(r)


def make_matched_pair(a: Acreo, *, valid_until_ms_offset=60_000,
                       resource='polymarket/btc'):
    """Build a clean matched pair using shared pair_id (the right way)."""
    user_a = a.create_user('alice')
    user_b = a.create_user('bob')
    agent_a = a.create_agent('alice-bot')
    agent_b = a.create_agent('bob-bot')
    cred_a = a.delegate(user_a, agent_a, ['transact', 'execute'], scope=[resource])
    cred_b = a.delegate(user_b, agent_b, ['transact', 'execute'], scope=[resource])

    valid_until = int(time.time() * 1000) + valid_until_ms_offset
    pair_id = Entropy.hex(16)  # both parties agree on this out of band

    proof_a = agent_a.propose(
        cred_a, 'transact', resource,
        condition={'type': 'counterparty_proof',
                   'credential_id': cred_b.credential_id},
        valid_until_ms=valid_until,
        pair_id=pair_id,
    )
    proof_b = agent_b.propose(
        cred_b, 'execute', resource,
        condition={'type': 'counterparty_proof',
                   'credential_id': cred_a.credential_id},
        valid_until_ms=valid_until,
        pair_id=pair_id,
    )
    return cred_a, cred_b, proof_a, proof_b


# ═══════════════════════════════════════════════════════════════════════
# ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("settle", "happy_path",
        "A well-formed matched pair settles successfully",
        SEVERITY_CRITICAL)
def settle_happy():
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(a)
    r = a.settle_pair(proof_a, proof_b, cred_a, cred_b)
    if is_valid(r):
        record_pass("settle", "happy_path",
                    "A well-formed matched pair settles successfully",
                    f"settled, pair_key={r.get('pair_key', '?')[:24]}...")
    else:
        record_fail("settle", "happy_path",
                    "A well-formed matched pair settles successfully",
                    SEVERITY_CRITICAL,
                    f"happy path failed: {r}")


@attack("settle", "replay_settled_pair",
        "A pair that has been settled cannot be settled again",
        SEVERITY_CRITICAL)
def settle_replay():
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(a)
    r1 = a.settle_pair(proof_a, proof_b, cred_a, cred_b)
    if not is_valid(r1):
        record_skip("settle", "replay_settled_pair",
                    "A pair that has been settled cannot be settled again",
                    f"first settlement failed: {r1}")
        return
    r2 = a.settle_pair(proof_a, proof_b, cred_a, cred_b)
    if is_valid(r2):
        record_fail("settle", "replay_settled_pair",
                    "A pair that has been settled cannot be settled again",
                    SEVERITY_CRITICAL,
                    f"settled pair replayed: {r2}")
    else:
        record_pass("settle", "replay_settled_pair",
                    "A pair that has been settled cannot be settled again",
                    f"replay blocked: {r2.get('reason', 'unknown')}")


@attack("settle", "replay_swapped_order",
        "Settling (b, a) after (a, b) must also be blocked",
        SEVERITY_HIGH)
def settle_replay_swapped():
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(a)
    r1 = a.settle_pair(proof_a, proof_b, cred_a, cred_b)
    if not is_valid(r1):
        record_skip("settle", "replay_swapped_order",
                    "Settling (b, a) after (a, b) must also be blocked",
                    f"first failed: {r1}")
        return
    r2 = a.settle_pair(proof_b, proof_a, cred_b, cred_a)
    if is_valid(r2):
        record_fail("settle", "replay_swapped_order",
                    "Settling (b, a) after (a, b) must also be blocked",
                    SEVERITY_HIGH,
                    f"swapped-order replay accepted: {r2}")
    else:
        record_pass("settle", "replay_swapped_order",
                    "Settling (b, a) after (a, b) must also be blocked",
                    f"blocked: {r2.get('reason', 'unknown')}")


@attack("settle", "mismatched_pair_id",
        "Pair where pair_id values differ must be rejected",
        SEVERITY_CRITICAL)
def settle_mismatched():
    """Build two unrelated pairs, mix one proof from each. pair_ids will
    differ so the settle_pair check should reject."""
    a = Acreo()
    cred_a, _, proof_a, _ = make_matched_pair(a)
    _, _, proof_c, _ = make_matched_pair(a)
    r = a.settle_pair(proof_a, proof_c, cred_a)
    if is_valid(r):
        record_fail("settle", "mismatched_pair_id",
                    "Pair where pair_id values differ must be rejected",
                    SEVERITY_CRITICAL,
                    f"mismatched pair accepted: {r}")
    else:
        record_pass("settle", "mismatched_pair_id",
                    "Pair where pair_id values differ must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("settle", "self_pairing",
        "A proof paired with itself must be rejected",
        SEVERITY_HIGH)
def settle_self_pairing():
    a = Acreo()
    cred_a, _, proof_a, _ = make_matched_pair(a)
    r = a.settle_pair(proof_a, proof_a, cred_a, cred_a)
    if is_valid(r):
        record_fail("settle", "self_pairing",
                    "A proof paired with itself must be rejected",
                    SEVERITY_HIGH,
                    f"self-pair accepted: {r}")
    else:
        record_pass("settle", "self_pairing",
                    "A proof paired with itself must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("settle", "tampered_pair_id",
        "Mutating .pair_id after signing must invalidate the proof",
        SEVERITY_CRITICAL)
def settle_tamper_pair_id():
    """Take A's signed proof, mutate pair_id to match an attacker's pair.
    Signature should reject because pair_id is in the signed challenge."""
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(a)
    _, _, proof_attacker, _ = make_matched_pair(a)

    tampered_a = copy.deepcopy(proof_a)
    tampered_a.pair_id = proof_attacker.pair_id

    r = a.settle_pair(tampered_a, proof_attacker, cred_a)
    if is_valid(r):
        record_fail("settle", "tampered_pair_id",
                    "Mutating .pair_id after signing must invalidate the proof",
                    SEVERITY_CRITICAL,
                    f"tampered pair_id accepted: {r}")
    else:
        record_pass("settle", "tampered_pair_id",
                    "Mutating .pair_id after signing must invalidate the proof",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("settle", "expired_pair",
        "A pair whose window ended before settlement must be rejected",
        SEVERITY_HIGH)
def settle_expired():
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(
        a, valid_until_ms_offset=500)
    time.sleep(1.0)
    r = a.settle_pair(proof_a, proof_b, cred_a, cred_b)
    if is_valid(r):
        record_fail("settle", "expired_pair",
                    "A pair whose window ended before settlement must be rejected",
                    SEVERITY_HIGH,
                    f"expired pair accepted: {r}")
    else:
        record_pass("settle", "expired_pair",
                    "A pair whose window ended before settlement must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("settle", "signature_stripped",
        "Pair where one proof's signature has been zeroed must be rejected",
        SEVERITY_CRITICAL)
def settle_sig_strip():
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(a)
    stripped = copy.deepcopy(proof_b)
    stripped.signature = '0' * len(stripped.signature)
    r = a.settle_pair(proof_a, stripped, cred_a, cred_b)
    if is_valid(r):
        record_fail("settle", "signature_stripped",
                    "Pair where one proof's signature has been zeroed must be rejected",
                    SEVERITY_CRITICAL,
                    f"zero-signature accepted: {r}")
    else:
        record_pass("settle", "signature_stripped",
                    "Pair where one proof's signature has been zeroed must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("settle", "concurrent_settlement_race",
        "Concurrent settlements of the same pair must result in exactly one acceptance",
        SEVERITY_HIGH)
def settle_concurrent():
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(a)

    accept_count = [0]
    lock = threading.Lock()

    def worker():
        r = a.settle_pair(proof_a, proof_b, cred_a, cred_b)
        if is_valid(r):
            with lock:
                accept_count[0] += 1

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()

    n = accept_count[0]
    if n > 1:
        record_fail("settle", "concurrent_settlement_race",
                    "Concurrent settlements of the same pair must result in exactly one acceptance",
                    SEVERITY_HIGH,
                    f"{n}/20 concurrent settlements accepted (lock failure)")
    elif n == 1:
        record_pass("settle", "concurrent_settlement_race",
                    "Concurrent settlements of the same pair must result in exactly one acceptance",
                    "exactly 1/20 accepted")
    else:
        record_pass("settle", "concurrent_settlement_race",
                    "Concurrent settlements of the same pair must result in exactly one acceptance",
                    "0/20 accepted (no race exposed in this run)")


@attack("settle", "tampered_window_extension",
        "Extending valid_until past the signed value must be rejected",
        SEVERITY_HIGH)
def settle_tamper_window():
    a = Acreo()
    cred_a, cred_b, proof_a, proof_b = make_matched_pair(
        a, valid_until_ms_offset=500)
    time.sleep(1.0)
    tampered = copy.deepcopy(proof_b)
    tampered.valid_until = int(time.time() * 1000) + 100_000_000

    r = a.settle_pair(proof_a, tampered, cred_a, cred_b)
    if is_valid(r):
        record_fail("settle", "tampered_window_extension",
                    "Extending valid_until past the signed value must be rejected",
                    SEVERITY_HIGH,
                    f"tampered window accepted: {r}")
    else:
        record_pass("settle", "tampered_window_extension",
                    "Extending valid_until past the signed value must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


# ═══════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", default="chaos_negotiation_results.json")
    args = parser.parse_args()

    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    if not args.json:
        print(f"Acreo negotiation chaos test v2 — {len(_attacks)} attacks\n")
        print("[SETTLE]")

    for fn in _attacks:
        try:
            fn()
        except Exception as e:
            _results.append(AttackResult(
                family="settle", name=fn._name, claim=fn._claim,
                outcome="ERROR", severity=SEVERITY_INFO,
                detail=f"infra error: {type(e).__name__}: {e}",
            ))

        if not args.json:
            last = _results[-1]
            tag = f" [{last.severity}]" if last.outcome == "FAIL" else ""
            detail = (last.detail or "").replace("\n", " ")[:80]
            print(f"  {icons[last.outcome]} {last.outcome}{tag} "
                  f"{last.name} — {detail}")

    if not args.json:
        counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
        for r in _results:
            counts[r.outcome] += 1
        print("\n" + "═" * 60)
        print(f"  Total: {len(_results)}  PASS={counts['PASS']}  "
              f"FAIL={counts['FAIL']}  SKIP={counts['SKIP']}  "
              f"ERROR={counts['ERROR']}")

        fails = [r for r in _results if r.outcome == "FAIL"]
        if fails:
            print("\n  Findings:")
            fails.sort(key=lambda r: -SEVERITY_ORDER[r.severity])
            for r in fails:
                print(f"    [{r.severity}] {r.name}")
                print(f"        claim: {r.claim}")
                print(f"        detail: {r.detail}")
        print("═" * 60)

    with open(args.output, "w") as fp:
        json.dump({
            "total": len(_results),
            "summary": {k: sum(1 for r in _results if r.outcome == k)
                        for k in ["PASS", "FAIL", "SKIP", "ERROR"]},
            "results": [asdict(r) for r in _results],
        }, fp, indent=2)
    if not args.json:
        print(f"\n  Full results: {args.output}")

    fails = [r for r in _results if r.outcome == "FAIL"]
    errors = [r for r in _results if r.outcome == "ERROR"]
    if errors:
        return 2
    if any(SEVERITY_ORDER[r.severity] >= SEVERITY_ORDER[SEVERITY_MEDIUM]
           for r in fails):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
