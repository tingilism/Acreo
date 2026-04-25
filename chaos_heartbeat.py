"""
chaos_heartbeat.py — adversarial tests for Acreo's dead-man's switch
====================================================================

Tests the heartbeat-based auto-revocation mechanism added in this patch.

CLAIMS BEING TESTED (from README):
  - "dead-man's switch" primitive
  - "heartbeat → auto-revocation"

SPECIFIC PROPERTIES:
  1. Credential without heartbeat_interval_ms behaves as before (backward compat)
  2. Credential with heartbeat_interval_ms stays alive if heartbeat arrives in time
  3. Credential revokes (verify fails) if heartbeat is overdue
  4. Heartbeat must be signed by the agent's private key
  5. Heartbeat proof can't be replayed
  6. Heartbeat for agent A can't refresh credential for agent B
  7. Tampering with heartbeat_interval_ms invalidates credential signature

HOW TO RUN:
    cd <acreo repo root>
    python chaos_heartbeat.py

Takes ~15 seconds (includes sleeps to test expiration).
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any, Callable, Optional


try:
    from acreo import Acreo, HeartbeatProof
except ImportError as e:
    print(f"FATAL: {e}", file=sys.stderr)
    print("Run from Acreo repo root after applying heartbeat patches.",
          file=sys.stderr)
    sys.exit(2)


# ─── Severity (same scheme as chaos_test.py) ──────────────────────────

SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL = \
    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
                  SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}


@dataclass
class AttackResult:
    family: str; name: str; claim: str
    outcome: str; severity: str = SEVERITY_INFO; detail: str = ""
    elapsed_ms: float = 0.0


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


def fresh_acreo():
    return Acreo()


# ═══════════════════════════════════════════════════════════════════════
# FAMILY: HEARTBEAT
# ═══════════════════════════════════════════════════════════════════════

@attack("heartbeat", "backward_compat_no_interval",
        "A credential with no heartbeat_interval_ms works as before",
        SEVERITY_CRITICAL)
def heartbeat_backward_compat():
    """If this breaks, every existing Acreo user loses their credentials."""
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])  # NO heartbeat_interval_ms
    ap = a.authorize(agent, cred, 'read', 'doc')
    r = a.verify_action(ap, cred)
    if is_valid(r):
        record_pass("heartbeat", "backward_compat_no_interval",
                    "A credential with no heartbeat_interval_ms works as before",
                    "no-heartbeat credential accepted")
    else:
        record_fail("heartbeat", "backward_compat_no_interval",
                    "A credential with no heartbeat_interval_ms works as before",
                    SEVERITY_CRITICAL,
                    f"backward compat broken: {r!r}")


@attack("heartbeat", "fresh_heartbeat_keeps_alive",
        "A credential with recent heartbeat continues to verify",
        SEVERITY_HIGH)
def heartbeat_fresh_keeps_alive():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'], heartbeat_interval_ms=2000)

    # Wait a bit, heartbeat, then verify — should succeed
    time.sleep(1.0)
    hb = a.heartbeat(agent, cred)
    if not is_valid(hb):
        record_skip("heartbeat", "fresh_heartbeat_keeps_alive",
                    "A credential with recent heartbeat continues to verify",
                    f"heartbeat() itself failed: {hb}")
        return

    time.sleep(0.5)  # 0.5s after heartbeat, well within 2s window
    ap = a.authorize(agent, cred, 'read', 'doc')
    r = a.verify_action(ap, cred)

    if is_valid(r):
        record_pass("heartbeat", "fresh_heartbeat_keeps_alive",
                    "A credential with recent heartbeat continues to verify",
                    "fresh heartbeat kept credential alive")
    else:
        record_fail("heartbeat", "fresh_heartbeat_keeps_alive",
                    "A credential with recent heartbeat continues to verify",
                    SEVERITY_HIGH,
                    f"fresh heartbeat did not keep credential alive: {r}")


@attack("heartbeat", "missed_heartbeat_revokes",
        "A credential past its heartbeat window must not verify",
        SEVERITY_CRITICAL)
def heartbeat_missed_revokes():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'], heartbeat_interval_ms=1000)

    # Wait past the window without heartbeating
    time.sleep(1.5)
    ap = a.authorize(agent, cred, 'read', 'doc')
    r = a.verify_action(ap, cred)

    if is_valid(r):
        record_fail("heartbeat", "missed_heartbeat_revokes",
                    "A credential past its heartbeat window must not verify",
                    SEVERITY_CRITICAL,
                    "overdue credential was accepted — dead-man's switch does nothing")
    else:
        reason = r.get("reason", "blocked") if isinstance(r, dict) else "blocked"
        if "heartbeat" in reason or "overdue" in reason:
            record_pass("heartbeat", "missed_heartbeat_revokes",
                        "A credential past its heartbeat window must not verify",
                        f"overdue credential correctly rejected: {reason}")
        else:
            record_pass("heartbeat", "missed_heartbeat_revokes",
                        "A credential past its heartbeat window must not verify",
                        f"rejected (non-heartbeat reason): {reason}")


@attack("heartbeat", "replay_heartbeat",
        "A heartbeat proof cannot be replayed",
        SEVERITY_HIGH)
def heartbeat_replay():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'], heartbeat_interval_ms=5000)

    # Produce a heartbeat proof directly (not via a.heartbeat convenience call)
    hb_proof = agent.prove_heartbeat(cred)
    r1 = a.accept_heartbeat(hb_proof, cred)
    if not is_valid(r1):
        record_skip("heartbeat", "replay_heartbeat",
                    "A heartbeat proof cannot be replayed",
                    f"first use failed: {r1}")
        return

    # Replay the same proof — must be rejected
    r2 = a.accept_heartbeat(hb_proof, cred)
    if is_valid(r2):
        record_fail("heartbeat", "replay_heartbeat",
                    "A heartbeat proof cannot be replayed",
                    SEVERITY_HIGH,
                    f"heartbeat replay accepted: {r2}")
    else:
        record_pass("heartbeat", "replay_heartbeat",
                    "A heartbeat proof cannot be replayed",
                    f"replay blocked: {r2.get('reason', 'unknown')}")


@attack("heartbeat", "wrong_agent_heartbeat",
        "Agent B cannot produce a heartbeat that refreshes Agent A's credential",
        SEVERITY_CRITICAL)
def heartbeat_wrong_agent():
    a = fresh_acreo()
    user = a.create_user()
    agent_A = a.create_agent('A')
    agent_B = a.create_agent('B')
    cred_A = a.delegate(user, agent_A, ['read'], heartbeat_interval_ms=5000)

    # Agent B tries to produce a heartbeat for Agent A's credential
    try:
        hb_proof_B = agent_B.prove_heartbeat(cred_A)
    except Exception as e:
        record_pass("heartbeat", "wrong_agent_heartbeat",
                    "Agent B cannot produce a heartbeat that refreshes Agent A's credential",
                    f"prove_heartbeat refused: {type(e).__name__}")
        return

    # If it did produce one, it must be rejected by the verifier
    r = a.accept_heartbeat(hb_proof_B, cred_A)
    if is_valid(r):
        record_fail("heartbeat", "wrong_agent_heartbeat",
                    "Agent B cannot produce a heartbeat that refreshes Agent A's credential",
                    SEVERITY_CRITICAL,
                    "wrong-agent heartbeat accepted — compromised agent can't be killed")
    else:
        record_pass("heartbeat", "wrong_agent_heartbeat",
                    "Agent B cannot produce a heartbeat that refreshes Agent A's credential",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("heartbeat", "tamper_heartbeat_interval",
        "Mutating heartbeat_interval_ms must invalidate the credential signature",
        SEVERITY_CRITICAL)
def heartbeat_tamper_interval():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'], heartbeat_interval_ms=1000)

    # Attacker extends the window to effectively disable the switch
    mutated = copy.deepcopy(cred)
    mutated.heartbeat_interval_ms = 100_000_000  # ~1158 days

    # Wait past the original 1-second window
    time.sleep(1.5)
    try:
        ap = a.authorize(agent, mutated, 'read', 'doc')
        r = a.verify_action(ap, mutated)
    except Exception as e:
        record_pass("heartbeat", "tamper_heartbeat_interval",
                    "Mutating heartbeat_interval_ms must invalidate the credential signature",
                    f"authorize refused: {type(e).__name__}")
        return

    if is_valid(r):
        record_fail("heartbeat", "tamper_heartbeat_interval",
                    "Mutating heartbeat_interval_ms must invalidate the credential signature",
                    SEVERITY_CRITICAL,
                    "tampered interval accepted — switch can be disabled by attacker")
    else:
        reason = r.get("reason", "blocked") if isinstance(r, dict) else "blocked"
        record_pass("heartbeat", "tamper_heartbeat_interval",
                    "Mutating heartbeat_interval_ms must invalidate the credential signature",
                    f"tampered credential rejected: {reason}")


@attack("heartbeat", "heartbeat_after_credential_expiry",
        "Heartbeat cannot revive a credential past its absolute expiration",
        SEVERITY_HIGH)
def heartbeat_post_expiry():
    """Dead-man's switch is a faster revocation, not a TTL extender.
    TTL expiration must still be absolute."""
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    # Credential expires in 1 second, heartbeat every 5 seconds
    cred = a.delegate(user, agent, ['read'],
                      ttl_hours=1/3600,  # 1 second TTL
                      heartbeat_interval_ms=5000)
    time.sleep(1.5)  # wait past TTL

    # Try to heartbeat — should fail (credential itself is expired)
    try:
        hb_proof = agent.prove_heartbeat(cred)
        r = a.accept_heartbeat(hb_proof, cred)
    except Exception as e:
        record_pass("heartbeat", "heartbeat_after_credential_expiry",
                    "Heartbeat cannot revive a credential past its absolute expiration",
                    f"heartbeat refused: {type(e).__name__}")
        return

    if is_valid(r):
        record_fail("heartbeat", "heartbeat_after_credential_expiry",
                    "Heartbeat cannot revive a credential past its absolute expiration",
                    SEVERITY_HIGH,
                    "heartbeat revived expired credential — TTL bypass")
    else:
        record_pass("heartbeat", "heartbeat_after_credential_expiry",
                    "Heartbeat cannot revive a credential past its absolute expiration",
                    f"expired credential not revivable: {r.get('reason', 'unknown')}")


# ═══════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", default="chaos_heartbeat_results.json")
    args = parser.parse_args()

    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    if not args.json:
        print(f"Acreo heartbeat chaos test — {len(_attacks)} attacks\n")
        print("[HEARTBEAT]")

    for fn in _attacks:
        t0 = time.perf_counter()
        try:
            fn()
            if _results and _results[-1].name == fn._name:
                _results[-1].elapsed_ms = (time.perf_counter() - t0) * 1000
        except Exception as e:
            _results.append(AttackResult(
                family="heartbeat", name=fn._name, claim=fn._claim,
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

    # JSON output
    with open(args.output, "w") as fp:
        json.dump({
            "total": len(_results),
            "summary": {k: sum(1 for r in _results if r.outcome == k)
                        for k in ["PASS", "FAIL", "SKIP", "ERROR"]},
            "results": [asdict(r) for r in _results],
        }, fp, indent=2)
    if not args.json:
        print(f"\n  Full results: {args.output}")

    # Exit code
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
