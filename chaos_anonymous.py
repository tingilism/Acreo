"""
chaos_anonymous.py — adversarial tests for integrated anonymous proofs
========================================================================

Tests claims that the standalone acreo_anon.py self-test can't cover:
  - Witnesses flow through delegate() correctly
  - Verifier-side witness registry handles registration/lookup
  - Replay detection works at Acreo's nonce store level
  - Credential revocation still applies to anonymous flows
  - External-observer unlinkability holds across Acreo's API surface

Run:
    python chaos_anonymous.py
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Callable

try:
    from acreo import Acreo, AcreoError, CredentialError, ExpiredError
    from acreo_anon import AnonProof
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


def attack(family, name, claim):
    def decorator(fn):
        _attacks.append(fn)
        fn._family, fn._name, fn._claim = family, name, claim
        return fn
    return decorator


def is_valid(r):
    return bool(r.get("valid", False)) if isinstance(r, dict) else bool(r)


# ─── Helper ───────────────────────────────────────────────────────────

def setup(a=None):
    a = a or Acreo()
    operator = a.create_user('operator')
    bot = a.create_agent('trading-bot')
    cred = a.delegate(operator, bot, ['transact', 'execute'],
                       scope=['polymarket/*'])
    return a, operator, bot, cred


# ═══════════════════════════════════════════════════════════════════════
# ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("anon", "happy_path",
        "Bot generates anonymous proof, verifier accepts and identifies cred")
def anon_happy():
    a, operator, bot, cred = setup()
    proof = a.prove_anonymous(bot, cred, 'transact,execute')
    r = a.verify_anonymous(proof)
    if is_valid(r):
        record_pass("anon", "happy_path",
                    "Bot generates anonymous proof, verifier accepts and identifies cred",
                    f"matched cred={r.get('matched_credential_id', '')[:16]}...")
    else:
        record_fail("anon", "happy_path",
                    "Bot generates anonymous proof, verifier accepts and identifies cred",
                    SEVERITY_CRITICAL, f"unexpected reject: {r}")


@attack("anon", "external_unlinkability",
        "Two proofs from same credential have no shared public fields")
def anon_unlinkable():
    a, operator, bot, cred = setup()
    p1 = a.prove_anonymous(bot, cred, 'transact')
    p2 = a.prove_anonymous(bot, cred, 'transact')
    # Same credential should produce different pseudonyms, sigs, bindings
    if (p1.pseudonym != p2.pseudonym and
        p1.signature != p2.signature and
        p1.binding != p2.binding and
        p1.challenge != p2.challenge):
        record_pass("anon", "external_unlinkability",
                    "Two proofs from same credential have no shared public fields",
                    "all four public fields differ")
    else:
        record_fail("anon", "external_unlinkability",
                    "Two proofs from same credential have no shared public fields",
                    SEVERITY_CRITICAL,
                    f"shared fields: pseudonym={p1.pseudonym==p2.pseudonym} "
                    f"sig={p1.signature==p2.signature} "
                    f"binding={p1.binding==p2.binding}")


@attack("anon", "operator_can_correlate",
        "v0.1 KNOWN: operator can match both proofs to same credential")
def anon_operator_correlates():
    """This is the documented v0.1 limitation. Test confirms it works
    as designed — operator matches both proofs to same credential_id."""
    a, operator, bot, cred = setup()
    p1 = a.prove_anonymous(bot, cred, 'transact')
    p2 = a.prove_anonymous(bot, cred, 'transact')
    r1 = a.verify_anonymous(p1)
    r2 = a.verify_anonymous(p2)
    if (is_valid(r1) and is_valid(r2) and
        r1.get('matched_credential_id') == r2.get('matched_credential_id') == cred.credential_id):
        record_pass("anon", "operator_can_correlate",
                    "v0.1 KNOWN: operator can match both proofs to same credential",
                    "matched correctly (this is the v0.5 issue)")
    else:
        record_fail("anon", "operator_can_correlate",
                    "v0.1 KNOWN: operator can match both proofs to same credential",
                    SEVERITY_HIGH,
                    f"unexpected: r1={r1}, r2={r2}")


@attack("anon", "replay_blocked",
        "Same proof verified twice must be blocked on second use")
def anon_replay():
    a, operator, bot, cred = setup()
    proof = a.prove_anonymous(bot, cred, 'transact')
    r1 = a.verify_anonymous(proof)
    if not is_valid(r1):
        record_skip("anon", "replay_blocked",
                    "Same proof verified twice must be blocked on second use",
                    f"first verify failed: {r1}")
        return
    r2 = a.verify_anonymous(proof)
    if is_valid(r2):
        record_fail("anon", "replay_blocked",
                    "Same proof verified twice must be blocked on second use",
                    SEVERITY_HIGH, "replay accepted")
    else:
        record_pass("anon", "replay_blocked",
                    "Same proof verified twice must be blocked on second use",
                    f"replay rejected: {r2.get('reason')}")


@attack("anon", "no_witness_for_other_operator",
        "Proof made with operator A's witness doesn't verify against operator B's verifier")
def anon_wrong_operator():
    # Two separate operators, each with their own bot
    a1, op1, bot1, cred1 = setup()
    a2, op2, bot2, cred2 = setup(Acreo())  # different verifier instance
    proof = a1.prove_anonymous(bot1, cred1, 'transact')
    # Try to verify proof from a1 against a2's verifier (which has no record of cred1)
    r = a2.verify_anonymous(proof)
    if not is_valid(r):
        record_pass("anon", "no_witness_for_other_operator",
                    "Proof made with operator A's witness doesn't verify against operator B's verifier",
                    f"rejected: {r.get('reason')}")
    else:
        record_fail("anon", "no_witness_for_other_operator",
                    "Proof made with operator A's witness doesn't verify against operator B's verifier",
                    SEVERITY_CRITICAL, "cross-operator proof accepted")


@attack("anon", "tampered_pseudonym",
        "Mutating proof.pseudonym after generation must fail verification")
def anon_tampered():
    a, operator, bot, cred = setup()
    proof = a.prove_anonymous(bot, cred, 'transact')
    tampered = copy.deepcopy(proof)
    tampered.pseudonym = "00" * 32
    r = a.verify_anonymous(tampered)
    if not is_valid(r):
        record_pass("anon", "tampered_pseudonym",
                    "Mutating proof.pseudonym after generation must fail verification",
                    f"rejected: {r.get('reason')}")
    else:
        record_fail("anon", "tampered_pseudonym",
                    "Mutating proof.pseudonym after generation must fail verification",
                    SEVERITY_CRITICAL, "tampered pseudonym accepted")


@attack("anon", "revoked_credential_blocked",
        "Bot whose credential is revoked cannot generate new anonymous proofs")
def anon_revoked():
    a, operator, bot, cred = setup()
    bot._revoked.add(cred.credential_id)
    try:
        a.prove_anonymous(bot, cred, 'transact')
    except CredentialError:
        record_pass("anon", "revoked_credential_blocked",
                    "Bot whose credential is revoked cannot generate new anonymous proofs",
                    "CredentialError raised")
        return
    except Exception as e:
        record_fail("anon", "revoked_credential_blocked",
                    "Bot whose credential is revoked cannot generate new anonymous proofs",
                    SEVERITY_HIGH,
                    f"wrong exception: {type(e).__name__}: {e}")
        return
    record_fail("anon", "revoked_credential_blocked",
                "Bot whose credential is revoked cannot generate new anonymous proofs",
                SEVERITY_HIGH, "revoked cred allowed proof generation")


@attack("anon", "expired_credential_blocked_at_prove",
        "Expired credential cannot generate new anonymous proofs")
def anon_expired_at_prove():
    a, operator, bot, cred = setup()
    short = a.delegate(operator, bot, ['transact'], scope=['*'],
                        ttl_hours=0.0001)
    time.sleep(0.5)
    try:
        a.prove_anonymous(bot, short, 'transact')
    except ExpiredError:
        record_pass("anon", "expired_credential_blocked_at_prove",
                    "Expired credential cannot generate new anonymous proofs",
                    "ExpiredError raised at prove time")
        return
    except Exception as e:
        record_fail("anon", "expired_credential_blocked_at_prove",
                    "Expired credential cannot generate new anonymous proofs",
                    SEVERITY_HIGH,
                    f"wrong exception: {type(e).__name__}: {e}")
        return
    record_fail("anon", "expired_credential_blocked_at_prove",
                "Expired credential cannot generate new anonymous proofs",
                SEVERITY_HIGH, "expired cred allowed proof generation")


@attack("anon", "non_agent_blocked",
        "Users (non-agents) cannot generate anonymous proofs")
def anon_user_blocked():
    a, operator, bot, cred = setup()
    try:
        a.prove_anonymous(operator, cred, 'transact')
    except (AcreoError, CredentialError):
        record_pass("anon", "non_agent_blocked",
                    "Users (non-agents) cannot generate anonymous proofs",
                    "raised as expected")
        return
    except Exception as e:
        record_fail("anon", "non_agent_blocked",
                    "Users (non-agents) cannot generate anonymous proofs",
                    SEVERITY_MEDIUM,
                    f"wrong exception: {type(e).__name__}: {e}")
        return
    record_fail("anon", "non_agent_blocked",
                "Users (non-agents) cannot generate anonymous proofs",
                SEVERITY_MEDIUM, "user successfully made anonymous proof")


@attack("anon", "claim_filter_works",
        "verify_anonymous with claim filter rejects proofs for different claims")
def anon_claim_filter():
    a, operator, bot, cred = setup()
    proof = a.prove_anonymous(bot, cred, 'transact')
    # Verify with wrong claim filter
    r = a.verify_anonymous(proof, claim='different_claim')
    if not is_valid(r):
        record_pass("anon", "claim_filter_works",
                    "verify_anonymous with claim filter rejects proofs for different claims",
                    f"rejected: {r.get('reason')}")
    else:
        record_fail("anon", "claim_filter_works",
                    "verify_anonymous with claim filter rejects proofs for different claims",
                    SEVERITY_MEDIUM, "wrong-claim proof accepted")


# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="chaos_anonymous_results.json")
    args = parser.parse_args()

    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    print(f"Acreo anonymous-proof chaos test — {len(_attacks)} attacks\n")
    print("[ANON]")

    for fn in _attacks:
        try:
            fn()
        except Exception as e:
            _results.append(AttackResult(
                family="anon", name=fn._name, claim=fn._claim,
                outcome="ERROR", severity=SEVERITY_INFO,
                detail=f"infra error: {type(e).__name__}: {e}",
            ))

        last = _results[-1]
        tag = f" [{last.severity}]" if last.outcome == "FAIL" else ""
        detail = (last.detail or "").replace("\n", " ")[:80]
        print(f"  {icons[last.outcome]} {last.outcome}{tag} "
              f"{last.name} — {detail}")

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
            "summary": counts,
            "results": [asdict(r) for r in _results],
        }, fp, indent=2)
    print(f"\n  Full results: {args.output}")

    if any(r.outcome == "ERROR" for r in _results):
        return 2
    if any(SEVERITY_ORDER[r.severity] >= SEVERITY_ORDER[SEVERITY_MEDIUM]
           for r in fails):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
