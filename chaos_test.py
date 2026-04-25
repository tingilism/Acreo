"""
chaos_test.py — Acreo adversarial test suite
=============================================

Runs adversarial attacks against Acreo's local Python API. Tests authorization
correctness under deliberate misuse: replay, scope escalation, credential
forgery, expiration bypass, budget enforcement, malformed inputs, race
conditions.

WHAT THIS TESTS
  Local correctness of the Acreo Python library:
    - Verifier.verify rejects what it should reject
    - Identity.delegate produces credentials that can't be tampered with
    - AgentWallet enforces spending limits
    - MandatedAgent.act gates on wallet state and PII

WHAT THIS DOES NOT TEST
  - The deployed AgentVerifier.sol contract on Polygon Amoy (different surface)
  - The MCP server (acreo_mcp.py) when running as a network process
  - Side-channel attacks (timing, cache, memory analysis)
  - Cryptographic primitive correctness (assumes _sign/_verify/_keypair are sound)
  - Multi-process or distributed deployment scenarios

USAGE
  cd <acreo repo root>
  python chaos_test.py                  # run all attacks
  python chaos_test.py --family replay  # run one family
  python chaos_test.py --json           # machine-readable output only
  python chaos_test.py --strict         # exit nonzero on any non-PASS

OUTPUT
  Stdout: per-attack lines + summary table grouped by family and severity
  chaos_results.json: full results + metadata for CI/diffing across runs

EXIT CODES
  0  — all attacks blocked (or with --strict, all PASS)
  1  — one or more findings at MEDIUM+ severity
  2  — test infrastructure error (couldn't import, couldn't set up)

EXTENDING
  Add an attack by writing a function decorated with @attack(...). The
  decorator registers it with the runner. See existing attacks for the
  pattern. Each attack should call record_pass() or record_fail() exactly
  once per logical assertion.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
import threading
import time
import traceback
from dataclasses import dataclass, asdict
from typing import Any, Callable, Optional


# ─── Fixed seed for reproducibility ────────────────────────────────────
RANDOM_SEED = 0xACE0
random.seed(RANDOM_SEED)


# ─── Acreo import ──────────────────────────────────────────────────────
try:
    from acreo import Acreo
except ImportError as e:
    print(f"FATAL: cannot import Acreo ({e}).", file=sys.stderr)
    print("Run from the Acreo repo root where acreo.py lives.", file=sys.stderr)
    sys.exit(2)


# ─── Severity model ────────────────────────────────────────────────────
SEVERITY_INFO     = "INFO"
SEVERITY_LOW      = "LOW"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_HIGH     = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
                  SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}


# ─── Result tracking ───────────────────────────────────────────────────

@dataclass
class AttackResult:
    family: str
    name: str
    claim: str
    outcome: str
    severity: str = SEVERITY_INFO
    detail: str = ""
    elapsed_ms: float = 0.0


_results: list[AttackResult] = []
_attacks: list[Callable] = []


def record_pass(family, name, claim, detail=""):
    _results.append(AttackResult(family, name, claim, "PASS",
                                  SEVERITY_INFO, detail))


def record_fail(family, name, claim, severity, detail):
    assert severity in SEVERITY_ORDER, f"unknown severity {severity}"
    _results.append(AttackResult(family, name, claim, "FAIL",
                                  severity, detail))


def record_skip(family, name, claim, reason):
    _results.append(AttackResult(family, name, claim, "SKIP",
                                  SEVERITY_INFO, reason))


def attack(family, name, claim, default_severity=SEVERITY_HIGH):
    def decorator(fn):
        _attacks.append(fn)
        fn._family = family
        fn._name = name
        fn._claim = claim
        fn._default_severity = default_severity
        return fn
    return decorator


# ─── Helpers ───────────────────────────────────────────────────────────

def is_valid_proof_result(r: Any) -> bool:
    """verify_action returns a dict like {'valid': bool, 'reason': str}.
    Bare truthiness on the dict is wrong — any non-empty dict is True."""
    if isinstance(r, dict):
        return bool(r.get("valid", False))
    return bool(r)


def fresh_acreo() -> Acreo:
    return Acreo()


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 1: REPLAY ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("replay", "single_proof_used_twice",
        "An action proof must be accepted at most once",
        SEVERITY_CRITICAL)
def replay_basic():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read', 'write'])

    ap = a.authorize(agent, cred, 'write', 'doc_1')
    r1 = a.verify_action(ap, cred)
    if not is_valid_proof_result(r1):
        record_skip("replay", "single_proof_used_twice",
                    "An action proof must be accepted at most once",
                    f"first use rejected: {r1!r}")
        return

    r2 = a.verify_action(ap, cred)
    if is_valid_proof_result(r2):
        record_fail("replay", "single_proof_used_twice",
                    "An action proof must be accepted at most once",
                    SEVERITY_CRITICAL,
                    f"same proof accepted twice: {r2!r}")
    else:
        reason = r2.get("reason", "blocked") if isinstance(r2, dict) else "blocked"
        record_pass("replay", "single_proof_used_twice",
                    "An action proof must be accepted at most once",
                    f"second use blocked: {reason}")


@attack("replay", "burst_of_replays",
        "100 rapid replays of one proof must all be rejected after first",
        SEVERITY_CRITICAL)
def replay_burst():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])
    ap = a.authorize(agent, cred, 'read', 'doc_1')
    a.verify_action(ap, cred)

    accepted = sum(1 for _ in range(100)
                   if is_valid_proof_result(a.verify_action(ap, cred)))
    if accepted > 0:
        record_fail("replay", "burst_of_replays",
                    "100 rapid replays of one proof must all be rejected after first",
                    SEVERITY_CRITICAL,
                    f"{accepted}/100 replays accepted")
    else:
        record_pass("replay", "burst_of_replays",
                    "100 rapid replays of one proof must all be rejected after first",
                    "0/100 replays accepted")


@attack("replay", "fresh_verifier_no_shared_state",
        "Fresh verifier instance with no shared state cannot detect prior replays",
        SEVERITY_INFO)
def replay_cross_instance():
    """Documents that nonce stores are local to a Verifier instance.
    Distributed deployments need shared nonce state."""
    a1 = fresh_acreo()
    user = a1.create_user(); agent = a1.create_agent()
    cred = a1.delegate(user, agent, ['read'])
    ap = a1.authorize(agent, cred, 'read', 'doc_1')
    a1.verify_action(ap, cred)

    a2 = fresh_acreo()
    r = a2.verify_action(ap, cred)
    if is_valid_proof_result(r):
        record_pass("replay", "fresh_verifier_no_shared_state",
                    "Fresh verifier instance with no shared state cannot detect prior replays",
                    "EXPECTED: fresh instance accepts (in-process nonce store, by design)")
    else:
        record_pass("replay", "fresh_verifier_no_shared_state",
                    "Fresh verifier instance with no shared state cannot detect prior replays",
                    "fresh instance also blocked")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 2: SCOPE & PERMISSION ESCALATION
# ═══════════════════════════════════════════════════════════════════════

@attack("scope", "read_only_attempts_write",
        "A 'read'-only credential must not authorize 'write'",
        SEVERITY_CRITICAL)
def scope_read_to_write():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])

    try:
        ap = a.authorize(agent, cred, 'write', 'doc_1')
        r = a.verify_action(ap, cred)
    except Exception as e:
        record_pass("scope", "read_only_attempts_write",
                    "A 'read'-only credential must not authorize 'write'",
                    f"authorize() refused: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("scope", "read_only_attempts_write",
                    "A 'read'-only credential must not authorize 'write'",
                    SEVERITY_CRITICAL,
                    "read-only credential successfully authorized write")
    else:
        record_pass("scope", "read_only_attempts_write",
                    "A 'read'-only credential must not authorize 'write'",
                    f"verify rejected: {r.get('reason', 'unknown')}")


@attack("scope", "undeclared_permission",
        "A permission not in the credential's grant must be rejected",
        SEVERITY_HIGH)
def scope_undeclared():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])

    try:
        ap = a.authorize(agent, cred, 'delete', 'doc_1')
        r = a.verify_action(ap, cred)
    except Exception as e:
        record_pass("scope", "undeclared_permission",
                    "A permission not in the credential's grant must be rejected",
                    f"authorize() refused: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("scope", "undeclared_permission",
                    "A permission not in the credential's grant must be rejected",
                    SEVERITY_HIGH,
                    "undeclared permission accepted")
    else:
        record_pass("scope", "undeclared_permission",
                    "A permission not in the credential's grant must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("scope", "out_of_resource_scope",
        "Acting on a resource outside credential scope must be rejected",
        SEVERITY_HIGH)
def scope_resource():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'], scope=['files/public/*'])

    try:
        ap = a.authorize(agent, cred, 'read', 'files/private/secrets.txt')
        r = a.verify_action(ap, cred)
    except Exception as e:
        record_pass("scope", "out_of_resource_scope",
                    "Acting on a resource outside credential scope must be rejected",
                    f"authorize() refused: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("scope", "out_of_resource_scope",
                    "Acting on a resource outside credential scope must be rejected",
                    SEVERITY_HIGH,
                    "out-of-scope resource access accepted")
    else:
        record_pass("scope", "out_of_resource_scope",
                    "Acting on a resource outside credential scope must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 3: CREDENTIAL FORGERY & TAMPERING
# ═══════════════════════════════════════════════════════════════════════

@attack("forgery", "swap_credential_to_other_agent",
        "Agent B must not be able to use a credential issued for Agent A",
        SEVERITY_CRITICAL)
def forgery_wrong_agent():
    a = fresh_acreo()
    user = a.create_user()
    agent_A = a.create_agent('agent_A')
    agent_B = a.create_agent('agent_B')
    cred_for_A = a.delegate(user, agent_A, ['read', 'write'])

    try:
        ap = a.authorize(agent_B, cred_for_A, 'write', 'doc_1')
        r = a.verify_action(ap, cred_for_A)
    except Exception as e:
        record_pass("forgery", "swap_credential_to_other_agent",
                    "Agent B must not be able to use a credential issued for Agent A",
                    f"authorize() refused: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("forgery", "swap_credential_to_other_agent",
                    "Agent B must not be able to use a credential issued for Agent A",
                    SEVERITY_CRITICAL,
                    "wrong agent successfully used credential")
    else:
        record_pass("forgery", "swap_credential_to_other_agent",
                    "Agent B must not be able to use a credential issued for Agent A",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("forgery", "mutate_permissions",
        "Tampering with credential.permissions must invalidate the signature",
        SEVERITY_CRITICAL)
def forgery_mutate_perms():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])

    if not hasattr(cred, 'permissions'):
        record_skip("forgery", "mutate_permissions",
                    "Tampering with credential.permissions must invalidate the signature",
                    f"no .permissions attr (type={type(cred).__name__})")
        return

    mutated = copy.deepcopy(cred)
    mutated.permissions = ['read', 'write', 'admin', 'delete']

    try:
        ap = a.authorize(agent, mutated, 'admin', 'doc_1')
        r = a.verify_action(ap, mutated)
    except Exception as e:
        record_pass("forgery", "mutate_permissions",
                    "Tampering with credential.permissions must invalidate the signature",
                    f"authorize() refused: {type(e).__name__}: {e}")
        return

    if is_valid_proof_result(r):
        record_fail("forgery", "mutate_permissions",
                    "Tampering with credential.permissions must invalidate the signature",
                    SEVERITY_CRITICAL,
                    f"escalated permissions accepted: {r!r}")
    else:
        record_pass("forgery", "mutate_permissions",
                    "Tampering with credential.permissions must invalidate the signature",
                    f"signature rejected: {r.get('reason', 'unknown')}")


@attack("forgery", "extend_expiration",
        "Tampering with credential.expires_at must invalidate the signature",
        SEVERITY_HIGH)
def forgery_extend_exp():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'], ttl_hours=0.001)

    if not hasattr(cred, 'expires_at'):
        record_skip("forgery", "extend_expiration",
                    "Tampering with credential.expires_at must invalidate the signature",
                    "no .expires_at attribute")
        return

    mutated = copy.deepcopy(cred)
    mutated.expires_at = int(time.time() * 1000) + 100_000_000
    time.sleep(4.5)  # let original expire

    try:
        ap = a.authorize(agent, mutated, 'read', 'doc_1')
        r = a.verify_action(ap, mutated)
    except Exception as e:
        record_pass("forgery", "extend_expiration",
                    "Tampering with credential.expires_at must invalidate the signature",
                    f"authorize() refused: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("forgery", "extend_expiration",
                    "Tampering with credential.expires_at must invalidate the signature",
                    SEVERITY_HIGH,
                    "expiration extension accepted")
    else:
        record_pass("forgery", "extend_expiration",
                    "Tampering with credential.expires_at must invalidate the signature",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("forgery", "random_signature",
        "Random bytes substituted for credential signature must fail verification",
        SEVERITY_HIGH)
def forgery_random_sig():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])

    if not hasattr(cred, 'signature'):
        record_skip("forgery", "random_signature",
                    "Random bytes substituted for credential signature must fail verification",
                    "no .signature attribute")
        return

    mutated = copy.deepcopy(cred)
    sig_len = len(mutated.signature)
    mutated.signature = ''.join(random.choices('0123456789abcdef', k=sig_len))

    try:
        ap = a.authorize(agent, mutated, 'read', 'doc_1')
        r = a.verify_action(ap, mutated)
    except Exception as e:
        record_pass("forgery", "random_signature",
                    "Random bytes substituted for credential signature must fail verification",
                    f"authorize() refused: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("forgery", "random_signature",
                    "Random bytes substituted for credential signature must fail verification",
                    SEVERITY_HIGH,
                    "random signature accepted")
    else:
        record_pass("forgery", "random_signature",
                    "Random bytes substituted for credential signature must fail verification",
                    f"rejected: {r.get('reason', 'unknown')}")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 4: EXPIRATION & TIME ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("expiration", "expired_credential",
        "Credential past expires_at must not authorize new actions",
        SEVERITY_HIGH)
def expiration_basic():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'], ttl_hours=1/3600)
    time.sleep(2)

    try:
        ap = a.authorize(agent, cred, 'read', 'doc_1')
        r = a.verify_action(ap, cred)
    except Exception as e:
        record_pass("expiration", "expired_credential",
                    "Credential past expires_at must not authorize new actions",
                    f"authorize() refused: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("expiration", "expired_credential",
                    "Credential past expires_at must not authorize new actions",
                    SEVERITY_HIGH,
                    "expired credential accepted")
    else:
        record_pass("expiration", "expired_credential",
                    "Credential past expires_at must not authorize new actions",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("expiration", "future_timestamp",
        "A proof timestamped far in the future must be rejected",
        SEVERITY_MEDIUM)
def expiration_future_ts():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])
    ap = a.authorize(agent, cred, 'read', 'doc_1')

    if not hasattr(ap, 'timestamp'):
        record_skip("expiration", "future_timestamp",
                    "A proof timestamped far in the future must be rejected",
                    "no .timestamp attr")
        return

    ap.timestamp = int(time.time() * 1000) + 600_000  # +10 min
    r = a.verify_action(ap, cred)
    if is_valid_proof_result(r):
        record_fail("expiration", "future_timestamp",
                    "A proof timestamped far in the future must be rejected",
                    SEVERITY_MEDIUM,
                    "future-timestamped proof accepted")
    else:
        record_pass("expiration", "future_timestamp",
                    "A proof timestamped far in the future must be rejected",
                    f"rejected: {r.get('reason', 'unknown')}")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 5: BUDGET ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════

@attack("budget", "exceed_per_tx_limit",
        "A single action exceeding spend_limit_per_tx must be declined",
        SEVERITY_HIGH)
def budget_per_tx():
    a = fresh_acreo()
    bot = a.create_mandated_agent("test", budget_usd=10.0,
                                   spend_limit_per_tx=0.0001)
    try:
        bot.act('execute', 'expensive_action.py')
        record_fail("budget", "exceed_per_tx_limit",
                    "A single action exceeding spend_limit_per_tx must be declined",
                    SEVERITY_HIGH,
                    "expensive action accepted under tiny per-tx limit")
    except Exception as e:
        record_pass("budget", "exceed_per_tx_limit",
                    "A single action exceeding spend_limit_per_tx must be declined",
                    f"refused: {type(e).__name__}: {str(e)[:60]}")


@attack("budget", "exhaust_total_budget",
        "After total budget is exhausted, further actions must be declined",
        SEVERITY_HIGH)
def budget_exhaust():
    a = fresh_acreo()
    bot = a.create_mandated_agent("test", budget_usd=0.0001,
                                   spend_limit_per_tx=0.0001)
    succeeded = 0
    refused = False
    for i in range(50):
        try:
            bot.act('execute', f's_{i}')
            succeeded += 1
        except Exception:
            refused = True
            break

    if refused:
        record_pass("budget", "exhaust_total_budget",
                    "After total budget is exhausted, further actions must be declined",
                    f"refused after {succeeded} successful calls")
    elif succeeded == 50:
        record_fail("budget", "exhaust_total_budget",
                    "After total budget is exhausted, further actions must be declined",
                    SEVERITY_HIGH,
                    "50 calls completed against $0.0001 budget")
    else:
        record_pass("budget", "exhaust_total_budget",
                    "After total budget is exhausted, further actions must be declined",
                    f"loop ended at {succeeded} successful calls")


@attack("budget", "negative_amount",
        "Negative payment amounts must not credit the wallet",
        SEVERITY_HIGH)
def budget_negative():
    a = fresh_acreo()
    bot = a.create_mandated_agent("test", budget_usd=1.0)
    initial = bot.balance

    if not hasattr(bot.wallet, 'pay_for_action'):
        record_skip("budget", "negative_amount",
                    "Negative payment amounts must not credit the wallet",
                    "wallet has no pay_for_action")
        return

    try:
        receipt = bot.wallet.pay_for_action('exploit', 'wallet', amount_usd=-1000.0)
    except Exception as e:
        record_pass("budget", "negative_amount",
                    "Negative payment amounts must not credit the wallet",
                    f"raised: {type(e).__name__}")
        return

    final = bot.balance
    if final > initial:
        record_fail("budget", "negative_amount",
                    "Negative payment amounts must not credit the wallet",
                    SEVERITY_HIGH,
                    f"balance went from {initial} to {final} on negative payment")
    elif getattr(receipt, 'approved', False):
        record_fail("budget", "negative_amount",
                    "Negative payment amounts must not credit the wallet",
                    SEVERITY_MEDIUM,
                    f"negative payment approved (balance preserved but logic surprising)")
    else:
        record_pass("budget", "negative_amount",
                    "Negative payment amounts must not credit the wallet",
                    f"rejected (balance unchanged: {final})")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 6: MALFORMED INPUT
# ═══════════════════════════════════════════════════════════════════════

@attack("malformed", "verify_with_none",
        "verify_action(None) must not crash and must not return valid",
        SEVERITY_MEDIUM)
def malformed_none_proof():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])

    try:
        r = a.verify_action(None, cred)
    except Exception as e:
        record_fail("malformed", "verify_with_none",
                    "verify_action(None) must not crash and must not return valid",
                    SEVERITY_LOW,
                    f"crashed instead of clean reject: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("malformed", "verify_with_none",
                    "verify_action(None) must not crash and must not return valid",
                    SEVERITY_MEDIUM,
                    f"None proof returned valid: {r!r}")
    else:
        record_pass("malformed", "verify_with_none",
                    "verify_action(None) must not crash and must not return valid",
                    "cleanly rejected None")


@attack("malformed", "delegate_empty_perms",
        "delegate with empty permissions list must not produce a usable credential",
        SEVERITY_MEDIUM)
def malformed_empty_perms():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()

    try:
        cred = a.delegate(user, agent, [])
    except Exception as e:
        record_pass("malformed", "delegate_empty_perms",
                    "delegate with empty permissions list must not produce a usable credential",
                    f"delegate refused: {type(e).__name__}")
        return

    try:
        ap = a.authorize(agent, cred, 'read', 'doc_1')
        r = a.verify_action(ap, cred)
    except Exception as e:
        record_pass("malformed", "delegate_empty_perms",
                    "delegate with empty permissions list must not produce a usable credential",
                    f"empty-perm credential unusable: {type(e).__name__}")
        return

    if is_valid_proof_result(r):
        record_fail("malformed", "delegate_empty_perms",
                    "delegate with empty permissions list must not produce a usable credential",
                    SEVERITY_MEDIUM,
                    "empty-permission credential authorized an action")
    else:
        record_pass("malformed", "delegate_empty_perms",
                    "delegate with empty permissions list must not produce a usable credential",
                    f"rejected: {r.get('reason', 'unknown')}")


@attack("malformed", "invalid_permission_string",
        "delegate with garbage permission strings must be rejected",
        SEVERITY_LOW)
def malformed_invalid_perm():
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()

    try:
        a.delegate(user, agent, ['read', '../../etc/passwd', 'write'])
    except Exception as e:
        record_pass("malformed", "invalid_permission_string",
                    "delegate with garbage permission strings must be rejected",
                    f"refused: {type(e).__name__}: {str(e)[:50]}")
        return

    record_fail("malformed", "invalid_permission_string",
                "delegate with garbage permission strings must be rejected",
                SEVERITY_LOW,
                "invalid permission string accepted")


@attack("malformed", "act_with_none_action",
        "MandatedAgent.act(None) must not silently succeed",
        SEVERITY_LOW)
def malformed_none_action():
    a = fresh_acreo()
    bot = a.create_mandated_agent("test", budget_usd=10.0)
    try:
        result = bot.act(None, 'resource')
    except Exception as e:
        record_pass("malformed", "act_with_none_action",
                    "MandatedAgent.act(None) must not silently succeed",
                    f"raised: {type(e).__name__}")
        return

    if isinstance(result, dict) and result.get('allowed'):
        record_fail("malformed", "act_with_none_action",
                    "MandatedAgent.act(None) must not silently succeed",
                    SEVERITY_LOW,
                    f"None action allowed: {result}")
    else:
        record_pass("malformed", "act_with_none_action",
                    "MandatedAgent.act(None) must not silently succeed",
                    f"None action gated: allowed={result.get('allowed') if isinstance(result, dict) else result}")


# ═══════════════════════════════════════════════════════════════════════
# FAMILY 7: CONCURRENCY
# ═══════════════════════════════════════════════════════════════════════

@attack("concurrency", "parallel_replay_race",
        "Concurrent replays of one proof must result in at most one acceptance",
        SEVERITY_HIGH)
def concurrency_replay():
    """Many threads simultaneously submit the same proof. Only one should
    win. If two or more win, there's a race in the nonce check."""
    a = fresh_acreo()
    user = a.create_user(); agent = a.create_agent()
    cred = a.delegate(user, agent, ['read'])
    ap = a.authorize(agent, cred, 'read', 'doc_1')

    accept_count = [0]
    lock = threading.Lock()

    def worker():
        r = a.verify_action(ap, cred)
        if is_valid_proof_result(r):
            with lock:
                accept_count[0] += 1

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()

    n = accept_count[0]
    if n > 1:
        record_fail("concurrency", "parallel_replay_race",
                    "Concurrent replays of one proof must result in at most one acceptance",
                    SEVERITY_HIGH,
                    f"{n}/20 concurrent replays accepted (nonce race condition)")
    elif n == 1:
        record_pass("concurrency", "parallel_replay_race",
                    "Concurrent replays of one proof must result in at most one acceptance",
                    "exactly 1/20 accepted as expected")
    else:
        record_pass("concurrency", "parallel_replay_race",
                    "Concurrent replays of one proof must result in at most one acceptance",
                    "0/20 accepted (no race exposed in this run)")


@attack("concurrency", "parallel_overspend",
        "Concurrent expensive actions must not exceed total budget",
        SEVERITY_HIGH)
def concurrency_overspend():
    """Many threads execute small actions concurrently. Total spend should
    not exceed initial budget."""
    a = fresh_acreo()
    bot = a.create_mandated_agent("test", budget_usd=0.001)
    initial = bot.balance
    success = [0]
    lock = threading.Lock()

    def worker(i):
        try:
            bot.act('execute', f's_{i}')
            with lock:
                success[0] += 1
        except Exception:
            pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    for t in threads: t.start()
    for t in threads: t.join()

    final = bot.balance
    spent = initial - final
    if final < -0.0000001:
        record_fail("concurrency", "parallel_overspend",
                    "Concurrent expensive actions must not exceed total budget",
                    SEVERITY_HIGH,
                    f"balance went negative: {final}")
    elif spent > initial + 0.0000001:
        record_fail("concurrency", "parallel_overspend",
                    "Concurrent expensive actions must not exceed total budget",
                    SEVERITY_MEDIUM,
                    f"spent {spent} > initial {initial}")
    else:
        record_pass("concurrency", "parallel_overspend",
                    "Concurrent expensive actions must not exceed total budget",
                    f"{success[0]}/40 ok, spent {spent:.6f}/{initial}, final {final:.6f}")


# ═══════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════

def run_attacks(family_filter: Optional[str] = None) -> list[AttackResult]:
    _results.clear()
    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    families_seen = set()
    for fn in _attacks:
        if family_filter and fn._family != family_filter:
            continue
        if fn._family not in families_seen:
            families_seen.add(fn._family)
            print(f"\n[{fn._family.upper()}]")

        t0 = time.perf_counter()
        try:
            fn()
            if _results and _results[-1].name == fn._name:
                _results[-1].elapsed_ms = (time.perf_counter() - t0) * 1000
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            tb = traceback.format_exc(limit=3)
            _results.append(AttackResult(
                family=fn._family, name=fn._name, claim=fn._claim,
                outcome="ERROR", severity=SEVERITY_INFO,
                detail=f"infra error: {type(e).__name__}: {e}\n{tb}",
                elapsed_ms=elapsed,
            ))

        last = _results[-1]
        sev_tag = f" [{last.severity}]" if last.outcome == "FAIL" else ""
        detail = (last.detail or "").replace("\n", " ")[:80]
        print(f"  {icons[last.outcome]} {last.outcome}{sev_tag} "
              f"{last.name} — {detail}")

    return list(_results)


def print_summary(results: list[AttackResult]):
    by_family: dict[str, list[AttackResult]] = {}
    for r in results:
        by_family.setdefault(r.family, []).append(r)

    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
    for r in results:
        counts[r.outcome] += 1

    print("\n" + "═" * 72)
    print("  SUMMARY")
    print("═" * 72)
    print(f"  Total: {len(results)}  PASS={counts['PASS']}  "
          f"FAIL={counts['FAIL']}  SKIP={counts['SKIP']}  "
          f"ERROR={counts['ERROR']}")

    print(f"\n  By family:")
    for family, rs in sorted(by_family.items()):
        c = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
        for r in rs:
            c[r.outcome] += 1
        print(f"    {family:<14} {c['PASS']:>2}P {c['FAIL']:>2}F "
              f"{c['SKIP']:>2}S {c['ERROR']:>2}E")

    fails = [r for r in results if r.outcome == "FAIL"]
    if fails:
        print(f"\n  Findings (sorted by severity):")
        fails.sort(key=lambda r: -SEVERITY_ORDER[r.severity])
        for r in fails:
            print(f"    [{r.severity:<8}] {r.family}/{r.name}")
            print(f"        claim:  {r.claim}")
            print(f"        detail: {r.detail}")

    errors = [r for r in results if r.outcome == "ERROR"]
    if errors:
        print(f"\n  Test infrastructure ERRORS (not Acreo issues):")
        for r in errors:
            print(f"    {r.family}/{r.name}: {r.detail.splitlines()[0]}")

    skips = [r for r in results if r.outcome == "SKIP"]
    if skips:
        print(f"\n  SKIPPED (test couldn't run as written):")
        for r in skips:
            print(f"    {r.family}/{r.name}: {r.detail}")

    print("═" * 72)


def write_json(results: list[AttackResult], path: str = "chaos_results.json"):
    payload = {
        "version": "1.0",
        "seed": RANDOM_SEED,
        "timestamp": int(time.time()),
        "total": len(results),
        "summary": {
            "pass": sum(1 for r in results if r.outcome == "PASS"),
            "fail": sum(1 for r in results if r.outcome == "FAIL"),
            "skip": sum(1 for r in results if r.outcome == "SKIP"),
            "error": sum(1 for r in results if r.outcome == "ERROR"),
        },
        "results": [asdict(r) for r in results],
    }
    with open(path, "w") as fp:
        json.dump(payload, fp, indent=2)
    return path


def main():
    parser = argparse.ArgumentParser(
        description="Acreo adversarial test suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for threat model and scope.",
    )
    parser.add_argument("--family", help="run only one family (e.g. replay)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output only")
    parser.add_argument("--output", default="chaos_results.json",
                        help="JSON results path")
    parser.add_argument("--strict", action="store_true",
                        help="exit nonzero on any non-PASS")
    args = parser.parse_args()

    if not args.json:
        print(f"Acreo chaos test suite — {len(_attacks)} attacks across "
              f"{len(set(fn._family for fn in _attacks))} families")
        if args.family:
            print(f"  Filter: family={args.family}")
        print(f"  Seed: 0x{RANDOM_SEED:X}")

    results = run_attacks(family_filter=args.family)

    if not args.json:
        print_summary(results)

    json_path = write_json(results, args.output)
    if not args.json:
        print(f"\n  Full results: {json_path}")

    fails = [r for r in results if r.outcome == "FAIL"]
    errors = [r for r in results if r.outcome == "ERROR"]
    if errors:
        return 2
    if args.strict and (fails or any(r.outcome == "SKIP" for r in results)):
        return 1
    if any(SEVERITY_ORDER[r.severity] >= SEVERITY_ORDER[SEVERITY_MEDIUM] for r in fails):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
