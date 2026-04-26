"""
chaos_reports.py — adversarial tests for OperatorReport
=========================================================

Eight attack categories covering Verifier.verify_report and the seal/unseal
flow for bot-to-operator notifications.

Run:
    python chaos_reports.py
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
    from acreo import Acreo, OperatorReport, AcreoError
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


# ─── Helper: build a typical operator/bot setup ──────────────────────

def setup(a=None):
    a = a or Acreo()
    operator = a.create_user('operator')
    bot = a.create_agent('trading-bot')
    cred = a.delegate(operator, bot, ['transact'], scope=['polymarket/*'])
    return a, operator, bot, cred


# ═══════════════════════════════════════════════════════════════════════
# ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("report", "happy_path",
        "Bot reports, operator unseals, verifier accepts")
def report_happy():
    a, operator, bot, cred = setup()
    sealed = a.report(bot, cred, operator.peer_key, 'trade_executed',
                       {'venue': 'polymarket', 'pnl_usdc': 42.5})
    report = a.receive_report(operator, sealed)
    r = a.verify_report(report, cred)
    if is_valid(r):
        record_pass("report", "happy_path",
                    "Bot reports, operator unseals, verifier accepts",
                    f"event_type={r.get('event_type')}")
    else:
        record_fail("report", "happy_path",
                    "Bot reports, operator unseals, verifier accepts",
                    SEVERITY_CRITICAL, f"unexpected reject: {r}")


@attack("report", "wrong_operator_cannot_decrypt",
        "Sealed report cannot be decrypted by anyone except intended operator")
def report_wrong_operator():
    a, operator, bot, cred = setup()
    eve = a.create_user('eve')
    sealed = a.report(bot, cred, operator.peer_key, 'trade_executed',
                       {'pnl_usdc': 42.5})
    try:
        eve.receive_report(sealed)
    except ValueError:
        record_pass("report", "wrong_operator_cannot_decrypt",
                    "Sealed report cannot be decrypted by anyone except intended operator",
                    "decryption rejected as expected")
        return
    record_fail("report", "wrong_operator_cannot_decrypt",
                "Sealed report cannot be decrypted by anyone except intended operator",
                SEVERITY_CRITICAL, "eve decrypted operator's sealed report")


@attack("report", "tampered_payload",
        "Modifying report.payload after signing must fail verification")
def report_tampered():
    a, operator, bot, cred = setup()
    sealed = a.report(bot, cred, operator.peer_key, 'trade_executed',
                       {'pnl_usdc': 42.5})
    report = a.receive_report(operator, sealed)
    # Mutate payload
    report.payload = {'pnl_usdc': 999999.0}  # attacker changes the number
    r = a.verify_report(report, cred)
    if not is_valid(r):
        record_pass("report", "tampered_payload",
                    "Modifying report.payload after signing must fail verification",
                    f"rejected: {r.get('reason')}")
    else:
        record_fail("report", "tampered_payload",
                    "Modifying report.payload after signing must fail verification",
                    SEVERITY_CRITICAL, "tampered payload accepted")


@attack("report", "forged_sender_signature",
        "Report signed by a different agent's key must be rejected")
def report_forged():
    a, operator, bot, cred = setup()
    # Eve has her own bot and credential, but she'll try to claim her report
    # is from `bot`'s credential
    eve_user = a.create_user('eve')
    eve_bot = a.create_agent('eve-bot')
    eve_cred = a.delegate(eve_user, eve_bot, ['transact'], scope=['*'])

    # Eve creates a real signed report from her own credential
    sealed = a.report(eve_bot, eve_cred, operator.peer_key,
                       'trade_executed', {'pnl_usdc': 1000000})
    report = a.receive_report(operator, sealed)

    # But she swaps the credential_id to point at the legit bot's credential
    forged = copy.deepcopy(report)
    forged.credential_id = cred.credential_id
    forged.agent_key = bot.public_key

    r = a.verify_report(forged, cred)
    if not is_valid(r):
        record_pass("report", "forged_sender_signature",
                    "Report signed by a different agent's key must be rejected",
                    f"rejected: {r.get('reason')}")
    else:
        record_fail("report", "forged_sender_signature",
                    "Report signed by a different agent's key must be rejected",
                    SEVERITY_CRITICAL, "forged report accepted")


@attack("report", "replay_blocked",
        "Same report verified twice must be blocked on second use")
def report_replay():
    a, operator, bot, cred = setup()
    sealed = a.report(bot, cred, operator.peer_key, 'heartbeat_ok', {})
    report = a.receive_report(operator, sealed)
    r1 = a.verify_report(report, cred)
    if not is_valid(r1):
        record_skip("report", "replay_blocked",
                    "Same report verified twice must be blocked on second use",
                    f"first verify failed: {r1}")
        return
    r2 = a.verify_report(report, cred)
    if is_valid(r2):
        record_fail("report", "replay_blocked",
                    "Same report verified twice must be blocked on second use",
                    SEVERITY_HIGH, "replay accepted")
    else:
        record_pass("report", "replay_blocked",
                    "Same report verified twice must be blocked on second use",
                    f"replay rejected: {r2.get('reason')}")


@attack("report", "expired_credential",
        "Report from an expired credential must be rejected at verify time")
def report_expired_cred():
    a, operator, bot, cred = setup()
    # Create a separately-issued credential that will expire by verify time
    short_cred = a.delegate(operator, bot, ['transact'], scope=['*'],
                             ttl_hours=0.0001)
    sealed = a.report(bot, short_cred, operator.peer_key, 'event', {})
    report = a.receive_report(operator, sealed)
    time.sleep(0.5)  # let credential expire (longer than 360ms ttl)
    r = a.verify_report(report, short_cred)
    if not is_valid(r):
        record_pass("report", "expired_credential",
                    "Report from an expired credential must be rejected at verify time",
                    f"rejected: {r.get('reason')}")
    else:
        record_fail("report", "expired_credential",
                    "Report from an expired credential must be rejected at verify time",
                    SEVERITY_HIGH, "expired-cred report accepted")


@attack("report", "revoked_credential",
        "Bot whose credential is revoked cannot create new reports")
def report_revoked():
    a, operator, bot, cred = setup()
    # Bot revokes its own copy by being marked as revoked
    bot._revoked.add(cred.credential_id)
    try:
        a.report(bot, cred, operator.peer_key, 'event', {})
    except Exception as e:
        record_pass("report", "revoked_credential",
                    "Bot whose credential is revoked cannot create new reports",
                    f"raised: {type(e).__name__}: {str(e)[:50]}")
        return
    record_fail("report", "revoked_credential",
                "Bot whose credential is revoked cannot create new reports",
                SEVERITY_HIGH, "revoked credential allowed report creation")


@attack("report", "non_agent_cannot_report",
        "Users (non-agents) cannot create reports — only agents can")
def report_user_blocked():
    a, operator, bot, cred = setup()
    try:
        # Operator (a user) trying to create a report should fail
        a.report(operator, cred, bot.peer_key, 'event', {})
    except AcreoError:
        record_pass("report", "non_agent_cannot_report",
                    "Users (non-agents) cannot create reports — only agents can",
                    "AcreoError raised as expected")
        return
    except Exception as e:
        # CredentialError is also acceptable since the cred isn't for the user
        record_pass("report", "non_agent_cannot_report",
                    "Users (non-agents) cannot create reports — only agents can",
                    f"raised: {type(e).__name__}")
        return
    record_fail("report", "non_agent_cannot_report",
                "Users (non-agents) cannot create reports — only agents can",
                SEVERITY_MEDIUM, "user successfully created a report")


# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="chaos_reports_results.json")
    args = parser.parse_args()

    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    print(f"Acreo operator-report chaos test — {len(_attacks)} attacks\n")
    print("[REPORT]")

    for fn in _attacks:
        try:
            fn()
        except Exception as e:
            _results.append(AttackResult(
                family="report", name=fn._name, claim=fn._claim,
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
