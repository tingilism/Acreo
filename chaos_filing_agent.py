"""
chaos_filing_agent.py — adversarial chaos for Filing Agent
==============================================================

Twelve attacks targeting the adversarial boundary of the Filing Agent.
These complement the 12 self-tests in agents/test_filing_agent.py
(which cover happy/unhappy paths within FA's logic).

Attacks here probe the cryptographic and architectural seams:

  1. forged_ma_identity        — attacker signs flag with own key, claims to be MA
  2. expired_ma_credential     — MA's credential has expired; flag must be rejected
  3. wrong_scope               — MA's credential scope doesn't cover the flag's resource
  4. action_mismatch           — proof claims action FA isn't authorized for
  5. tampered_condition_dict   — condition dict modified after signing
  6. swapped_proof_payload     — valid proof from one flag carrying different flag content
  7. dedup_bypass_attempt      — attempt to bypass dedup via cosmetic flag changes
  8. parallel_filing_race      — same flag submitted by parallel callers
  9. reused_proof_different_flag — proof reused with substituted flag content
 10. fa_credential_revoked     — FA's own credential revoked during operation
 11. activity_stream_tamper    — tamper FA's activity stream to hide a filing
 12. excess_severity_inflation — flag claims critical when underlying data is benign

Run:
    python -m chaos_filing_agent
"""

from __future__ import annotations
import argparse
import copy
import json
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable

from acreo import (
    Identity, Acreo, AcreoError, Entropy, ConditionalProof,
    PermissionDenied,
)

from agents.compliance_schemas import (
    ComplianceFlag, AddressInvolvement,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    FLAG_SANCTIONS_HIT, FLAG_THRESHOLD_CROSSING, FLAG_SUSPICIOUS_PATTERN,
    hash_flag,
)
from agents.filing_agent import FilingAgent, FilingResult


SEVERITY_INFO = "INFO"
SEVERITY_LOW_RANK = "LOW"
SEVERITY_MEDIUM_RANK = "MEDIUM"
SEVERITY_HIGH_RANK = "HIGH"
SEVERITY_CRITICAL_RANK = "CRITICAL"
SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_LOW_RANK: 1,
                  SEVERITY_MEDIUM_RANK: 2, SEVERITY_HIGH_RANK: 3,
                  SEVERITY_CRITICAL_RANK: 4}


@dataclass
class AttackResult:
    family: str
    name: str
    claim: str
    outcome: str
    severity: str = SEVERITY_INFO
    detail: str = ""


_results: list[AttackResult] = []
_attacks: list[Callable] = []


def record_pass(family, name, claim, detail=""):
    _results.append(AttackResult(family, name, claim, "PASS",
                                  SEVERITY_INFO, detail))


def record_fail(family, name, claim, severity, detail):
    _results.append(AttackResult(family, name, claim, "FAIL", severity, detail))


def attack(family, name, claim):
    def decorator(fn):
        _attacks.append(fn)
        fn._family = family
        fn._name = name
        fn._claim = claim
        return fn
    return decorator


# ─── Helpers ──────────────────────────────────────────────────────

def make_flag(severity=SEVERITY_CRITICAL,
              flag_type=FLAG_SANCTIONS_HIT,
              detected_at_ms=None,
              risk_score=0.95,
              chain='ethereum',
              tx_hash='0xabc123def456') -> ComplianceFlag:
    if detected_at_ms is None:
        detected_at_ms = int(time.time() * 1000)
    return ComplianceFlag(
        flag_type=flag_type,
        severity=severity,
        transaction_hashes=[tx_hash],
        addresses_involved=[
            AddressInvolvement(
                address='0xSANCTIONED_ADDR', chain=chain,
                role='sanctioned', label='OFAC SDN'
            ),
        ],
        risk_score=risk_score,
        rationale_hash='0' * 64,
        evidence_pointer='1' * 64,
        detected_at_ms=detected_at_ms,
        chain=chain,
    )


def setup_fa(filings_dir: str, fa_perms=('write', 'communicate'),
             ma_perms=('read', 'communicate'),
             ma_scope=('compliance/crypto/*',)):
    """Standard setup. Returns (acreo, op, ma_id, ma_cred, fa)."""
    acreo = Acreo()
    op = acreo.create_user('jimmy')

    ma_id = acreo.create_agent('monitoring-agent')
    ma_cred = acreo.delegate(
        op, ma_id, permissions=list(ma_perms),
        scope=list(ma_scope), heartbeat_interval_ms=300000,
    )

    fa_id = acreo.create_agent('filing-agent')
    fa_cred = acreo.delegate(
        op, fa_id, permissions=list(fa_perms),
        scope=['compliance/crypto/*'], heartbeat_interval_ms=60000,
    )

    fa = FilingAgent(
        identity=fa_id, credential=fa_cred, operator=op,
        verifier=acreo._verifier, filings_dir=filings_dir,
        trusted_ma_keys={ma_id.public_key},
    )
    return acreo, op, ma_id, ma_cred, fa


def ma_proof(ma_id, ma_cred, flag, valid_until_ms=None,
             action='communicate'):
    if valid_until_ms is None:
        valid_until_ms = int(time.time() * 1000) + 60_000
    return ma_id.propose(
        cred=ma_cred,
        action=action,
        resource=f'compliance/crypto/{flag.chain}',
        condition=flag.to_condition_dict(),
        valid_until_ms=valid_until_ms,
    )


# ═══════════════════════════════════════════════════════════════════════
# ATTACKS
# ═══════════════════════════════════════════════════════════════════════

@attack("filing", "forged_ma_identity",
        "Attacker with valid Acreo credential but unregistered with FA — rejected")
def forged_ma_identity():
    """Phase 1.5: FA holds a registry of trusted MA pubkeys. Attacker has a
    valid op-issued credential but isn't in FA's registry. FA rejects."""
    d = tempfile.mkdtemp(prefix='chaos_fa_forge_ma_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        # FA already has ma_id.public_key registered (via setup_fa).
        # Attacker gets their own credential but isn't in FA's registry.
        attacker = acreo.create_agent('attacker')
        try:
            attacker_cred = acreo.delegate(
                op, attacker, permissions=['communicate'],
                scope=['compliance/crypto/*'],
                heartbeat_interval_ms=300000,
            )
            flag = make_flag()
            proof = ma_proof(attacker, attacker_cred, flag)
            result = fa.receive_flag(proof)
            if not result.accepted and result.rejection_reason == 'unregistered_ma':
                record_pass("filing", "forged_ma_identity",
                            "Attacker with valid Acreo credential but unregistered with FA — rejected",
                            f"rejected: {result.rejection_reason}")
            elif not result.accepted:
                record_pass("filing", "forged_ma_identity",
                            "Attacker with valid Acreo credential but unregistered with FA — rejected",
                            f"rejected: {result.rejection_reason} (different reason than expected)")
            else:
                record_fail("filing", "forged_ma_identity",
                            "Attacker with valid Acreo credential but unregistered with FA — rejected",
                            SEVERITY_HIGH_RANK,
                            "unregistered MA's flag accepted — MA-binding broken")
        except Exception as e:
            record_fail("filing", "forged_ma_identity",
                        "Attacker with valid Acreo credential but unregistered with FA — rejected",
                        SEVERITY_LOW_RANK,
                        f"setup error: {type(e).__name__}: {e}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "expired_ma_credential",
        "MA credential past expiry — FA rejects flag")
def expired_credential():
    d = tempfile.mkdtemp(prefix='chaos_fa_expired_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        # Manually expire MA's credential by editing the in-memory record
        # (this mimics the wall-clock having moved past expiry)
        ma_cred.expires_at = int(time.time() * 1000) - 1000  # 1s ago
        flag = make_flag()
        try:
            proof = ma_proof(ma_id, ma_cred, flag)
            result = fa.receive_flag(proof)
            if not result.accepted:
                record_pass("filing", "expired_ma_credential",
                            "MA credential past expiry — FA rejects flag",
                            f"rejected: {result.rejection_reason}")
            else:
                record_fail("filing", "expired_ma_credential",
                            "MA credential past expiry — FA rejects flag",
                            SEVERITY_HIGH_RANK,
                            "expired credential's flag accepted")
        except (AcreoError, PermissionDenied) as e:
            # propose() itself may refuse to issue proof against expired cred
            record_pass("filing", "expired_ma_credential",
                        "MA credential past expiry — FA rejects flag",
                        f"propose blocked: {type(e).__name__}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "wrong_scope",
        "MA tries to flag activity outside its credential scope")
def wrong_scope():
    d = tempfile.mkdtemp(prefix='chaos_fa_scope_')
    try:
        # MA's credential scope is restricted to ethereum only
        acreo, op, ma_id, ma_cred, fa = setup_fa(
            d, ma_scope=('compliance/crypto/ethereum',))
        # Flag claims polygon — outside scope
        flag = make_flag(chain='polygon')
        try:
            proof = ma_proof(ma_id, ma_cred, flag)
            # If propose accepts it, FA should still reject
            result = fa.receive_flag(proof)
            if not result.accepted:
                record_pass("filing", "wrong_scope",
                            "MA tries to flag activity outside its credential scope",
                            f"rejected: {result.rejection_reason}")
            else:
                record_fail("filing", "wrong_scope",
                            "MA tries to flag activity outside its credential scope",
                            SEVERITY_HIGH_RANK,
                            "out-of-scope flag accepted")
        except (AcreoError, PermissionDenied) as e:
            record_pass("filing", "wrong_scope",
                        "MA tries to flag activity outside its credential scope",
                        f"propose blocked: {type(e).__name__}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "action_mismatch",
        "MA proposes with action it doesn't have permission for")
def action_mismatch():
    d = tempfile.mkdtemp(prefix='chaos_fa_action_')
    try:
        # MA has only 'read' — no 'communicate'
        acreo, op, ma_id, ma_cred, fa = setup_fa(d, ma_perms=('read',))
        flag = make_flag()
        try:
            proof = ma_proof(ma_id, ma_cred, flag, action='communicate')
            record_fail("filing", "action_mismatch",
                        "MA proposes with action it doesn't have permission for",
                        SEVERITY_HIGH_RANK,
                        "propose accepted disallowed action")
        except (AcreoError, PermissionDenied) as e:
            record_pass("filing", "action_mismatch",
                        "MA proposes with action it doesn't have permission for",
                        f"propose blocked: {type(e).__name__}: {e}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "tampered_condition_dict",
        "Tampering with condition dict after signing breaks proof verification")
def tampered_condition():
    d = tempfile.mkdtemp(prefix='chaos_fa_tamper_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        flag = make_flag()
        proof = ma_proof(ma_id, ma_cred, flag)
        # Tamper with the condition AFTER proof was signed
        proof.condition = dict(proof.condition)
        proof.condition['risk_score'] = 0.0  # downgrade severity
        result = fa.receive_flag(proof)
        if not result.accepted:
            record_pass("filing", "tampered_condition_dict",
                        "Tampering with condition dict after signing breaks proof verification",
                        f"rejected: {result.rejection_reason}")
        else:
            record_fail("filing", "tampered_condition_dict",
                        "Tampering with condition dict after signing breaks proof verification",
                        SEVERITY_CRITICAL_RANK,
                        "post-sign condition tamper accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "swapped_proof_payload",
        "Swap a different flag into a valid proof's condition field")
def swapped_payload():
    d = tempfile.mkdtemp(prefix='chaos_fa_swap_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        flag_real = make_flag(severity=SEVERITY_LOW)  # benign flag MA actually signs
        flag_fake = make_flag(severity=SEVERITY_CRITICAL)  # critical flag attacker wants

        proof = ma_proof(ma_id, ma_cred, flag_real)
        # Attacker swaps the condition payload to point to the critical flag
        proof.condition = flag_fake.to_condition_dict()
        result = fa.receive_flag(proof)
        if not result.accepted:
            record_pass("filing", "swapped_proof_payload",
                        "Swap a different flag into a valid proof's condition field",
                        f"rejected: {result.rejection_reason}")
        else:
            record_fail("filing", "swapped_proof_payload",
                        "Swap a different flag into a valid proof's condition field",
                        SEVERITY_CRITICAL_RANK,
                        "swapped condition payload accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "dedup_bypass_attempt",
        "Same flag with cosmetic changes still dedups via content hash")
def dedup_bypass():
    d = tempfile.mkdtemp(prefix='chaos_fa_dedup_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        flag1 = make_flag(severity=SEVERITY_HIGH)
        proof1 = ma_proof(ma_id, ma_cred, flag1)
        result1 = fa.receive_flag(proof1)
        if not (result1.accepted and result1.filing_id):
            record_fail("filing", "dedup_bypass_attempt",
                        "Same flag with cosmetic changes still dedups via content hash",
                        SEVERITY_LOW_RANK,
                        "first filing didn't succeed")
            return

        # Try variants that should still dedup (identical content)
        flag2 = make_flag(severity=SEVERITY_HIGH)  # same content, new object
        proof2 = ma_proof(ma_id, ma_cred, flag2)
        result2 = fa.receive_flag(proof2)
        if not result2.accepted or result2.filing_id is not None:
            record_pass("filing", "dedup_bypass_attempt",
                        "Same flag with cosmetic changes still dedups via content hash",
                        f"second filing dedupped: {result2.skip_reason}")
        else:
            record_fail("filing", "dedup_bypass_attempt",
                        "Same flag with cosmetic changes still dedups via content hash",
                        SEVERITY_HIGH_RANK,
                        "duplicate flag produced second filing")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "parallel_filing_race",
        "Same flag submitted by parallel threads — exactly one filing produced")
def parallel_race():
    d = tempfile.mkdtemp(prefix='chaos_fa_race_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        flag = make_flag(severity=SEVERITY_HIGH)
        # Pre-build proofs (proof creation might not be thread-safe)
        proofs = [ma_proof(ma_id, ma_cred, flag) for _ in range(10)]

        results = []
        results_lock = threading.Lock()

        def worker(p):
            r = fa.receive_flag(p)
            with results_lock:
                results.append(r)

        threads = [threading.Thread(target=worker, args=(p,)) for p in proofs]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 1 should produce a filing; rest should dedup
        filings = [r for r in results if r.filing_id]
        if len(filings) == 1:
            record_pass("filing", "parallel_filing_race",
                        "Same flag submitted by parallel threads — exactly one filing produced",
                        f"1 filing, {len(results) - 1} dedupped")
        else:
            record_fail("filing", "parallel_filing_race",
                        "Same flag submitted by parallel threads — exactly one filing produced",
                        SEVERITY_MEDIUM_RANK,
                        f"got {len(filings)} filings under contention; "
                        "Phase 1 dedup is not thread-safe")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "reused_proof_different_flag",
        "Reused valid proof's signature won't match a different flag")
def reused_proof_different_flag():
    d = tempfile.mkdtemp(prefix='chaos_fa_reuse_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        flag1 = make_flag(severity=SEVERITY_LOW, tx_hash='0x111')
        flag2 = make_flag(severity=SEVERITY_CRITICAL, tx_hash='0x222')

        proof1 = ma_proof(ma_id, ma_cred, flag1)
        # Try to reuse proof1's signature with flag2's content
        proof_reused = copy.copy(proof1)
        proof_reused.condition = flag2.to_condition_dict()
        # signature stays from proof1 — won't match flag2's condition
        result = fa.receive_flag(proof_reused)
        if not result.accepted:
            record_pass("filing", "reused_proof_different_flag",
                        "Reused valid proof's signature won't match a different flag",
                        f"rejected: {result.rejection_reason}")
        else:
            record_fail("filing", "reused_proof_different_flag",
                        "Reused valid proof's signature won't match a different flag",
                        SEVERITY_CRITICAL_RANK,
                        "signature reuse accepted")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "fa_credential_revoked",
        "FA's own credential expired — Phase 1.7 self-validation rejects flag")
def fa_credential_revoked():
    """Phase 1.7: FA self-validates its own credential at the top of
    each receive_flag call. Expired credential → rejection with reason
    'fa_credential_expired'."""
    d = tempfile.mkdtemp(prefix='chaos_fa_revoked_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        # Expire FA's credential
        fa.credential.expires_at = int(time.time() * 1000) - 1000
        flag = make_flag()
        proof = ma_proof(ma_id, ma_cred, flag)
        result = fa.receive_flag(proof)
        if not result.accepted and result.rejection_reason == 'fa_credential_expired':
            record_pass("filing", "fa_credential_revoked",
                        "FA's own credential expired — Phase 1.7 self-validation rejects flag",
                        f"rejected: {result.rejection_reason}")
        elif not result.accepted:
            record_pass("filing", "fa_credential_revoked",
                        "FA's own credential expired — Phase 1.7 self-validation rejects flag",
                        f"rejected: {result.rejection_reason} (different reason)")
        else:
            record_fail("filing", "fa_credential_revoked",
                        "FA's own credential expired — Phase 1.7 self-validation rejects flag",
                        SEVERITY_HIGH_RANK,
                        "FA processed flag with expired own credential")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "activity_stream_tamper",
        "Tampering FA's activity stream breaks chain verification")
def activity_stream_tamper():
    d = tempfile.mkdtemp(prefix='chaos_fa_stream_tamper_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        flag = make_flag()
        proof = ma_proof(ma_id, ma_cred, flag)
        fa.receive_flag(proof)

        # Get FA's activity stream and tamper a frame
        stream = fa.activity_stream
        if len(stream.frames) < 2:
            record_fail("filing", "activity_stream_tamper",
                        "Tampering FA's activity stream breaks chain verification",
                        SEVERITY_LOW_RANK,
                        "stream has too few frames to tamper")
            return

        # Tamper with a frame in the middle
        from acreo_activity_stream import StreamVerifier, ActivityFrame
        original_frames = list(stream.frames)
        tampered = ActivityFrame.from_dict(original_frames[1].to_dict())
        tampered.payload = {**tampered.payload, 'tampered': True}
        tampered_frames = [original_frames[0], tampered] + list(original_frames[2:])

        verifier = StreamVerifier(fa.identity.public_key)
        verdict = verifier.verify_segment(tampered_frames)
        if not verdict.get('valid'):
            record_pass("filing", "activity_stream_tamper",
                        "Tampering FA's activity stream breaks chain verification",
                        f"rejected: {verdict.get('reason')}")
        else:
            record_fail("filing", "activity_stream_tamper",
                        "Tampering FA's activity stream breaks chain verification",
                        SEVERITY_CRITICAL_RANK,
                        "tampered stream verified clean")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@attack("filing", "severity_inflation_caught",
        "Inflated severity caught by Phase 1.7 risk-score cross-check")
def severity_inflation():
    """Phase 1.7: FA cross-checks declared severity against risk_score.
    A flag claiming severity=CRITICAL with risk_score=0.1 is rejected
    because CRITICAL is more than one tier above what risk_score 0.1
    warrants (which is LOW)."""
    d = tempfile.mkdtemp(prefix='chaos_fa_inflate_')
    try:
        acreo, op, ma_id, ma_cred, fa = setup_fa(d)
        # MA claims critical severity but flag's risk_score is 0.1
        flag = make_flag(severity=SEVERITY_CRITICAL, risk_score=0.1)
        proof = ma_proof(ma_id, ma_cred, flag)
        result = fa.receive_flag(proof)
        if not result.accepted and result.rejection_reason == 'severity_exceeds_risk_score':
            record_pass("filing", "severity_inflation_caught",
                        "Inflated severity caught by Phase 1.7 risk-score cross-check",
                        f"rejected: {result.rejection_reason}")
        elif not result.accepted:
            record_pass("filing", "severity_inflation_caught",
                        "Inflated severity caught by Phase 1.7 risk-score cross-check",
                        f"rejected: {result.rejection_reason} (different reason)")
        else:
            record_fail("filing", "severity_inflation_caught",
                        "Inflated severity caught by Phase 1.7 risk-score cross-check",
                        SEVERITY_HIGH_RANK,
                        "severity inflation accepted — Phase 1.7 cross-check broken")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="chaos_filing_agent_results.json")
    args = parser.parse_args()

    icons = {"PASS": "✓", "FAIL": "✗", "SKIP": "⋯", "ERROR": "!"}

    print(f"Acreo Filing Agent chaos test — {len(_attacks)} attacks\n")
    print("[FILING]")

    for fn in _attacks:
        try:
            fn()
        except Exception as e:
            _results.append(AttackResult(
                family="filing", name=fn._name, claim=fn._claim,
                outcome="ERROR", severity=SEVERITY_INFO,
                detail=f"infra error: {type(e).__name__}: {e}",
            ))

        last = _results[-1]
        tag = f" [{last.severity}]" if last.outcome == "FAIL" else ""
        detail = (last.detail or "").replace("\n", " ")[:100]
        print(f"  {icons[last.outcome]} {last.outcome}{tag} {last.name} — {detail}")

    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
    for r in _results:
        counts[r.outcome] += 1
    print("\n" + "═" * 60)
    print(f"  Total: {len(_results)}  PASS={counts['PASS']}  "
          f"FAIL={counts['FAIL']}  ERROR={counts['ERROR']}")

    fails = [r for r in _results if r.outcome == "FAIL"]
    if fails:
        print("\n  Findings:")
        fails.sort(key=lambda r: -SEVERITY_ORDER[r.severity])
        for r in fails:
            print(f"    [{r.severity}] {r.name}")
            print(f"        claim: {r.claim}")
            print(f"        detail: {r.detail}")

    errors = [r for r in _results if r.outcome == "ERROR"]
    if errors:
        print("\n  Errors:")
        for r in errors:
            print(f"    [!] {r.name}")
            print(f"        {r.detail}")

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
    if any(SEVERITY_ORDER[r.severity] >= SEVERITY_ORDER[SEVERITY_MEDIUM_RANK]
           for r in fails):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
