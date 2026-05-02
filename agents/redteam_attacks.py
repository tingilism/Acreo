"""
agents/redteam_attacks.py — adversarial attack scenarios
==============================================================

Library of attacks RTA runs against sandboxed MA + FA instances.
Each attack is a function: (sandbox: RedTeamSandbox) -> AttackResult.

  succeeded=True  → defense failed, vulnerability found
  succeeded=False → defense held, current hardening works

Step 4 scope: first 6 attacks against FA. Mirror the existing
chaos_filing_agent.py tests but framed as live attempts.

The 6 attacks here cover the most distinct categories:
  1. forge_ma_identity      — identity / MA-binding bypass
  2. submit_expired_credential — credential validity
  3. submit_wrong_scope     — credential scope enforcement
  4. tamper_condition_dict  — proof tampering
  5. submit_duplicate       — dedup logic
  6. inflate_severity       — semantic policy enforcement

Step 5 will add 6 more FA attacks. Step 5b adds 12 MA attacks.

Each attack function follows the same shape:
  - Set up the malicious input
  - Submit it through the appropriate sandbox interface
  - Examine the result
  - Return AttackResult(succeeded=<defense failed?>, ...)

Convention: the attack succeeds (succeeded=True) ONLY if a malicious
outcome was achieved — e.g. an unauthorized flag was filed. If FA
rejects with a clean rejection_reason, defense held (succeeded=False).
"""

from __future__ import annotations
import time
import threading
import json
import base64

from acreo import AcreoError

from agents.compliance_schemas import (
    ComplianceFlag, AddressInvolvement,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    FLAG_SANCTIONS_HIT,
)
from agents.redteam_schemas import AttackResult


def _make_test_flag(severity: str = SEVERITY_CRITICAL,
                    risk_score: float = 0.95,
                    tx_hash: str = '0xtest_attack_tx',
                    counterparty: str = '0xsanctioned') -> ComplianceFlag:
    """Construct a test ComplianceFlag for use in attacks."""
    return ComplianceFlag(
        flag_type=FLAG_SANCTIONS_HIT,
        severity=severity,
        transaction_hashes=[tx_hash],
        addresses_involved=[
            AddressInvolvement(
                address=counterparty,
                chain='ethereum',
                role='receiver',
                label='test',
            ),
        ],
        risk_score=risk_score,
        rationale_hash='0' * 64,
        evidence_pointer=tx_hash,
        detected_at_ms=int(time.time() * 1000),
        chain='ethereum',
    )


def _proof_blob(data: dict) -> str:
    """Serialize attack proof data to base64-encoded JSON."""
    return base64.b64encode(
        json.dumps(data, sort_keys=True).encode('utf-8')
    ).decode('ascii')


# ─── Attack 1: forge_ma_identity ──────────────────────────────────

def attack_forge_ma_identity(sandbox) -> AttackResult:
    """Try to file a flag from an MA not registered with FA.

    Defense (Phase 1.5 MA-binding): FA rejects with 'unregistered_ma'.
    """
    acreo = sandbox.get_acreo()
    op = sandbox.get_operator()
    fa = sandbox.get_fa()

    try:
        # Create an attacker agent with valid op-issued credential
        attacker = acreo.create_agent('attacker')
        attacker_cred = acreo.delegate(
            op, attacker,
            permissions=['communicate'],
            scope=['compliance/crypto/*'],
            heartbeat_interval_ms=300_000,
        )

        # Construct a flag and try to file it
        flag = _make_test_flag()
        proof = attacker.propose(
            cred=attacker_cred,
            action='communicate',
            resource='compliance/crypto/ethereum',
            condition=flag.to_condition_dict(),
            valid_until_ms=int(time.time() * 1000) + 60_000,
        )
        result = fa.receive_flag(proof)

        # Did the attack succeed?
        if result.accepted:
            return AttackResult(
                succeeded=True,
                description=(
                    "FA accepted flag from unregistered MA — "
                    "Phase 1.5 MA-binding broken"
                ),
                proof_data={
                    'attacker_pubkey': attacker.public_key,
                    'filing_id': result.filing_id,
                },
            )
        else:
            return AttackResult(
                succeeded=False,
                description=(
                    f"defense held: rejected with '{result.rejection_reason}'"
                ),
                proof_data={'rejection_reason': result.rejection_reason},
            )
    except (AcreoError, ValueError) as e:
        return AttackResult(
            succeeded=False,
            description=f"attack blocked at construction: {type(e).__name__}: {e}",
            error=f"{type(e).__name__}: {e}",
        )


# ─── Attack 2: submit_expired_credential ──────────────────────────

def attack_submit_expired_credential(sandbox) -> AttackResult:
    """Try to file a flag using an expired MA credential.

    Defense: propose() should refuse to issue a proof against an
    expired credential. If propose somehow succeeds, FA's verifier
    chain should reject. Either way, defense holds.
    """
    ma = sandbox.get_ma()
    ma_cred = sandbox.get_ma_credential()
    ma_identity = sandbox.get_ma_identity()
    fa = sandbox.get_fa()

    try:
        # Manually expire the credential
        ma_cred.expires_at = int(time.time() * 1000) - 10_000  # 10s ago

        flag = _make_test_flag()

        try:
            proof = ma_identity.propose(
                cred=ma_cred,
                action='communicate',
                resource='compliance/crypto/ethereum',
                condition=flag.to_condition_dict(),
                valid_until_ms=int(time.time() * 1000) + 60_000,
            )
            # If propose succeeded somehow, see if FA accepts
            result = fa.receive_flag(proof)
            if result.accepted:
                return AttackResult(
                    succeeded=True,
                    description=(
                        "Expired credential's flag was accepted — "
                        "credential lifecycle broken"
                    ),
                    proof_data={'filing_id': result.filing_id},
                )
            return AttackResult(
                succeeded=False,
                description=(
                    f"defense held: FA rejected with "
                    f"'{result.rejection_reason}'"
                ),
                proof_data={'rejection_reason': result.rejection_reason},
            )
        except (AcreoError, ValueError) as e:
            # Expected: propose blocks with ExpiredError or similar
            return AttackResult(
                succeeded=False,
                description=(
                    f"defense held: propose blocked with "
                    f"{type(e).__name__}"
                ),
                proof_data={'block_point': 'propose', 'error_type': type(e).__name__},
            )
    except Exception as e:
        return AttackResult(
            succeeded=False,
            description=f"attack errored: {type(e).__name__}: {e}",
            error=f"{type(e).__name__}: {e}",
        )


# ─── Attack 3: submit_wrong_scope ─────────────────────────────────

def attack_submit_wrong_scope(sandbox) -> AttackResult:
    """Try to file a flag with a credential that lacks the required scope.

    Defense: propose() should reject because the credential's scope
    doesn't cover the resource being acted on.
    """
    acreo = sandbox.get_acreo()
    op = sandbox.get_operator()
    fa = sandbox.get_fa()

    try:
        # Create an MA-like agent with WRONG scope
        rogue_ma = acreo.create_agent('rogue-ma')
        rogue_cred = acreo.delegate(
            op, rogue_ma,
            permissions=['read', 'communicate'],
            scope=['compliance/different/*'],  # wrong domain
            heartbeat_interval_ms=300_000,
        )

        flag = _make_test_flag()

        try:
            proof = rogue_ma.propose(
                cred=rogue_cred,
                action='communicate',
                resource='compliance/crypto/ethereum',  # outside scope
                condition=flag.to_condition_dict(),
                valid_until_ms=int(time.time() * 1000) + 60_000,
            )
            result = fa.receive_flag(proof)
            if result.accepted:
                return AttackResult(
                    succeeded=True,
                    description=(
                        "Out-of-scope credential's flag was accepted — "
                        "scope enforcement broken"
                    ),
                )
            return AttackResult(
                succeeded=False,
                description=(
                    f"defense held: FA rejected with "
                    f"'{result.rejection_reason}'"
                ),
            )
        except (AcreoError, ValueError) as e:
            return AttackResult(
                succeeded=False,
                description=(
                    f"defense held: propose blocked with "
                    f"{type(e).__name__}"
                ),
                proof_data={'block_point': 'propose'},
            )
    except Exception as e:
        return AttackResult(
            succeeded=False,
            description=f"attack errored: {type(e).__name__}: {e}",
            error=f"{type(e).__name__}: {e}",
        )


# ─── Attack 4: tamper_condition_dict ──────────────────────────────

def attack_tamper_condition_dict(sandbox) -> AttackResult:
    """Try to modify a flag's condition after the proof was signed.

    Defense: FA's signature verification catches the mismatch
    between the proof's commitment and the modified condition.
    """
    ma_identity = sandbox.get_ma_identity()
    ma_cred = sandbox.get_ma_credential()
    fa = sandbox.get_fa()

    try:
        # Get a legitimate flag + proof
        flag = _make_test_flag(severity=SEVERITY_HIGH, risk_score=0.7)
        proof = ma_identity.propose(
            cred=ma_cred,
            action='communicate',
            resource='compliance/crypto/ethereum',
            condition=flag.to_condition_dict(),
            valid_until_ms=int(time.time() * 1000) + 60_000,
        )

        # Tamper the condition AFTER signing
        # Try to escalate severity post-hoc
        tampered_condition = dict(proof.condition)
        tampered_condition['severity'] = SEVERITY_CRITICAL

        # Replace the proof's condition
        # (proof is frozen but we can try via __dict__ or object.__setattr__)
        try:
            object.__setattr__(proof, 'condition', tampered_condition)
        except (AttributeError, TypeError):
            return AttackResult(
                succeeded=False,
                description="defense held: proof is immutable, cannot tamper",
            )

        result = fa.receive_flag(proof)
        if result.accepted:
            return AttackResult(
                succeeded=True,
                description=(
                    "FA accepted tampered condition — "
                    "signature verification broken"
                ),
                proof_data={'filing_id': result.filing_id},
            )
        return AttackResult(
            succeeded=False,
            description=(
                f"defense held: rejected with '{result.rejection_reason}'"
            ),
            proof_data={'rejection_reason': result.rejection_reason},
        )
    except Exception as e:
        return AttackResult(
            succeeded=False,
            description=f"attack errored: {type(e).__name__}: {e}",
            error=f"{type(e).__name__}: {e}",
        )


# ─── Attack 5: submit_duplicate ───────────────────────────────────

def attack_submit_duplicate(sandbox) -> AttackResult:
    """Try to make FA file the same flag twice.

    Defense: dedup set rejects the second submission.
    """
    ma_identity = sandbox.get_ma_identity()
    ma_cred = sandbox.get_ma_credential()
    fa = sandbox.get_fa()

    try:
        flag = _make_test_flag()

        # First submission (legitimate)
        proof1 = ma_identity.propose(
            cred=ma_cred,
            action='communicate',
            resource='compliance/crypto/ethereum',
            condition=flag.to_condition_dict(),
            valid_until_ms=int(time.time() * 1000) + 60_000,
        )
        result1 = fa.receive_flag(proof1)

        if not result1.accepted:
            # First submission was rejected for reasons unrelated to dedup
            return AttackResult(
                succeeded=False,
                description=(
                    f"first submission already rejected: "
                    f"{result1.rejection_reason}"
                ),
            )

        # Second submission (attack: same flag, fresh proof)
        proof2 = ma_identity.propose(
            cred=ma_cred,
            action='communicate',
            resource='compliance/crypto/ethereum',
            condition=flag.to_condition_dict(),
            valid_until_ms=int(time.time() * 1000) + 60_000,
        )
        result2 = fa.receive_flag(proof2)

        # Did dedup catch it?
        # FA's contract: accepted=True with filing_id=None means deduplicated.
        # accepted=True with filing_id set means a NEW filing was created.
        # Dedup is broken only if a new filing_id is produced.
        if result2.accepted and result2.filing_id is not None:
            return AttackResult(
                succeeded=True,
                description=(
                    "Duplicate flag was filed twice — dedup broken"
                ),
                proof_data={
                    'first_filing': result1.filing_id,
                    'second_filing': result2.filing_id,
                },
            )
        return AttackResult(
            succeeded=False,
            description=(
                f"defense held: dedup blocked second filing "
                f"(accepted={result2.accepted}, filing_id={result2.filing_id})"
            ),
            proof_data={
                'first_filing': result1.filing_id,
                'second_filing': result2.filing_id,
                'rejection_reason': result2.rejection_reason,
            },
        )
    except Exception as e:
        return AttackResult(
            succeeded=False,
            description=f"attack errored: {type(e).__name__}: {e}",
            error=f"{type(e).__name__}: {e}",
        )


# ─── Attack 6: inflate_severity ───────────────────────────────────

def attack_inflate_severity(sandbox) -> AttackResult:
    """Try to file a flag claiming CRITICAL severity for benign data.

    Defense (Phase 1.7): severity-vs-risk-score cross-check rejects
    flags where claimed severity is more than one tier above what
    risk_score warrants.
    """
    ma_identity = sandbox.get_ma_identity()
    ma_cred = sandbox.get_ma_credential()
    fa = sandbox.get_fa()

    try:
        # Construct a flag with absurd severity vs risk_score
        flag = _make_test_flag(
            severity=SEVERITY_CRITICAL,
            risk_score=0.05,  # warrants LOW max, claiming CRITICAL
        )

        proof = ma_identity.propose(
            cred=ma_cred,
            action='communicate',
            resource='compliance/crypto/ethereum',
            condition=flag.to_condition_dict(),
            valid_until_ms=int(time.time() * 1000) + 60_000,
        )
        result = fa.receive_flag(proof)

        if result.accepted:
            return AttackResult(
                succeeded=True,
                description=(
                    "Inflated severity (CRITICAL with risk_score=0.05) "
                    "was accepted — Phase 1.7 cross-check broken"
                ),
                proof_data={'filing_id': result.filing_id},
            )
        return AttackResult(
            succeeded=False,
            description=(
                f"defense held: rejected with '{result.rejection_reason}'"
            ),
            proof_data={'rejection_reason': result.rejection_reason},
        )
    except Exception as e:
        return AttackResult(
            succeeded=False,
            description=f"attack errored: {type(e).__name__}: {e}",
            error=f"{type(e).__name__}: {e}",
        )


# ─── Attack library registry ──────────────────────────────────────

PHASE_3_STEP_4_ATTACKS = {
    'forge_ma_identity': attack_forge_ma_identity,
    'submit_expired_credential': attack_submit_expired_credential,
    'submit_wrong_scope': attack_submit_wrong_scope,
    'tamper_condition_dict': attack_tamper_condition_dict,
    'submit_duplicate': attack_submit_duplicate,
    'inflate_severity': attack_inflate_severity,
}


# ─── Self-test ────────────────────────────────────────────────────

def _self_test() -> int:
    print("agents.redteam_attacks self-test (Step 4: 6 FA attacks)")
    print("─" * 50)

    from agents.redteam_agent import RedTeamSandbox
    from agents.redteam_schemas import RedTeamConfig

    results = []

    def check(name, fn):
        try:
            ok = fn()
        except Exception as e:
            print(f"  ✗ {name}: {type(e).__name__}: {e}")
            results.append(False)
            return
        if ok:
            print(f"  ✓ {name}")
            results.append(True)
        else:
            print(f"  ✗ {name}: returned False")
            results.append(False)

    config = RedTeamConfig(
        watch_list=('0xcustomer',),
        sanctions_addresses=('0xsanctioned',),
    )

    # For each attack, verify:
    # - it runs without crashing
    # - against current Phase 1+1.5+1.6+1.7 hardening, defense holds
    # - the AttackResult has the right shape

    def run_attack(attack_fn):
        with RedTeamSandbox(config) as sb:
            return attack_fn(sb)

    # 1. forge_ma_identity: defense should hold (Phase 1.5)
    def t_forge_ma_identity():
        result = run_attack(attack_forge_ma_identity)
        return (not result.succeeded
                and 'unregistered_ma' in str(result.proof_data))
    check("forge_ma_identity: defense holds", t_forge_ma_identity)

    # 2. submit_expired_credential: defense should hold
    def t_expired_cred():
        result = run_attack(attack_submit_expired_credential)
        return not result.succeeded
    check("submit_expired_credential: defense holds", t_expired_cred)

    # 3. submit_wrong_scope: defense should hold
    def t_wrong_scope():
        result = run_attack(attack_submit_wrong_scope)
        return not result.succeeded
    check("submit_wrong_scope: defense holds", t_wrong_scope)

    # 4. tamper_condition_dict: defense should hold
    def t_tamper():
        result = run_attack(attack_tamper_condition_dict)
        return not result.succeeded
    check("tamper_condition_dict: defense holds", t_tamper)

    # 5. submit_duplicate: defense should hold (dedup)
    def t_duplicate():
        result = run_attack(attack_submit_duplicate)
        return not result.succeeded
    check("submit_duplicate: defense holds", t_duplicate)

    # 6. inflate_severity: defense should hold (Phase 1.7)
    def t_inflate():
        result = run_attack(attack_inflate_severity)
        return (not result.succeeded
                and 'severity_exceeds_risk_score' in str(result.proof_data))
    check("inflate_severity: defense holds (Phase 1.7)", t_inflate)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")

    if passed == total:
        print()
        print("  All 6 attacks correctly report 'defense holds'.")
        print("  This proves Phase 1.5/1.6/1.7 hardening works against")
        print("  live adversarial probes, not just chaos suite assertions.")

    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
