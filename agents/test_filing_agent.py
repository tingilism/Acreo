"""
agents/test_filing_agent.py — self-tests for Filing Agent
============================================================

Twelve tests covering Phase 1 of the compliance operation:

  1. Schema validation: malformed flags rejected at construction
  2. Round-trip: flag.to_condition_dict() / from_condition_dict() preserves data
  3. Happy path sanctions: critical sanctions hit produces SAR
  4. Happy path threshold: high-severity threshold crossing produces SAR
  5. Wrong condition type rejected
  6. Forged proof rejected (bad signature)
  7. Duplicate flag deduplicated
  8. Low severity skipped (audit recorded but no filing)
  9. Medium severity queued for review (audit recorded but no filing)
 10. Stale flag rejected
 11. Activity stream chain advances correctly across multiple flags
 12. Filings written to mock destination with valid JSON

Run:
    python -m agents.test_filing_agent
"""

from __future__ import annotations
import json
import sys
import time
import shutil
import tempfile
from pathlib import Path

from acreo import Identity, Acreo

from agents.compliance_schemas import (
    ComplianceFlag, AddressInvolvement, SARFiling,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    FLAG_SANCTIONS_HIT, FLAG_THRESHOLD_CROSSING, FLAG_SUSPICIOUS_PATTERN,
    FLAG_MIXER_INTERACTION, FILING_SAR,
    hash_flag, regulatory_deadline_for,
)
from agents.filing_agent import FilingAgent, FilingResult


# ─── Helpers ──────────────────────────────────────────────────────

def make_flag(severity=SEVERITY_CRITICAL,
              flag_type=FLAG_SANCTIONS_HIT,
              detected_at_ms=None,
              risk_score=0.95) -> ComplianceFlag:
    """Construct a valid ComplianceFlag with reasonable defaults."""
    if detected_at_ms is None:
        detected_at_ms = int(time.time() * 1000)
    return ComplianceFlag(
        flag_type=flag_type,
        severity=severity,
        transaction_hashes=['0xabc123def456'],
        addresses_involved=[
            AddressInvolvement(
                address='0xSANCTIONED_ADDR',
                chain='ethereum',
                role='sanctioned',
                label='OFAC SDN entry'
            ),
        ],
        risk_score=risk_score,
        rationale_hash='0' * 64,
        evidence_pointer='1' * 64,
        detected_at_ms=detected_at_ms,
        chain='ethereum',
    )


def setup_fa(filings_dir: str):
    """Set up an Acreo instance, operator, FA identity, credential, and FA.

    Returns (acreo, operator, ma_identity, fa, fa_credential).
    The 'ma_identity' is a placeholder simulating MA — used to produce
    signed ConditionalProofs for FA to receive.
    """
    acreo = Acreo()
    operator = acreo.create_user('jimmy')

    # MA's role in Phase 1 is played by another agent identity that the
    # operator delegates flag-production authority to.
    ma_identity = acreo.create_agent('monitoring-agent')
    ma_credential = acreo.delegate(
        operator, ma_identity,
        permissions=['read', 'communicate'],
        scope=['compliance/crypto/*'],
        heartbeat_interval_ms=300000,
    )

    fa_identity = acreo.create_agent('filing-agent')
    fa_credential = acreo.delegate(
        operator, fa_identity,
        permissions=['write', 'communicate'],
        scope=['compliance/crypto/*'],
        heartbeat_interval_ms=60000,
    )

    fa = FilingAgent(
        identity=fa_identity,
        credential=fa_credential,
        operator=operator,
        verifier=acreo._verifier,
        filings_dir=filings_dir,
    )

    return acreo, operator, ma_identity, ma_credential, fa


def ma_produces_flag_proof(acreo, ma_identity, ma_credential,
                            flag: ComplianceFlag,
                            valid_until_ms=None):
    """Have MA produce a signed ConditionalProof carrying the flag.

    In Phase 1 this is the operator-driven flow; in Phase 2 the real
    Monitoring Agent does this.
    """
    if valid_until_ms is None:
        valid_until_ms = int(time.time() * 1000) + 60_000  # 1 min
    # Acreo's propose() validates action against cred.permissions.
    # 'communicate' is the right Permission enum value for "MA sends
    # flag to FA". The compliance domain meaning lives in resource.
    proof = ma_identity.propose(
        cred=ma_credential,
        action='communicate',
        resource=f'compliance/crypto/{flag.chain}',
        condition=flag.to_condition_dict(),
        valid_until_ms=valid_until_ms,
    )
    return proof


# ─── Test runner ──────────────────────────────────────────────────

def main():
    print("Filing Agent self-test")
    print("─" * 50)
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

    # Use a temporary directory for mock filings
    tmp_dir = tempfile.mkdtemp(prefix='acreo_fa_test_')

    try:
        # ─── 1. Schema validation ─────────────────────────────────
        def schema_validation():
            try:
                ComplianceFlag(
                    flag_type='bogus_type',
                    severity=SEVERITY_CRITICAL,
                    transaction_hashes=['0xabc'],
                    addresses_involved=[
                        AddressInvolvement(address='0x', chain='ethereum',
                                           role='sender')
                    ],
                    risk_score=0.5,
                    rationale_hash='0' * 64,
                    evidence_pointer='0' * 64,
                    detected_at_ms=int(time.time() * 1000),
                    chain='ethereum',
                )
                return False  # should have raised
            except ValueError:
                return True
        check("schema rejects invalid flag_type", schema_validation)

        # ─── 2. Condition dict round-trip ─────────────────────────
        def condition_round_trip():
            f = make_flag()
            cd = f.to_condition_dict()
            assert cd['type'] == 'compliance_flag'
            f2 = ComplianceFlag.from_condition_dict(cd)
            return (f.flag_type == f2.flag_type
                    and f.severity == f2.severity
                    and f.risk_score == f2.risk_score
                    and len(f.addresses_involved) == len(f2.addresses_involved))
        check("condition dict round-trip preserves flag", condition_round_trip)

        # ─── 3. Happy path: critical sanctions hit ────────────────
        def happy_sanctions():
            d = tempfile.mkdtemp(prefix='acreo_fa_happy_sanctions_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                flag = make_flag(severity=SEVERITY_CRITICAL,
                                 flag_type=FLAG_SANCTIONS_HIT)
                proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                result = fa.receive_flag(proof)
                if not result.accepted or result.filing_id is None:
                    return False
                # Confirm filing was written
                filing_path = Path(d) / f"{result.filing_id}.json"
                if not filing_path.exists():
                    return False
                # Confirm filing is valid JSON
                filing_data = json.loads(filing_path.read_text())
                return (filing_data['filing_type'] == FILING_SAR
                        and filing_data['filing_id'] == result.filing_id)
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("critical sanctions hit produces SAR filing", happy_sanctions)

        # ─── 4. Happy path: high-severity threshold ───────────────
        def happy_threshold():
            d = tempfile.mkdtemp(prefix='acreo_fa_happy_threshold_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                flag = make_flag(severity=SEVERITY_HIGH,
                                 flag_type=FLAG_THRESHOLD_CROSSING)
                proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                result = fa.receive_flag(proof)
                return (result.accepted and result.filing_id is not None)
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("high-severity threshold produces SAR", happy_threshold)

        # ─── 5. Wrong condition type rejected ─────────────────────
        def wrong_condition_rejected():
            d = tempfile.mkdtemp(prefix='acreo_fa_wrong_cond_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                # Build a proof with condition type='always' instead of
                # 'compliance_flag'
                proof = ma_id.propose(
                    cred=ma_cred,
                    action='communicate',
                    resource='compliance/crypto/ethereum',
                    condition={'type': 'always'},
                    valid_until_ms=int(time.time() * 1000) + 60_000,
                )
                result = fa.receive_flag(proof)
                return (not result.accepted
                        and 'wrong_condition_type' in (result.rejection_reason or ''))
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("wrong condition type rejected", wrong_condition_rejected)

        # ─── 6. Forged signature rejected ─────────────────────────
        def forged_sig_rejected():
            d = tempfile.mkdtemp(prefix='acreo_fa_forged_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                flag = make_flag()
                proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                # Tamper with signature
                proof.signature = ('1' if proof.signature[0] != '1' else '0') + proof.signature[1:]
                result = fa.receive_flag(proof)
                return not result.accepted
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("forged signature rejected", forged_sig_rejected)

        # ─── 7. Duplicate flag deduplicated ───────────────────────
        def duplicate_dedup():
            d = tempfile.mkdtemp(prefix='acreo_fa_dup_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                flag = make_flag(severity=SEVERITY_HIGH)
                proof1 = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                # Different proof object but same flag content → same hash
                proof2 = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                r1 = fa.receive_flag(proof1)
                r2 = fa.receive_flag(proof2)
                return (r1.filing_id is not None
                        and r2.filing_id is None
                        and r2.skip_reason == 'duplicate_flag_already_filed')
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("duplicate flag deduplicated", duplicate_dedup)

        # ─── 8. Low severity skipped ──────────────────────────────
        def low_severity_skipped():
            d = tempfile.mkdtemp(prefix='acreo_fa_low_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                flag = make_flag(severity=SEVERITY_LOW,
                                 flag_type=FLAG_SUSPICIOUS_PATTERN,
                                 risk_score=0.3)
                proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                result = fa.receive_flag(proof)
                return (result.accepted
                        and result.filing_id is None
                        and result.skip_reason == 'low_severity_below_threshold')
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("low severity skipped without filing", low_severity_skipped)

        # ─── 9. Medium severity queued for review ─────────────────
        def medium_severity_queued():
            d = tempfile.mkdtemp(prefix='acreo_fa_med_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                flag = make_flag(severity=SEVERITY_MEDIUM,
                                 flag_type=FLAG_SUSPICIOUS_PATTERN,
                                 risk_score=0.6)
                proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                result = fa.receive_flag(proof)
                return (result.accepted
                        and result.filing_id is None
                        and result.skip_reason == 'medium_severity_requires_human_review')
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("medium severity queued for review", medium_severity_queued)

        # ─── 10. Stale flag rejected ──────────────────────────────
        def stale_flag_rejected():
            d = tempfile.mkdtemp(prefix='acreo_fa_stale_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                # Detected 48 hours ago — outside default 24h freshness window
                stale_time = int(time.time() * 1000) - 48 * 60 * 60 * 1000
                flag = make_flag(severity=SEVERITY_CRITICAL,
                                 detected_at_ms=stale_time)
                # Use a valid_until_ms in the future so the proof itself is fresh
                # but the flag claims old detection time
                proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                result = fa.receive_flag(proof)
                return (not result.accepted
                        and result.rejection_reason == 'stale_flag')
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("stale flag rejected", stale_flag_rejected)

        # ─── 11. Activity stream chain advances ──────────────────
        def activity_chain():
            d = tempfile.mkdtemp(prefix='acreo_fa_chain_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                # Process 3 flags
                for i in range(3):
                    flag = make_flag(severity=SEVERITY_CRITICAL,
                                     flag_type=FLAG_SANCTIONS_HIT)
                    # Vary the rationale_hash so flag hashes differ
                    flag.rationale_hash = (str(i) * 64)[:64]
                    proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                    fa.receive_flag(proof)
                # Stream should have multiple frames
                frames = fa.activity_stream.frames
                # First few frames are the observation/reasoning/action triplets
                # for the first flag, plus the operator notification reasoning frame.
                # Per flag we record: 1 obs + 1 reasoning + 1 action + 1 reasoning
                # = 4 frames. So 3 flags = 12 frames.
                if len(frames) < 9:  # at minimum
                    return False
                # Frame indices should be monotonic
                for i, f in enumerate(frames):
                    if f.frame_index != i:
                        return False
                # Chain hashes must form an unbroken chain
                from acreo_activity_stream import _frame_chain_hash
                expected_prev = '0' * 64
                for f in frames:
                    if f.previous_frame_hash != expected_prev:
                        return False
                    expected_prev = _frame_chain_hash(f.to_dict())
                return True
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("activity stream chain advances correctly", activity_chain)

        # ─── 12. Filing has valid structure ──────────────────────
        def filing_structure():
            d = tempfile.mkdtemp(prefix='acreo_fa_struct_')
            try:
                acreo, op, ma_id, ma_cred, fa = setup_fa(d)
                flag = make_flag(severity=SEVERITY_CRITICAL,
                                 flag_type=FLAG_SANCTIONS_HIT)
                proof = ma_produces_flag_proof(acreo, ma_id, ma_cred, flag)
                result = fa.receive_flag(proof)
                if not result.accepted or result.filing_id is None:
                    return False
                filing_path = Path(d) / f"{result.filing_id}.json"
                data = json.loads(filing_path.read_text())
                required_fields = [
                    'filing_id', 'filing_type', 'originating_flag_hash',
                    'flag_summary', 'filed_at_ms', 'regulatory_deadline_ms',
                    'narrative', 'filer_id', 'protocol',
                ]
                for field_name in required_fields:
                    if field_name not in data:
                        return False
                # Regulatory deadline should be in the future for a fresh flag
                if data['regulatory_deadline_ms'] <= data['filed_at_ms']:
                    return False
                # Narrative should be non-trivial
                if len(data['narrative']) < 100:
                    return False
                return True
            finally:
                shutil.rmtree(d, ignore_errors=True)
        check("filing JSON has all required fields and valid structure",
              filing_structure)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
