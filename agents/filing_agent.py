"""
agents/filing_agent.py — Filing Agent for compliance operation
=================================================================

Phase 1 of the 3-agent compliance operation. FA receives compliance
flags (initially from manual operator input, eventually from MA),
verifies them, generates compliance filings, and maintains a full
Acreo audit trail.

Architecture:

  Operator/MA → ConditionalProof(condition=ComplianceFlag) → FA.receive_flag()
                                                                    │
                                                                    ▼
                                                          verify signature
                                                          verify scope
                                                          verify freshness
                                                                    │
                                                                    ▼
                                                          decide: file or skip
                                                                    │
                                                                    ▼
                                                          generate SAR filing
                                                          ActionProof for filing
                                                          write to mock destination
                                                          activity stream record
                                                          OperatorReport to op
                                                                    │
                                                                    ▼
                                                              return result

PHASE 1 SCOPE:
  - SAR filings only (most common AML filing)
  - Mock destination (writes to local directory, not real FinCEN API)
  - Manual operator-produced flags (no Monitoring Agent yet)
  - Single chain support per flag (multi-chain in Phase 1.5)

OUT OF SCOPE FOR PHASE 1:
  - Real regulatory API submission
  - CTR filings, sanctions notices (other filing types)
  - MA integration (next phase)
  - Multi-chain flag aggregation
"""

from __future__ import annotations
import os
import json
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass

from acreo import (
    Identity, Credential, Acreo, AcreoError, CredentialError,
    ConditionalProof, Entropy,
)
from acreo_activity_stream import ActivityStream

from agents.compliance_schemas import (
    ComplianceFlag, SARFiling, AddressInvolvement,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    FLAG_SANCTIONS_HIT, FLAG_THRESHOLD_CROSSING, FLAG_SUSPICIOUS_PATTERN,
    FLAG_MIXER_INTERACTION, FILING_SAR,
    hash_flag, regulatory_deadline_for,
)


# Filing decision thresholds — tunable per deployment
DEFAULT_AUTO_FILE_SEVERITIES = (SEVERITY_HIGH, SEVERITY_CRITICAL)
DEFAULT_FRESHNESS_WINDOW_MS = 24 * 60 * 60 * 1000  # 24 hours

# Phase 1.7: severity-vs-risk-score cross-check.
# Maps risk_score thresholds to maximum allowable severity tier.
# A flag with risk_score in [low_bound, high_bound) cannot legitimately
# claim a severity higher than max_severity. One-tier tolerance is allowed
# (e.g. risk_score=0.1 may declare LOW or MEDIUM but not HIGH or CRITICAL).
SEVERITY_TIER_ORDER = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)


def max_severity_for_risk(risk_score: float) -> str:
    """Return the maximum severity tier warranted by a given risk_score."""
    if risk_score < 0.30:
        return SEVERITY_LOW
    elif risk_score < 0.60:
        return SEVERITY_MEDIUM
    elif risk_score < 0.85:
        return SEVERITY_HIGH
    else:
        return SEVERITY_CRITICAL


def severity_within_tolerance(declared: str, risk_score: float) -> bool:
    """True if declared severity is within one tier of what risk_score warrants."""
    max_warranted = max_severity_for_risk(risk_score)
    declared_idx = SEVERITY_TIER_ORDER.index(declared)
    warranted_idx = SEVERITY_TIER_ORDER.index(max_warranted)
    return declared_idx <= warranted_idx + 1

# Reasons for skipping a filing — for audit trail clarity
SKIP_LOW_SEVERITY = "low_severity_below_threshold"
SKIP_NEEDS_HUMAN_REVIEW = "medium_severity_requires_human_review"
SKIP_DUPLICATE = "duplicate_flag_already_filed"


@dataclass
class FilingResult:
    """Outcome of FA processing a single flag."""
    accepted: bool
    filing_id: Optional[str] = None
    skip_reason: Optional[str] = None
    rejection_reason: Optional[str] = None
    activity_frame_id: Optional[str] = None


class FilingAgent:
    """Compliance Filing Agent.

    Holds an Acreo identity (kind='agent'), a credential issued by the
    operator, and operational state (queue of pending filings, history
    of filings produced, set of seen flag hashes for deduplication).

    Usage:
        operator = Identity.create_user('jimmy')
        fa_identity = Identity.create_agent('filing-agent')
        cred = operator.delegate(
            fa_identity.public_key, ['file', 'report'],
            scope=['compliance/crypto/*'], heartbeat_interval_ms=60000
        )
        fa = FilingAgent(
            identity=fa_identity,
            credential=cred,
            operator=operator,
            verifier=acreo._verifier,
            filings_dir='./mock_filings',
        )
        result = fa.receive_flag(conditional_proof, flag)
    """

    def __init__(self,
                 identity: Identity,
                 credential: Credential,
                 operator: Identity,
                 verifier,
                 filings_dir: str = './mock_filings',
                 auto_file_severities: tuple = DEFAULT_AUTO_FILE_SEVERITIES,
                 freshness_window_ms: int = DEFAULT_FRESHNESS_WINDOW_MS,
                 trusted_ma_keys: Optional[set] = None):
        if identity.kind != 'agent':
            raise AcreoError(
                f"FilingAgent requires agent identity, got kind={identity.kind!r}")
        if credential.agent_key != identity.public_key:
            raise CredentialError(
                "credential not issued to this filing agent's key")
        # Acreo's Permission enum is domain-agnostic; we accept either
        # 'write' (for filing reports) or 'communicate' (for operator notifications).
        # Domain meaning ('compliance') lives in credential.scope.
        if not credential.has('write') and not credential.has('communicate'):
            raise CredentialError(
                "credential must grant 'write' or 'communicate' permission")

        self.identity = identity
        self.credential = credential
        self.operator = operator
        self.verifier = verifier
        self.filings_dir = Path(filings_dir)
        self.filings_dir.mkdir(parents=True, exist_ok=True)
        self.auto_file_severities = set(auto_file_severities)
        self.freshness_window_ms = freshness_window_ms
        # Phase 1.5: explicit MA-binding. If non-empty, only flags from
        # listed pubkeys are accepted. If None/empty, Phase 1 permissive
        # behavior (any operator-credentialed agent can flag).
        self.trusted_ma_keys = set(trusted_ma_keys) if trusted_ma_keys else set()
        # Phase 1.6: coarse lock to serialize flag processing per FA instance.
        # Protects dedup set, filings list, and activity stream chain from
        # concurrent mutation. See chaos_filing_agent::parallel_filing_race.
        self._lock = threading.Lock()

        # Operational state
        self._seen_flag_hashes: set = set()
        self._filings_produced: list = []

        # Activity stream for FA's own behavior
        self._stream = ActivityStream(self.identity)

    # ─── Receiving and verifying flags ────────────────────────────

    def receive_flag(self, proof: ConditionalProof) -> FilingResult:
        """Process an incoming compliance flag.

        proof: a signed ConditionalProof with condition type='compliance_flag'.
               The flag fields ride inside proof.condition.

        Returns a FilingResult describing what FA did.

        Stage F architecture: the ComplianceFlag is the condition. The
        cryptographic primitive (ConditionalProof) commits the sender to
        the flag; the flag fields are extracted from proof.condition.

        Phase 1.6: serialized via self._lock. Flag processing per FA
        instance is single-threaded; concurrent callers wait for the lock.
        """
        with self._lock:
            return self._receive_flag_locked(proof)

    def _receive_flag_locked(self, proof: ConditionalProof) -> FilingResult:
        """Inner implementation of receive_flag, called under self._lock.

        Split out so the locking is unambiguous: caller acquires lock,
        this method does the work, caller releases on return.
        """
        # Phase 1.7: FA self-validation. Check own credential before
        # processing anything. If FA's credential has expired or been
        # revoked, FA must not produce filings — its ActionProofs would
        # be rejected by downstream verifiers anyway.
        now_ms = int(time.time() * 1000)
        if self.credential.expires_at <= now_ms:
            return FilingResult(
                accepted=False,
                rejection_reason='fa_credential_expired',
            )

        # Phase 1.5: MA-binding check. If trusted_ma_keys is non-empty,
        # only registered MA pubkeys can produce flags. Empty set means
        # Phase 1 permissive behavior (backward compatible).
        if self.trusted_ma_keys and proof.agent_key not in self.trusted_ma_keys:
            return FilingResult(
                accepted=False,
                rejection_reason='unregistered_ma',
            )

        # Extract the flag from the proof's condition field
        if not isinstance(proof.condition, dict):
            return FilingResult(
                accepted=False,
                rejection_reason='malformed_condition',
            )
        if proof.condition.get('type') != 'compliance_flag':
            return FilingResult(
                accepted=False,
                rejection_reason=f'wrong_condition_type:{proof.condition.get("type")}',
            )

        try:
            flag = ComplianceFlag.from_condition_dict(proof.condition)
        except (ValueError, KeyError, TypeError) as e:
            return FilingResult(
                accepted=False,
                rejection_reason=f'flag_extraction_failed:{type(e).__name__}',
            )

        # Phase 1.7: severity-vs-risk-score cross-check. Reject flags whose
        # declared severity is more than one tier above what risk_score
        # warrants. This catches malicious or buggy MAs claiming high
        # severity for benign events.
        if not severity_within_tolerance(flag.severity, flag.risk_score):
            return FilingResult(
                accepted=False,
                rejection_reason='severity_exceeds_risk_score',
            )

        # Record the observation: we received a flag
        obs_frame = self._stream.record_observation({
            'event': 'flag_received',
            'flag_type': flag.flag_type,
            'severity': flag.severity,
            'risk_score': flag.risk_score,
            'proof_id': proof.proof_id,
            'sender_key': proof.agent_key[:16] + '...',
        })

        # Verify the proof against the verifier (signature + freshness)
        verdict = self.verifier.verify_proposal(proof)
        if not verdict.get('valid'):
            self._stream.record_reasoning({
                'event': 'flag_rejected',
                'reason': verdict.get('reason', 'unknown'),
                'observation_frame_id': obs_frame.frame_id,
            })
            return FilingResult(
                accepted=False,
                rejection_reason=verdict.get('reason', 'verification_failed'),
                activity_frame_id=obs_frame.frame_id,
            )

        # Deduplicate: have we seen this exact flag before?
        flag_hash = hash_flag(flag)
        if flag_hash in self._seen_flag_hashes:
            self._stream.record_reasoning({
                'event': 'flag_skipped',
                'reason': SKIP_DUPLICATE,
                'flag_hash': flag_hash[:16] + '...',
            })
            return FilingResult(
                accepted=True,
                skip_reason=SKIP_DUPLICATE,
                activity_frame_id=obs_frame.frame_id,
            )

        # Freshness check (separate from proof validity for clarity)
        now_ms = int(time.time() * 1000)
        age_ms = now_ms - flag.detected_at_ms
        if age_ms > self.freshness_window_ms:
            self._stream.record_reasoning({
                'event': 'flag_stale',
                'reason': 'flag_outside_freshness_window',
                'age_ms': age_ms,
                'window_ms': self.freshness_window_ms,
            })
            return FilingResult(
                accepted=False,
                rejection_reason='stale_flag',
                activity_frame_id=obs_frame.frame_id,
            )

        # Decide what to do based on severity
        if flag.severity in self.auto_file_severities:
            return self._file_sar(flag, flag_hash, proof, obs_frame.frame_id)
        elif flag.severity == SEVERITY_MEDIUM:
            self._stream.record_reasoning({
                'event': 'flag_queued_for_review',
                'reason': SKIP_NEEDS_HUMAN_REVIEW,
                'flag_hash': flag_hash[:16] + '...',
            })
            self._seen_flag_hashes.add(flag_hash)
            return FilingResult(
                accepted=True,
                skip_reason=SKIP_NEEDS_HUMAN_REVIEW,
                activity_frame_id=obs_frame.frame_id,
            )
        else:
            # Low severity — record and skip
            self._stream.record_reasoning({
                'event': 'flag_skipped',
                'reason': SKIP_LOW_SEVERITY,
                'severity': flag.severity,
            })
            self._seen_flag_hashes.add(flag_hash)
            return FilingResult(
                accepted=True,
                skip_reason=SKIP_LOW_SEVERITY,
                activity_frame_id=obs_frame.frame_id,
            )

    # ─── Generating filings ───────────────────────────────────────

    def _file_sar(self, flag: ComplianceFlag, flag_hash: str,
                  proof: ConditionalProof,
                  observation_frame_id: str) -> FilingResult:
        """Generate a SAR filing for this flag, write to mock destination."""
        now_ms = int(time.time() * 1000)
        filing_id = f"SAR-{Entropy.hex(8)}"

        # Reasoning frame: explain the decision to file
        self._stream.record_reasoning({
            'event': 'filing_decision',
            'decision': 'file_sar',
            'flag_type': flag.flag_type,
            'severity': flag.severity,
            'flag_hash': flag_hash[:16] + '...',
            'rationale': f"severity {flag.severity} triggers auto-filing per policy",
            'observation_frame_id': observation_frame_id,
        })

        # Generate the SAR
        narrative = self._build_narrative(flag)
        flag_summary = {
            'flag_type': flag.flag_type,
            'severity': flag.severity,
            'risk_score': flag.risk_score,
            'transaction_hashes': flag.transaction_hashes,
            'addresses_involved': [a.to_dict() for a in flag.addresses_involved],
            'chain': flag.chain,
            'detected_at_ms': flag.detected_at_ms,
        }

        filing = SARFiling(
            filing_id=filing_id,
            originating_flag_hash=flag_hash,
            flag_summary=flag_summary,
            filed_at_ms=now_ms,
            regulatory_deadline_ms=regulatory_deadline_for(flag),
            narrative=narrative,
            filer_id=self.identity.public_key,
        )

        # Write to mock destination
        filing_path = self.filings_dir / f"{filing_id}.json"
        filing_path.write_text(filing.to_json())

        # Record the action
        action_frame = self._stream.record_action({
            'event': 'sar_filed',
            'filing_id': filing_id,
            'filing_path': str(filing_path),
            'originating_flag_hash': flag_hash[:16] + '...',
            'regulatory_deadline_ms': filing.regulatory_deadline_ms,
        })

        # Update operational state
        self._seen_flag_hashes.add(flag_hash)
        self._filings_produced.append(filing)

        # Send sealed OperatorReport (Phase 1: just record we did)
        # Real OperatorReport flow comes in Phase 1.5 when we wire up
        # the full report() method which requires a Verifier instance.
        self._stream.record_reasoning({
            'event': 'operator_notification_logged',
            'filing_id': filing_id,
            'note': 'sealed OperatorReport flow added in Phase 1.5',
        })

        return FilingResult(
            accepted=True,
            filing_id=filing_id,
            activity_frame_id=action_frame.frame_id,
        )

    def _build_narrative(self, flag: ComplianceFlag) -> str:
        """Generate human-readable narrative for the SAR."""
        lines = [
            f"SUSPICIOUS ACTIVITY REPORT",
            f"Generated by Acreo Filing Agent at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"",
            f"Flag Type: {flag.flag_type}",
            f"Severity: {flag.severity}",
            f"Risk Score: {flag.risk_score:.2f}",
            f"Chain: {flag.chain}",
            f"Detected At: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(flag.detected_at_ms / 1000))}",
            f"",
            f"Transactions Involved ({len(flag.transaction_hashes)}):",
        ]
        for tx in flag.transaction_hashes:
            lines.append(f"  - {tx}")

        lines.append("")
        lines.append(f"Addresses Involved ({len(flag.addresses_involved)}):")
        for addr in flag.addresses_involved:
            label = f" ({addr.label})" if addr.label else ""
            lines.append(f"  - {addr.address} [role: {addr.role}]{label}")

        lines.append("")
        lines.append(f"Evidence Pointer: {flag.evidence_pointer[:32]}...")
        lines.append(f"Rationale Hash: {flag.rationale_hash[:32]}...")

        return "\n".join(lines)

    # ─── Operational accessors ────────────────────────────────────

    def filings_count(self) -> int:
        return len(self._filings_produced)

    def filing_ids(self) -> list:
        return [f.filing_id for f in self._filings_produced]

    @property
    def activity_stream(self) -> ActivityStream:
        return self._stream
