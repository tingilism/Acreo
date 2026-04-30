"""
agents/compliance_schemas.py — compliance flag and filing schemas
====================================================================

Single source of truth for the structure of compliance events as they
flow through the 3-agent operation:

  Monitoring Agent → ConditionalProof(condition=ComplianceFlag) → Filing Agent
  Filing Agent → ActionProof(context=SARFiling) → mock filing destination

Phase 1 covers SAR (Suspicious Activity Report) — the most common
compliance filing in crypto AML work. Future phases add CTR (Currency
Transaction Report), sanctions hit notifications, MiCA-equivalent
filings.

The schemas here are deliberately simple. Real regulatory filings
have many more fields; we ship the minimum viable structure first,
extend as we learn what the operation actually needs.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
import json
import hashlib


# Flag severity levels — used for FA's filing decision logic
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
VALID_SEVERITIES = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)

# Flag types — the kind of compliance event being flagged
FLAG_SANCTIONS_HIT = "sanctions_hit"
FLAG_THRESHOLD_CROSSING = "threshold_crossing"
FLAG_SUSPICIOUS_PATTERN = "suspicious_pattern"
FLAG_MIXER_INTERACTION = "mixer_interaction"
VALID_FLAG_TYPES = (FLAG_SANCTIONS_HIT, FLAG_THRESHOLD_CROSSING,
                    FLAG_SUSPICIOUS_PATTERN, FLAG_MIXER_INTERACTION)

# Filing types — the kind of report FA produces
FILING_SAR = "sar"
FILING_CTR = "ctr"
FILING_SANCTIONS_NOTICE = "sanctions_notice"
VALID_FILING_TYPES = (FILING_SAR, FILING_CTR, FILING_SANCTIONS_NOTICE)


@dataclass
class AddressInvolvement:
    """One address involved in a flagged event, with its role."""
    address: str          # 0x-prefixed hex for EVM chains, etc.
    chain: str            # 'ethereum', 'polygon', 'bitcoin', etc.
    role: str             # 'sender', 'receiver', 'mixer', 'sanctioned'
    label: Optional[str] = None  # human-readable label if known

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ComplianceFlag:
    """A compliance event flagged by the Monitoring Agent.

    This is the payload of the ConditionalProof's condition field that
    MA sends to FA. Phase 1 has the operator producing these manually
    until MA exists.

    Fields:
      - flag_type: which kind of compliance event (see VALID_FLAG_TYPES)
      - severity: how urgent (see VALID_SEVERITIES)
      - transaction_hashes: tx hashes relevant to this flag
      - addresses_involved: addresses with role tags
      - risk_score: 0.0-1.0, MA's confidence
      - rationale_hash: hash of MA's analysis activity stream frame
      - evidence_pointer: hash of supporting on-chain data
      - detected_at_ms: when MA detected the event (unix ms)
      - chain: primary chain this flag pertains to
    """
    flag_type: str
    severity: str
    transaction_hashes: List[str]
    addresses_involved: List[AddressInvolvement]
    risk_score: float
    rationale_hash: str
    evidence_pointer: str
    detected_at_ms: int
    chain: str

    def __post_init__(self):
        if self.flag_type not in VALID_FLAG_TYPES:
            raise ValueError(
                f"flag_type must be one of {VALID_FLAG_TYPES}, "
                f"got {self.flag_type!r}")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {VALID_SEVERITIES}, "
                f"got {self.severity!r}")
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError(
                f"risk_score must be in [0.0, 1.0], got {self.risk_score}")
        if not self.transaction_hashes:
            raise ValueError("transaction_hashes cannot be empty")
        if not self.addresses_involved:
            raise ValueError("addresses_involved cannot be empty")

    def to_dict(self) -> Dict:
        d = asdict(self)
        # asdict handles nested dataclasses but we want consistency
        return d

    def to_condition_dict(self) -> Dict:
        """Convert this flag to a ConditionalProof.condition payload.

        Stage F: ConditionalProof accepts 'compliance_flag' as a condition
        type. The flag rides inside the condition field, with type='compliance_flag'
        as the dispatch tag plus all flag fields flattened in.

        Returns a dict suitable for passing as the condition argument to
        Identity.propose() or Acreo.propose().
        """
        d = self.to_dict()
        d['type'] = 'compliance_flag'
        return d

    @classmethod
    def from_condition_dict(cls, condition: Dict) -> 'ComplianceFlag':
        """Reverse of to_condition_dict — extract a ComplianceFlag from a
        ConditionalProof.condition payload.

        Strips the 'type' field and constructs a ComplianceFlag from the
        remaining fields.
        """
        if condition.get('type') != 'compliance_flag':
            raise ValueError(
                f"expected condition type 'compliance_flag', got {condition.get('type')!r}")
        d = {k: v for k, v in condition.items() if k != 'type'}
        return cls.from_dict(d)

    @classmethod
    def from_dict(cls, d: Dict) -> 'ComplianceFlag':
        # Convert nested AddressInvolvement dicts back to objects
        addresses = [
            AddressInvolvement(**a) if isinstance(a, dict) else a
            for a in d.get('addresses_involved', [])
        ]
        return cls(
            flag_type=d['flag_type'],
            severity=d['severity'],
            transaction_hashes=d['transaction_hashes'],
            addresses_involved=addresses,
            risk_score=d['risk_score'],
            rationale_hash=d['rationale_hash'],
            evidence_pointer=d['evidence_pointer'],
            detected_at_ms=d['detected_at_ms'],
            chain=d['chain'],
        )


@dataclass
class SARFiling:
    """A Suspicious Activity Report.

    Phase 1 minimal structure. Real SARs have many more fields (filer
    info, narrative, regulatory metadata) that get added in Phase 1.5
    when integrating with FinCEN's BSA E-Filing System.

    Fields:
      - filing_id: unique identifier for this filing
      - filing_type: always 'sar' for this dataclass
      - originating_flag_hash: hash of the ComplianceFlag that triggered this
      - flag_summary: copy of the key flag fields (for the report itself)
      - filed_at_ms: when FA generated this filing (unix ms)
      - regulatory_deadline_ms: when this filing must be submitted by
      - narrative: human-readable summary of the suspicious activity
      - filer_id: identifier of the entity producing this filing
      - protocol: schema version
    """
    filing_id: str
    originating_flag_hash: str
    flag_summary: Dict       # subset of ComplianceFlag fields
    filed_at_ms: int
    regulatory_deadline_ms: int
    narrative: str
    filer_id: str
    filing_type: str = FILING_SAR
    protocol: str = "acreo-compliance-sar-v1"

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: Dict) -> 'SARFiling':
        return cls(**{k: v for k, v in d.items()
                       if k in cls.__dataclass_fields__})


def hash_flag(flag: ComplianceFlag) -> str:
    """Deterministic hash of a ComplianceFlag for referencing in filings.

    The hash binds a filing to the specific flag that triggered it,
    so the audit trail can verify provenance.
    """
    canonical = json.dumps(flag.to_dict(), sort_keys=True,
                           separators=(',', ':')).encode()
    return hashlib.sha3_256(canonical).hexdigest()


def regulatory_deadline_for(flag: ComplianceFlag) -> int:
    """Compute the regulatory deadline for filing based on flag severity.

    These are operationally reasonable defaults. Real regulations have
    specific deadlines:
      - SARs: 30 days from initial detection (BSA)
      - Sanctions hits: 10 days (OFAC)
      - CTRs: 15 days from transaction date

    For Phase 1 we use simplified rules. Real regulatory deadlines
    are configurable in Phase 1.5.
    """
    # All times in milliseconds
    DAY_MS = 24 * 60 * 60 * 1000

    if flag.flag_type == FLAG_SANCTIONS_HIT:
        return flag.detected_at_ms + 10 * DAY_MS
    elif flag.flag_type == FLAG_THRESHOLD_CROSSING:
        return flag.detected_at_ms + 15 * DAY_MS
    else:
        # SARs: 30 days
        return flag.detected_at_ms + 30 * DAY_MS
