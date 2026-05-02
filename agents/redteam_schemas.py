"""
agents/redteam_schemas.py — Red Team Agent data structures
================================================================

Three dataclasses + severity constants. Same structural pattern as
compliance_schemas.py.

  RedTeamConfig    — operator's spec for what RTA tests against
  AttackResult     — internal: returned by each attack function
  RedTeamFinding   — external: what RTA produces when an attack succeeds

Severities reuse compliance_schemas constants for consistency:
  SEVERITY_CRITICAL / SEVERITY_HIGH / SEVERITY_MEDIUM / SEVERITY_LOW
"""

from __future__ import annotations
import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from agents.compliance_schemas import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)


# Attack categories
CATEGORY_FILING = 'filing'
CATEGORY_MONITORING = 'monitoring'
CATEGORY_CROSS = 'cross'

VALID_CATEGORIES = (CATEGORY_FILING, CATEGORY_MONITORING, CATEGORY_CROSS)
VALID_SEVERITIES = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)


# ─── RedTeamConfig ────────────────────────────────────────────────

@dataclass(frozen=True)
class RedTeamConfig:
    """Operator's spec for what RTA tests against.

    Mirrors a production deployment: same MA permissions, same FA
    policies, same watchlist + sanctions setup. RTA uses this to
    spawn an accurate sandbox.

    Frozen: config should not change during a sweep. Use replace()
    if you need to vary something.
    """
    # Watch list addresses MA will use in the sandbox
    watch_list: tuple = field(default_factory=tuple)

    # Sanctions list addresses to seed in the sandbox
    sanctions_addresses: tuple = field(default_factory=tuple)

    # Mixer addresses to seed in the sandbox
    mixer_addresses: tuple = field(default_factory=tuple)

    # MA permissions (mirrors production MA credential)
    ma_permissions: tuple = ('read', 'communicate')

    # FA permissions (mirrors production FA credential)
    fa_permissions: tuple = ('write', 'communicate')

    # MA credential heartbeat interval (ms)
    ma_heartbeat_ms: int = 300_000

    # FA credential heartbeat interval (ms)
    fa_heartbeat_ms: int = 60_000

    # Resource scope
    resource_scope: str = 'compliance/crypto/*'

    # Operator label (for logging/findings)
    operator_label: str = 'rta-operator'

    def to_dict(self) -> dict:
        return asdict(self)

    def hash(self) -> str:
        """Deterministic SHA256 hash of the config.

        Used in RedTeamFinding to bind a finding to the exact
        sandbox configuration that produced it.
        """
        canonical = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


# ─── AttackResult ─────────────────────────────────────────────────

@dataclass
class AttackResult:
    """Returned by an attack scenario function.

    Internal — never sent to the operator directly. RTA wraps
    successful attacks into RedTeamFindings.

    succeeded: True if attack found a vulnerability (the defense
               failed to stop the attack). False if defense held.
    """
    succeeded: bool
    description: str
    proof_data: dict = field(default_factory=dict)
    error: Optional[str] = None  # set if attack itself crashed

    def __post_init__(self):
        if not isinstance(self.succeeded, bool):
            raise TypeError(f"succeeded must be bool, got {type(self.succeeded)}")
        if not self.description:
            raise ValueError("description must be non-empty")


# ─── RedTeamFinding ───────────────────────────────────────────────

@dataclass(frozen=True)
class RedTeamFinding:
    """A signed finding describing a successful attack.

    Produced by RTA only when an attack scenario succeeds (vulnerability
    found). Sealed via ConditionalProof and routed to operator.

    proof_blob: base64-encoded JSON of the attack inputs and outputs.
                Detailed enough to replay the attack in a separate
                sandbox and confirm the finding.
    """
    attack_name: str
    attack_category: str
    severity: str
    description: str
    proof_blob: str
    detected_at_ms: int
    sandbox_hash: str
    rta_identity: str  # public_key hex of the RTA that found this

    def __post_init__(self):
        if self.attack_category not in VALID_CATEGORIES:
            raise ValueError(
                f"invalid category {self.attack_category!r}; "
                f"must be one of {VALID_CATEGORIES}"
            )
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"invalid severity {self.severity!r}; "
                f"must be one of {VALID_SEVERITIES}"
            )
        if not self.attack_name:
            raise ValueError("attack_name must be non-empty")
        if not self.description:
            raise ValueError("description must be non-empty")
        if not self.proof_blob:
            raise ValueError("proof_blob must be non-empty")
        if self.detected_at_ms <= 0:
            raise ValueError("detected_at_ms must be positive")
        if not self.sandbox_hash:
            raise ValueError("sandbox_hash must be non-empty")
        if not self.rta_identity:
            raise ValueError("rta_identity must be non-empty")

    def to_condition_dict(self) -> dict:
        """Build a dict suitable for use as a ConditionalProof.condition.

        Mirrors ComplianceFlag.to_condition_dict() pattern: includes
        a 'type' key so receivers can validate the condition shape.
        """
        return {
            'type': 'redteam_finding',
            'attack_name': self.attack_name,
            'attack_category': self.attack_category,
            'severity': self.severity,
            'description': self.description,
            'proof_blob': self.proof_blob,
            'detected_at_ms': self.detected_at_ms,
            'sandbox_hash': self.sandbox_hash,
            'rta_identity': self.rta_identity,
        }

    @classmethod
    def from_condition_dict(cls, d: dict) -> 'RedTeamFinding':
        """Reconstruct from a ConditionalProof.condition dict."""
        if not isinstance(d, dict):
            raise TypeError(f"expected dict, got {type(d)}")
        if d.get('type') != 'redteam_finding':
            raise ValueError(
                f"wrong condition type: {d.get('type')!r} "
                f"(expected 'redteam_finding')"
            )
        return cls(
            attack_name=d['attack_name'],
            attack_category=d['attack_category'],
            severity=d['severity'],
            description=d['description'],
            proof_blob=d['proof_blob'],
            detected_at_ms=d['detected_at_ms'],
            sandbox_hash=d['sandbox_hash'],
            rta_identity=d['rta_identity'],
        )


# ─── Self-test ────────────────────────────────────────────────────

def _self_test() -> int:
    print("agents.redteam_schemas self-test")
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

    # 1. RedTeamConfig defaults
    def config_defaults():
        c = RedTeamConfig()
        return (c.watch_list == () and c.ma_permissions == ('read', 'communicate'))
    check("config has sensible defaults", config_defaults)

    # 2. RedTeamConfig hash is deterministic
    def config_hash_deterministic():
        c1 = RedTeamConfig(watch_list=('0xabc',))
        c2 = RedTeamConfig(watch_list=('0xabc',))
        return c1.hash() == c2.hash() and len(c1.hash()) == 64
    check("config hash is deterministic and 64 hex chars",
          config_hash_deterministic)

    # 3. Different configs produce different hashes
    def config_hash_distinguishes():
        c1 = RedTeamConfig(watch_list=('0xabc',))
        c2 = RedTeamConfig(watch_list=('0xdef',))
        return c1.hash() != c2.hash()
    check("different configs produce different hashes",
          config_hash_distinguishes)

    # 4. AttackResult requires bool succeeded
    def attack_result_bool_check():
        try:
            AttackResult(succeeded='yes', description='x')
            return False
        except TypeError:
            return True
    check("AttackResult rejects non-bool succeeded", attack_result_bool_check)

    # 5. AttackResult requires non-empty description
    def attack_result_desc_check():
        try:
            AttackResult(succeeded=True, description='')
            return False
        except ValueError:
            return True
    check("AttackResult rejects empty description", attack_result_desc_check)

    # 6. RedTeamFinding rejects invalid category
    def finding_category_check():
        try:
            RedTeamFinding(
                attack_name='test',
                attack_category='invalid',
                severity=SEVERITY_HIGH,
                description='x',
                proof_blob='y',
                detected_at_ms=int(time.time() * 1000),
                sandbox_hash='a' * 64,
                rta_identity='b' * 64,
            )
            return False
        except ValueError as e:
            return 'invalid category' in str(e)
    check("RedTeamFinding rejects invalid category", finding_category_check)

    # 7. RedTeamFinding rejects invalid severity
    def finding_severity_check():
        try:
            RedTeamFinding(
                attack_name='test',
                attack_category=CATEGORY_FILING,
                severity='ULTRA',
                description='x',
                proof_blob='y',
                detected_at_ms=int(time.time() * 1000),
                sandbox_hash='a' * 64,
                rta_identity='b' * 64,
            )
            return False
        except ValueError as e:
            return 'invalid severity' in str(e)
    check("RedTeamFinding rejects invalid severity", finding_severity_check)

    # 8. RedTeamFinding round-trips through condition dict
    def finding_round_trip():
        original = RedTeamFinding(
            attack_name='forge_ma_identity',
            attack_category=CATEGORY_FILING,
            severity=SEVERITY_HIGH,
            description='Attacker bypassed MA-binding',
            proof_blob='base64encodedstuff',
            detected_at_ms=int(time.time() * 1000),
            sandbox_hash='a' * 64,
            rta_identity='b' * 64,
        )
        d = original.to_condition_dict()
        restored = RedTeamFinding.from_condition_dict(d)
        return restored == original
    check("RedTeamFinding round-trips via condition dict", finding_round_trip)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
