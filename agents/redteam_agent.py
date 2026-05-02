"""
agents/redteam_agent.py — Red Team Agent + Sandbox
=========================================================

Phase 3 of the 3-agent compliance operation. RTA continuously
attempts attacks against MA + FA in sandboxed instances and
produces RedTeamFindings when attacks succeed.

This file contains:
  - RedTeamSandbox: context manager that spawns/teardowns a fresh
    MA + FA pair per attack
  - RedTeamAgent: identity-bearing agent that orchestrates attacks
    (built incrementally — sandbox first, then RTA core, then attack
    library integration)

Sandbox design rationale:
  Each attack runs in a fresh Acreo() instance with a freshly-created
  MA and FA. This ensures attacks don't pollute each other's state
  (e.g. one attack's filing landing in the next attack's dedup set).

  ~50ms per spawn. Acceptable cost for clean isolation.
"""

from __future__ import annotations
import tempfile
import shutil
from pathlib import Path
from typing import Optional

from acreo import Acreo, Identity, Credential, AcreoError
from acreo_activity_stream import ActivityStream

from agents.compliance_schemas import (
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
)
from agents.filing_agent import FilingAgent
from agents.monitoring_agent import MonitoringAgent
from agents.sanctions_list import SanctionsList
from agents.mixers import MixerList
from agents.redteam_schemas import (
    RedTeamConfig, RedTeamFinding, AttackResult,
    CATEGORY_FILING, CATEGORY_MONITORING, CATEGORY_CROSS,
)


# ─── RedTeamSandbox ───────────────────────────────────────────────

class RedTeamSandbox:
    """Context manager: spawn a fresh Acreo + MA + FA per attack.

    Usage:
        with RedTeamSandbox(config) as sandbox:
            ma = sandbox.get_ma()
            fa = sandbox.get_fa()
            acreo = sandbox.get_acreo()
            # ... run attack ...
        # auto-teardown: temp dir deleted, instance dropped
    """

    def __init__(self, config: RedTeamConfig):
        self.config = config
        self._acreo: Optional[Acreo] = None
        self._operator: Optional[Identity] = None
        self._ma_identity: Optional[Identity] = None
        self._ma_credential: Optional[Credential] = None
        self._fa_identity: Optional[Identity] = None
        self._fa_credential: Optional[Credential] = None
        self._ma: Optional[MonitoringAgent] = None
        self._fa: Optional[FilingAgent] = None
        self._tempdir: Optional[Path] = None
        self._spawned: bool = False

    def __enter__(self) -> 'RedTeamSandbox':
        self.spawn()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.teardown()
        return False  # don't suppress exceptions

    def spawn(self) -> None:
        """Spin up a fresh Acreo instance with MA + FA per config."""
        if self._spawned:
            raise RuntimeError("sandbox already spawned")

        # Fresh Acreo instance (per-sandbox cryptographic state)
        self._acreo = Acreo()

        # Operator (the human delegating to MA + FA)
        self._operator = self._acreo.create_user(self.config.operator_label)

        # MA: identity + credential
        self._ma_identity = self._acreo.create_agent('rta-sandbox-ma')
        self._ma_credential = self._acreo.delegate(
            self._operator,
            self._ma_identity,
            permissions=list(self.config.ma_permissions),
            scope=[self.config.resource_scope],
            heartbeat_interval_ms=self.config.ma_heartbeat_ms,
        )

        # FA: identity + credential
        self._fa_identity = self._acreo.create_agent('rta-sandbox-fa')
        self._fa_credential = self._acreo.delegate(
            self._operator,
            self._fa_identity,
            permissions=list(self.config.fa_permissions),
            scope=[self.config.resource_scope],
            heartbeat_interval_ms=self.config.fa_heartbeat_ms,
        )

        # Sanctions list (in-memory, seeded from config)
        sl = SanctionsList()
        sl._addresses = {a.lower() for a in self.config.sanctions_addresses}
        # Set fetch timestamp so list isn't reported as stale
        import time
        sl._last_fetch_ms = int(time.time() * 1000)

        # Mixer list (with config-supplied additional addresses)
        ml = MixerList(additional_addresses=list(self.config.mixer_addresses))

        # MA: with mock RPC by default (caller can replace)
        from agents.monitoring_agent import _MockRpcClient
        self._ma = MonitoringAgent(
            identity=self._ma_identity,
            credential=self._ma_credential,
            watch_list=set(self.config.watch_list),
            sanctions_list=sl,
            mixer_list=ml,
            rpc_client=_MockRpcClient(),
        )

        # FA: temp dir for filings + trusted_ma_keys binding
        self._tempdir = Path(tempfile.mkdtemp(prefix='rta_sandbox_'))
        self._fa = FilingAgent(
            identity=self._fa_identity,
            credential=self._fa_credential,
            operator=self._operator,
            verifier=self._acreo._verifier,
            filings_dir=str(self._tempdir),
            trusted_ma_keys={self._ma_identity.public_key},
        )

        self._spawned = True

    def teardown(self) -> None:
        """Clean up sandbox state."""
        if not self._spawned:
            return

        if self._tempdir is not None and self._tempdir.exists():
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None

        # Drop references so GC can clean up
        self._acreo = None
        self._operator = None
        self._ma_identity = None
        self._ma_credential = None
        self._fa_identity = None
        self._fa_credential = None
        self._ma = None
        self._fa = None
        self._spawned = False

    # ─── Accessors ────────────────────────────────────────────────

    def _check_spawned(self) -> None:
        if not self._spawned:
            raise RuntimeError("sandbox not spawned (call spawn() or use as context manager)")

    def get_acreo(self) -> Acreo:
        self._check_spawned()
        return self._acreo

    def get_operator(self) -> Identity:
        self._check_spawned()
        return self._operator

    def get_ma(self) -> MonitoringAgent:
        self._check_spawned()
        return self._ma

    def get_fa(self) -> FilingAgent:
        self._check_spawned()
        return self._fa

    def get_ma_identity(self) -> Identity:
        self._check_spawned()
        return self._ma_identity

    def get_ma_credential(self) -> Credential:
        self._check_spawned()
        return self._ma_credential

    def get_fa_identity(self) -> Identity:
        self._check_spawned()
        return self._fa_identity

    def get_fa_credential(self) -> Credential:
        self._check_spawned()
        return self._fa_credential


# ─── RedTeamAgent ─────────────────────────────────────────────────

class RedTeamAgent:
    """Adversarial validation agent. Orchestrates attacks against
    sandboxed MA + FA instances and produces RedTeamFindings on
    successful attacks.

    Step 3 scope: skeleton only. Constructor, identity validation,
    activity stream, stats. Orchestration methods (run_attack,
    run_random_attack, run_all_attacks) come after the attack
    library is built (Step 6).
    """

    def __init__(self,
                 identity: Identity,
                 credential: Credential,
                 operator: Identity,
                 config: RedTeamConfig,
                 attack_library: Optional[dict] = None):
        if identity.kind != 'agent':
            raise AcreoError(
                f"RedTeamAgent requires agent identity, got "
                f"kind={identity.kind!r}")
        if credential.agent_key != identity.public_key:
            raise AcreoError(
                "credential not issued to this agent's key")
        if not credential.has('communicate'):
            raise AcreoError(
                "credential must grant 'communicate' permission "
                "(needed to seal findings to operator)")
        if operator.kind != 'user':
            raise AcreoError(
                f"operator must be a user identity, got "
                f"kind={operator.kind!r}")

        self.identity = identity
        self.credential = credential
        self.operator = operator
        self.config = config
        self.attack_library = attack_library or {}

        # Activity stream for RTA's own behavior
        self._stream = ActivityStream(self.identity)

        # Operational state
        self._attacks_run: int = 0
        self._findings_produced: int = 0
        self._defenses_held: int = 0
        self._attacks_errored: int = 0
        self._findings: list = []  # list of RedTeamFinding produced

    def stats(self) -> dict:
        return {
            'attacks_run': self._attacks_run,
            'findings_produced': self._findings_produced,
            'defenses_held': self._defenses_held,
            'attacks_errored': self._attacks_errored,
            'attack_library_size': len(self.attack_library),
        }

    @property
    def activity_stream(self) -> ActivityStream:
        return self._stream

    def get_findings(self) -> list:
        """Return a copy of all findings produced this session."""
        return list(self._findings)


# ─── Self-test ────────────────────────────────────────────────────

def _self_test() -> int:
    print("agents.redteam_agent self-test (Step 3: sandbox + RTA skeleton)")
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

    # 1. Sandbox spawns and tears down cleanly
    def sandbox_lifecycle():
        config = RedTeamConfig(
            watch_list=('0xcustomer',),
            sanctions_addresses=('0xsanctioned',),
        )
        with RedTeamSandbox(config) as sb:
            assert sb.get_ma() is not None
            assert sb.get_fa() is not None
        # After exit, accessors should fail
        try:
            sb.get_ma()
            return False
        except RuntimeError:
            return True
    check("sandbox spawns and tears down via context manager",
          sandbox_lifecycle)

    # 2. Sandbox MA and FA can communicate end-to-end
    def sandbox_ma_to_fa():
        from agents.monitoring_agent import _MockRpcClient
        config = RedTeamConfig(
            watch_list=('0xcustomer',),
            sanctions_addresses=('0xsanctioned',),
        )
        with RedTeamSandbox(config) as sb:
            ma = sb.get_ma()
            fa = sb.get_fa()
            # Set up the mock RPC with a block containing a sanctions hit
            rpc = ma.rpc
            rpc.add_block(100, [{
                'hash': '0xtx_test',
                'from': '0xcustomer',
                'to': '0xsanctioned',
            }])
            proofs = ma.scan_block(100)
            if len(proofs) != 1:
                return False
            result = fa.receive_flag(proofs[0])
            return result.accepted and result.filing_id is not None
    check("sandbox MA → FA pipeline works end-to-end", sandbox_ma_to_fa)

    # 3. Sandbox enforces FA's trusted_ma_keys (rejects external MA)
    def sandbox_rejects_external_ma():
        config = RedTeamConfig(
            watch_list=('0xcustomer',),
            sanctions_addresses=('0xsanctioned',),
        )
        with RedTeamSandbox(config) as sb:
            acreo = sb.get_acreo()
            op = sb.get_operator()
            fa = sb.get_fa()

            # Create an OUTSIDE MA (not registered with FA)
            outsider = acreo.create_agent('outsider')
            outsider_cred = acreo.delegate(
                op, outsider,
                permissions=['communicate'],
                scope=['compliance/crypto/*'],
                heartbeat_interval_ms=300_000,
            )

            # Construct a flag from the outsider
            from agents.compliance_schemas import (
                ComplianceFlag, AddressInvolvement,
                FLAG_SANCTIONS_HIT,
            )
            import time
            flag = ComplianceFlag(
                flag_type=FLAG_SANCTIONS_HIT,
                severity=SEVERITY_CRITICAL,
                transaction_hashes=['0xtx'],
                addresses_involved=[AddressInvolvement(
                    address='0xsanctioned', chain='ethereum',
                    role='receiver', label='OFAC',
                )],
                risk_score=0.95,
                rationale_hash='0' * 64,
                evidence_pointer='0xtx',
                detected_at_ms=int(time.time() * 1000),
                chain='ethereum',
            )
            proof = outsider.propose(
                cred=outsider_cred,
                action='communicate',
                resource='compliance/crypto/ethereum',
                condition=flag.to_condition_dict(),
                valid_until_ms=int(time.time() * 1000) + 60_000,
            )
            result = fa.receive_flag(proof)
            return (not result.accepted
                    and result.rejection_reason == 'unregistered_ma')
    check("sandbox FA rejects flags from external MAs",
          sandbox_rejects_external_ma)

    # 4. Cannot accidentally double-spawn
    def sandbox_no_double_spawn():
        config = RedTeamConfig()
        sb = RedTeamSandbox(config)
        sb.spawn()
        try:
            sb.spawn()
            sb.teardown()
            return False
        except RuntimeError:
            sb.teardown()
            return True
    check("sandbox prevents double spawn", sandbox_no_double_spawn)

    # 5. Accessors fail before spawn
    def sandbox_no_use_before_spawn():
        config = RedTeamConfig()
        sb = RedTeamSandbox(config)
        try:
            sb.get_ma()
            return False
        except RuntimeError:
            return True
    check("sandbox accessors fail before spawn",
          sandbox_no_use_before_spawn)

    # 6. Manual spawn + teardown (without context manager)
    def sandbox_manual_lifecycle():
        config = RedTeamConfig(watch_list=('0xtest',))
        sb = RedTeamSandbox(config)
        sb.spawn()
        try:
            ma = sb.get_ma()
            assert ma is not None
        finally:
            sb.teardown()
        # After teardown, accessors fail
        try:
            sb.get_ma()
            return False
        except RuntimeError:
            return True
    check("sandbox supports manual spawn/teardown",
          sandbox_manual_lifecycle)

    # 7. Teardown is idempotent (safe to call twice)
    def sandbox_teardown_idempotent():
        config = RedTeamConfig()
        sb = RedTeamSandbox(config)
        sb.spawn()
        sb.teardown()
        # Calling teardown again should not crash
        sb.teardown()
        return True
    check("sandbox teardown is idempotent", sandbox_teardown_idempotent)

    # 8. Each sandbox has independent MA keys
    def sandbox_independent_keys():
        config = RedTeamConfig()
        with RedTeamSandbox(config) as sb1:
            with RedTeamSandbox(config) as sb2:
                key1 = sb1.get_ma_identity().public_key
                key2 = sb2.get_ma_identity().public_key
                return key1 != key2
    check("each sandbox produces independent MA keys",
          sandbox_independent_keys)

    # ─── RedTeamAgent skeleton tests ──────────────────────────────

    def make_rta(config=None):
        """Helper: create a fresh RTA with operator + credential."""
        if config is None:
            config = RedTeamConfig()
        acreo = Acreo()
        op = acreo.create_user('jimmy')
        rta_id = acreo.create_agent('red-team-agent')
        rta_cred = acreo.delegate(
            op, rta_id,
            permissions=['communicate'],
            scope=['compliance/redteam/*'],
            heartbeat_interval_ms=300_000,
        )
        rta = RedTeamAgent(
            identity=rta_id,
            credential=rta_cred,
            operator=op,
            config=config,
        )
        return acreo, op, rta_id, rta_cred, rta

    # 9. Constructor rejects user identity
    def rta_rejects_user_identity():
        acreo = Acreo()
        op = acreo.create_user('jimmy')
        try:
            RedTeamAgent(
                identity=op,
                credential=None,  # won't get this far
                operator=op,
                config=RedTeamConfig(),
            )
            return False
        except AcreoError as e:
            return 'agent identity' in str(e)
    check("RTA constructor rejects user identity",
          rta_rejects_user_identity)

    # 10. Constructor rejects mismatched credential
    def rta_rejects_mismatched_cred():
        acreo = Acreo()
        op = acreo.create_user('jimmy')
        rta_id = acreo.create_agent('rta')
        other_id = acreo.create_agent('other')
        # Credential issued to OTHER agent
        wrong_cred = acreo.delegate(
            op, other_id,
            permissions=['communicate'],
            scope=['compliance/*'],
            heartbeat_interval_ms=300_000,
        )
        try:
            RedTeamAgent(
                identity=rta_id,  # but credential is for other_id
                credential=wrong_cred,
                operator=op,
                config=RedTeamConfig(),
            )
            return False
        except AcreoError as e:
            return 'not issued' in str(e)
    check("RTA constructor rejects mismatched credential",
          rta_rejects_mismatched_cred)

    # 11. Constructor requires communicate permission
    def rta_requires_communicate():
        acreo = Acreo()
        op = acreo.create_user('jimmy')
        rta_id = acreo.create_agent('rta')
        # Credential without 'communicate'
        bad_cred = acreo.delegate(
            op, rta_id,
            permissions=['read'],  # missing communicate
            scope=['compliance/*'],
            heartbeat_interval_ms=300_000,
        )
        try:
            RedTeamAgent(
                identity=rta_id,
                credential=bad_cred,
                operator=op,
                config=RedTeamConfig(),
            )
            return False
        except AcreoError as e:
            return 'communicate' in str(e)
    check("RTA constructor requires communicate permission",
          rta_requires_communicate)

    # 12. RTA has fresh stats and activity stream
    def rta_initial_state():
        _, _, _, _, rta = make_rta()
        stats = rta.stats()
        return (stats['attacks_run'] == 0
                and stats['findings_produced'] == 0
                and stats['defenses_held'] == 0
                and stats['attacks_errored'] == 0
                and stats['attack_library_size'] == 0
                and rta.activity_stream is not None
                and rta.get_findings() == [])
    check("RTA initializes with clean stats", rta_initial_state)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
