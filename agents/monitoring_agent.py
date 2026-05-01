"""
agents/monitoring_agent.py — on-chain compliance monitoring
=================================================================

Phase 2 of the 3-agent compliance operation. MA scans Ethereum blocks
for transactions involving watch-listed addresses, checks them against
the OFAC sanctions list and known mixer contracts, and produces
ConditionalProofs (sealed to FA) when it finds matches.

ARCHITECTURE: scan-on-demand
  MA exposes scan_block(block_number) and scan_latest(). The caller
  decides when to invoke (cron, daemon loop, manual). No internal
  thread or async loop — keeps testing simple and gives the caller
  full control over scheduling and error handling.

RPC TRANSPORT
  Manual JSON-RPC via urllib. No web3.py dependency. Two methods used:
    - eth_blockNumber: get current latest block
    - eth_getBlockByNumber: fetch full block with transactions

  RPC URL is read from ALCHEMY_API_KEY env var (Alchemy URL constructed)
  with fallback to a free public RPC endpoint.

DETECTION LOGIC (Phase 2 v1)
  For each transaction in a scanned block:
    1. Is tx.from OR tx.to in MA's watch list? Otherwise skip.
    2. Is the OTHER party (the counterparty) on the sanctions list?
       → produce sanctions_hit flag, severity=critical
    3. Is the OTHER party a known mixer contract?
       → produce mixer_interaction flag, severity=high
  Both can fire on the same tx if both apply.

NOT INCLUDED IN v1
  - Threshold crossing detection (needs price oracles)
  - Pattern detection (structuring, peel chains, chain hopping)
  - Multi-chain support (ETH only)
  - Real-time WebSocket subscription (polling only)

OUTPUT
  scan_block returns a list of ConditionalProofs. Caller seals each
  to FA's peer_key (for production) or feeds them directly to FA's
  receive_flag (for testing). Sealing is the caller's responsibility,
  not MA's — keeps MA decoupled from sealing transport.

ACTIVITY STREAM
  Every block scan, every transaction examined, and every flag
  produced is recorded in MA's activity stream. The audit trail
  shows what MA observed and why each flag was generated.

USAGE:
    from agents.monitoring_agent import MonitoringAgent
    from agents.sanctions_list import SanctionsList
    from agents.mixers import MixerList

    sl = SanctionsList()
    sl.refresh()
    ml = MixerList()

    ma = MonitoringAgent(
        identity=ma_identity,
        credential=ma_credential,
        watch_list={'0xCustomerWallet1', '0xCustomerWallet2'},
        sanctions_list=sl,
        mixer_list=ml,
        rpc_url='https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    )

    proofs = ma.scan_latest()
    for proof in proofs:
        # send to FA
        fa.receive_flag(proof)
"""

from __future__ import annotations
import json
import os
import time
import urllib.request
import urllib.error
from typing import Set, List, Optional, Dict, Any

from acreo import (
    Identity, Credential, AcreoError, Entropy,
    ConditionalProof,
)
from acreo_activity_stream import ActivityStream

from agents.compliance_schemas import (
    ComplianceFlag, AddressInvolvement,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL,
    FLAG_SANCTIONS_HIT, FLAG_MIXER_INTERACTION,
)
from agents.sanctions_list import SanctionsList
from agents.mixers import MixerList


# Default RPC if no Alchemy key available
DEFAULT_PUBLIC_RPC = "https://eth.llamarpc.com"

# Per-call timeout in seconds
DEFAULT_RPC_TIMEOUT_S = 10

# Confidence scores for flag types — used to populate ComplianceFlag.risk_score
CONFIDENCE_SANCTIONS_HIT = 0.95
CONFIDENCE_MIXER_INTERACTION = 0.85


def resolve_rpc_url(override: Optional[str] = None) -> str:
    """Determine the RPC URL to use.

    Priority:
      1. Explicit override parameter (for tests, custom deployments)
      2. ALCHEMY_API_KEY env var (constructs Alchemy URL)
      3. Free public RPC fallback
    """
    if override:
        return override
    alchemy_key = os.environ.get('ALCHEMY_API_KEY')
    if alchemy_key:
        return f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_key}"
    return DEFAULT_PUBLIC_RPC


class RpcClient:
    """Minimal JSON-RPC client. Just the two methods MA needs."""

    def __init__(self, url: str, timeout_s: int = DEFAULT_RPC_TIMEOUT_S):
        self.url = url
        self.timeout_s = timeout_s

    def _call(self, method: str, params: list) -> Any:
        """Synchronous JSON-RPC call. Returns the 'result' field."""
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }).encode('utf-8')
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        if 'error' in data:
            raise AcreoError(f"RPC error: {data['error']}")
        return data.get('result')

    def block_number(self) -> int:
        """Get the latest block number."""
        result = self._call('eth_blockNumber', [])
        return int(result, 16)  # hex string → int

    def get_block(self, block_number: int, include_txs: bool = True) -> Dict:
        """Fetch a full block including transactions."""
        hex_num = hex(block_number)
        result = self._call('eth_getBlockByNumber', [hex_num, include_txs])
        if result is None:
            raise AcreoError(f"block {block_number} not found")
        return result


class MonitoringAgent:
    """Compliance Monitoring Agent.

    Scans Ethereum blocks for compliance-relevant transactions and
    produces ConditionalProofs sealed to FA.
    """

    def __init__(self,
                 identity: Identity,
                 credential: Credential,
                 watch_list: Set[str],
                 sanctions_list: SanctionsList,
                 mixer_list: MixerList,
                 rpc_url: Optional[str] = None,
                 rpc_client: Optional[RpcClient] = None):
        if identity.kind != 'agent':
            raise AcreoError(
                f"MonitoringAgent requires agent identity, got "
                f"kind={identity.kind!r}")
        if credential.agent_key != identity.public_key:
            raise AcreoError(
                "credential not issued to this agent's key")
        if not credential.has('read') and not credential.has('communicate'):
            raise AcreoError(
                "credential must grant 'read' or 'communicate' permission")

        self.identity = identity
        self.credential = credential
        self.watch_list = {a.lower() for a in watch_list}
        self.sanctions_list = sanctions_list
        self.mixer_list = mixer_list

        # RPC: prefer injected client (for tests) over URL
        if rpc_client is not None:
            self.rpc = rpc_client
        else:
            self.rpc = RpcClient(resolve_rpc_url(rpc_url))

        # Activity stream for MA's own behavior
        self._stream = ActivityStream(self.identity)

        # Operational state
        self._blocks_scanned: int = 0
        self._txs_examined: int = 0
        self._flags_produced: int = 0
        self._last_block_scanned: Optional[int] = None

    # ─── Watch list management ────────────────────────────────────

    def add_to_watchlist(self, address: str) -> None:
        """Add an address to the watch list."""
        addr_lower = address.lower()
        self.watch_list.add(addr_lower)
        self._stream.record_action({
            'event': 'watchlist_add',
            'address': addr_lower,
        })

    def remove_from_watchlist(self, address: str) -> None:
        """Remove an address from the watch list."""
        addr_lower = address.lower()
        self.watch_list.discard(addr_lower)
        self._stream.record_action({
            'event': 'watchlist_remove',
            'address': addr_lower,
        })

    def watchlist_size(self) -> int:
        return len(self.watch_list)

    # ─── Block fetching ───────────────────────────────────────────

    def current_block_number(self) -> int:
        """Get the current latest block number from the RPC."""
        return self.rpc.block_number()

    # ─── Scanning ─────────────────────────────────────────────────

    def scan_block(self, block_number: int,
                   valid_until_ms: Optional[int] = None) -> List[ConditionalProof]:
        """Scan a single block, returning a list of ConditionalProofs
        for any compliance hits found.

        valid_until_ms: how long the resulting proofs are valid for.
                        Defaults to 5 minutes from now.
        """
        if valid_until_ms is None:
            valid_until_ms = int(time.time() * 1000) + 5 * 60 * 1000

        # Record block scan
        self._stream.record_observation({
            'event': 'block_scan_start',
            'block_number': block_number,
        })

        try:
            block = self.rpc.get_block(block_number, include_txs=True)
        except (urllib.error.URLError, AcreoError) as e:
            self._stream.record_reasoning({
                'event': 'block_fetch_failed',
                'block_number': block_number,
                'error': f'{type(e).__name__}: {e}',
            })
            return []

        txs = block.get('transactions', [])
        proofs: List[ConditionalProof] = []

        for tx in txs:
            self._txs_examined += 1
            tx_proofs = self._scan_transaction(tx, block_number, valid_until_ms)
            proofs.extend(tx_proofs)

        self._blocks_scanned += 1
        self._last_block_scanned = block_number
        self._flags_produced += len(proofs)

        self._stream.record_state({
            'event': 'block_scan_complete',
            'block_number': block_number,
            'txs_examined': len(txs),
            'flags_produced': len(proofs),
            'cumulative_blocks': self._blocks_scanned,
            'cumulative_flags': self._flags_produced,
        })

        return proofs

    def scan_latest(self,
                    valid_until_ms: Optional[int] = None) -> List[ConditionalProof]:
        """Convenience: scan the current latest block."""
        block_num = self.current_block_number()
        return self.scan_block(block_num, valid_until_ms)

    def _scan_transaction(self, tx: Dict, block_number: int,
                          valid_until_ms: int) -> List[ConditionalProof]:
        """Scan a single transaction. Returns flags if it matches detection rules."""
        # Normalize addresses to lowercase
        tx_from = (tx.get('from') or '').lower()
        tx_to = (tx.get('to') or '').lower()
        tx_hash = tx.get('hash', '')

        # Must involve a watch-listed address (otherwise out of scope)
        watched_addresses = []
        if tx_from in self.watch_list:
            watched_addresses.append((tx_from, 'sender'))
        if tx_to in self.watch_list:
            watched_addresses.append((tx_to, 'receiver'))

        if not watched_addresses:
            return []  # not in our scope

        # The "counterparty" is the address that's NOT on our watch list.
        # If both from and to are watched, both are counterparties to each
        # other but neither is suspicious from compliance standpoint
        # (internal transfer between customer wallets).
        counterparties = []
        if tx_from not in self.watch_list:
            counterparties.append((tx_from, 'sender'))
        if tx_to not in self.watch_list:
            counterparties.append((tx_to, 'receiver'))

        proofs = []

        for counterparty_addr, counterparty_role in counterparties:
            if not counterparty_addr:
                continue

            # Check sanctions
            if self.sanctions_list.is_sanctioned(counterparty_addr):
                proof = self._produce_flag(
                    flag_type=FLAG_SANCTIONS_HIT,
                    severity=SEVERITY_CRITICAL,
                    risk_score=CONFIDENCE_SANCTIONS_HIT,
                    tx_hash=tx_hash,
                    block_number=block_number,
                    watched_addrs=watched_addresses,
                    counterparty_addr=counterparty_addr,
                    counterparty_role=counterparty_role,
                    counterparty_label='OFAC sanctioned',
                    valid_until_ms=valid_until_ms,
                )
                if proof:
                    proofs.append(proof)

            # Check mixers
            if self.mixer_list.is_mixer(counterparty_addr):
                proof = self._produce_flag(
                    flag_type=FLAG_MIXER_INTERACTION,
                    severity=SEVERITY_HIGH,
                    risk_score=CONFIDENCE_MIXER_INTERACTION,
                    tx_hash=tx_hash,
                    block_number=block_number,
                    watched_addrs=watched_addresses,
                    counterparty_addr=counterparty_addr,
                    counterparty_role=counterparty_role,
                    counterparty_label='Known mixer contract',
                    valid_until_ms=valid_until_ms,
                )
                if proof:
                    proofs.append(proof)

        return proofs

    def _produce_flag(self, flag_type: str, severity: str,
                       risk_score: float, tx_hash: str, block_number: int,
                       watched_addrs: list, counterparty_addr: str,
                       counterparty_role: str, counterparty_label: str,
                       valid_until_ms: int) -> Optional[ConditionalProof]:
        """Generate a ConditionalProof for a compliance hit."""
        # Build addresses_involved list
        addrs = [
            AddressInvolvement(
                address=counterparty_addr,
                chain='ethereum',
                role=counterparty_role,
                label=counterparty_label,
            )
        ]
        for watched_addr, watched_role in watched_addrs:
            addrs.append(AddressInvolvement(
                address=watched_addr,
                chain='ethereum',
                role=f'watched_{watched_role}',
                label='customer watchlist',
            ))

        # Record the reasoning (what MA decided and why)
        rationale_frame = self._stream.record_reasoning({
            'event': 'flag_decision',
            'flag_type': flag_type,
            'severity': severity,
            'tx_hash': tx_hash,
            'block_number': block_number,
            'counterparty': counterparty_addr,
            'reason': counterparty_label,
        })

        # Build the ComplianceFlag
        flag = ComplianceFlag(
            flag_type=flag_type,
            severity=severity,
            transaction_hashes=[tx_hash] if tx_hash else [],
            addresses_involved=addrs,
            risk_score=risk_score,
            rationale_hash=rationale_frame.frame_id,
            evidence_pointer=tx_hash or '',
            detected_at_ms=int(time.time() * 1000),
            chain='ethereum',
        )

        # Build the ConditionalProof via Identity.propose
        try:
            proof = self.identity.propose(
                cred=self.credential,
                action='communicate',
                resource=f'compliance/crypto/ethereum',
                condition=flag.to_condition_dict(),
                valid_until_ms=valid_until_ms,
            )
        except (AcreoError, ValueError) as e:
            self._stream.record_reasoning({
                'event': 'flag_proposal_failed',
                'tx_hash': tx_hash,
                'error': f'{type(e).__name__}: {e}',
            })
            return None

        # Record action: flag produced
        self._stream.record_action({
            'event': 'flag_produced',
            'flag_type': flag_type,
            'severity': severity,
            'proof_id': proof.proof_id,
            'tx_hash': tx_hash,
        })

        return proof

    # ─── Stats ────────────────────────────────────────────────────

    def stats(self) -> Dict:
        return {
            'blocks_scanned': self._blocks_scanned,
            'txs_examined': self._txs_examined,
            'flags_produced': self._flags_produced,
            'last_block_scanned': self._last_block_scanned,
            'watchlist_size': len(self.watch_list),
        }

    @property
    def activity_stream(self) -> ActivityStream:
        return self._stream


# ─── Self-test (uses mock RPC, no network) ───────────────────────

class _MockRpcClient:
    """Mock RPC for offline testing."""
    def __init__(self):
        self._latest_block = 100
        self._blocks: Dict[int, Dict] = {}

    def set_latest_block(self, n: int) -> None:
        self._latest_block = n

    def add_block(self, n: int, transactions: list) -> None:
        self._blocks[n] = {
            'number': hex(n),
            'transactions': transactions,
        }

    def block_number(self) -> int:
        return self._latest_block

    def get_block(self, block_number: int, include_txs: bool = True) -> Dict:
        if block_number not in self._blocks:
            raise AcreoError(f"block {block_number} not found")
        return self._blocks[block_number]


def _self_test() -> int:
    print("agents.monitoring_agent self-test")
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

    # Setup helpers
    from acreo import Acreo

    def make_ma(watch_list=None, sanctions_addrs=None, mixer_addrs=None,
                rpc=None):
        acreo = Acreo()
        op = acreo.create_user('jimmy')
        ma_id = acreo.create_agent('monitoring-agent')
        ma_cred = acreo.delegate(
            op, ma_id,
            permissions=['read', 'communicate'],
            scope=['compliance/crypto/*'],
            heartbeat_interval_ms=300000,
        )

        # Build sanctions list
        sl = SanctionsList()
        if sanctions_addrs:
            sl._addresses = {a.lower() for a in sanctions_addrs}
            sl._last_fetch_ms = int(time.time() * 1000)

        # Build mixer list
        ml = MixerList(additional_addresses=mixer_addrs or [])

        ma = MonitoringAgent(
            identity=ma_id,
            credential=ma_cred,
            watch_list=watch_list or set(),
            sanctions_list=sl,
            mixer_list=ml,
            rpc_client=rpc or _MockRpcClient(),
        )
        return acreo, op, ma_id, ma_cred, ma

    # 1. Constructor rejects user identity
    def constructor_user_rejected():
        acreo = Acreo()
        op = acreo.create_user('jimmy')
        sl = SanctionsList()
        ml = MixerList()
        try:
            MonitoringAgent(
                identity=op, credential=None, watch_list=set(),
                sanctions_list=sl, mixer_list=ml,
                rpc_client=_MockRpcClient(),
            )
            return False
        except AcreoError:
            return True
    check("constructor rejects user identity", constructor_user_rejected)

    # 2. Watchlist add and remove
    def watchlist_management():
        _, _, _, _, ma = make_ma(watch_list={'0xaaa'})
        ma.add_to_watchlist('0xBBB')  # uppercase
        ma.remove_from_watchlist('0xaaa')
        return (ma.watchlist_size() == 1
                and '0xbbb' in ma.watch_list  # stored lowercase
                and '0xaaa' not in ma.watch_list)
    check("watchlist add/remove with case normalization", watchlist_management)

    # 3. Empty block scan returns no flags
    def empty_block_no_flags():
        rpc = _MockRpcClient()
        rpc.add_block(100, [])
        _, _, _, _, ma = make_ma(watch_list={'0xaaa'}, rpc=rpc)
        proofs = ma.scan_block(100)
        return len(proofs) == 0
    check("empty block produces no flags", empty_block_no_flags)

    # 4. Tx with no watched addresses produces no flag
    def out_of_scope_tx_skipped():
        rpc = _MockRpcClient()
        rpc.add_block(100, [{
            'hash': '0xtx1',
            'from': '0xrandom1',
            'to': '0xrandom2',
        }])
        _, _, _, _, ma = make_ma(
            watch_list={'0xaaa'},  # neither party
            sanctions_addrs={'0xrandom2'},  # would hit if in scope
            rpc=rpc,
        )
        proofs = ma.scan_block(100)
        return len(proofs) == 0
    check("out-of-scope tx (no watched address) skipped", out_of_scope_tx_skipped)

    # 5. Sanctions hit produces flag
    def sanctions_hit():
        rpc = _MockRpcClient()
        rpc.add_block(100, [{
            'hash': '0xtx1',
            'from': '0xcustomer',
            'to': '0xsanctioned',
        }])
        _, _, _, _, ma = make_ma(
            watch_list={'0xcustomer'},
            sanctions_addrs={'0xsanctioned'},
            rpc=rpc,
        )
        proofs = ma.scan_block(100)
        if len(proofs) != 1:
            return False
        # Verify the proof contains the right flag
        from agents.compliance_schemas import ComplianceFlag
        flag = ComplianceFlag.from_condition_dict(proofs[0].condition)
        return (flag.flag_type == FLAG_SANCTIONS_HIT
                and flag.severity == SEVERITY_CRITICAL
                and '0xtx1' in flag.transaction_hashes)
    check("sanctions hit produces critical flag", sanctions_hit)

    # 6. Mixer interaction produces flag
    def mixer_hit():
        rpc = _MockRpcClient()
        rpc.add_block(100, [{
            'hash': '0xtx1',
            'from': '0xcustomer',
            'to': '0xmixerabc',
        }])
        _, _, _, _, ma = make_ma(
            watch_list={'0xcustomer'},
            mixer_addrs={'0xmixerabc'},
            rpc=rpc,
        )
        proofs = ma.scan_block(100)
        if len(proofs) != 1:
            return False
        from agents.compliance_schemas import ComplianceFlag
        flag = ComplianceFlag.from_condition_dict(proofs[0].condition)
        return (flag.flag_type == FLAG_MIXER_INTERACTION
                and flag.severity == SEVERITY_HIGH)
    check("mixer interaction produces high flag", mixer_hit)

    # 7. Both sanctions + mixer on same tx → 2 flags
    def both_flags():
        rpc = _MockRpcClient()
        rpc.add_block(100, [{
            'hash': '0xtx1',
            'from': '0xcustomer',
            'to': '0xbadactor',
        }])
        _, _, _, _, ma = make_ma(
            watch_list={'0xcustomer'},
            sanctions_addrs={'0xbadactor'},
            mixer_addrs={'0xbadactor'},
            rpc=rpc,
        )
        proofs = ma.scan_block(100)
        if len(proofs) != 2:
            return False
        from agents.compliance_schemas import ComplianceFlag
        types = {ComplianceFlag.from_condition_dict(p.condition).flag_type for p in proofs}
        return types == {FLAG_SANCTIONS_HIT, FLAG_MIXER_INTERACTION}
    check("sanctions + mixer on same tx produces both flags", both_flags)

    # 8. Internal transfer (both addresses watched) produces no flag
    def internal_transfer_skipped():
        rpc = _MockRpcClient()
        rpc.add_block(100, [{
            'hash': '0xtx1',
            'from': '0xcustomer1',
            'to': '0xcustomer2',
        }])
        _, _, _, _, ma = make_ma(
            watch_list={'0xcustomer1', '0xcustomer2'},
            sanctions_addrs={'0xcustomer1'},  # would falsely flag if naive
            rpc=rpc,
        )
        proofs = ma.scan_block(100)
        # Both addresses are in watch_list, so neither is a "counterparty"
        # → no flags
        return len(proofs) == 0
    check("internal transfer between watched addrs not flagged",
          internal_transfer_skipped)

    # 9. Watched as sender vs receiver both detected
    def watched_as_sender_or_receiver():
        rpc = _MockRpcClient()
        rpc.add_block(100, [
            {'hash': '0xtx1', 'from': '0xcustomer', 'to': '0xsanctioned'},
            {'hash': '0xtx2', 'from': '0xsanctioned', 'to': '0xcustomer'},
        ])
        _, _, _, _, ma = make_ma(
            watch_list={'0xcustomer'},
            sanctions_addrs={'0xsanctioned'},
            rpc=rpc,
        )
        proofs = ma.scan_block(100)
        return len(proofs) == 2
    check("watched-as-sender and watched-as-receiver both detected",
          watched_as_sender_or_receiver)

    # 10. scan_latest uses current block
    def scan_latest_uses_current():
        rpc = _MockRpcClient()
        rpc.set_latest_block(500)
        rpc.add_block(500, [{
            'hash': '0xtx1',
            'from': '0xcustomer',
            'to': '0xsanctioned',
        }])
        _, _, _, _, ma = make_ma(
            watch_list={'0xcustomer'},
            sanctions_addrs={'0xsanctioned'},
            rpc=rpc,
        )
        proofs = ma.scan_latest()
        return len(proofs) == 1 and ma.stats()['last_block_scanned'] == 500
    check("scan_latest uses current block number", scan_latest_uses_current)

    # 11. Activity stream records each step
    def activity_stream_complete():
        rpc = _MockRpcClient()
        rpc.add_block(100, [{
            'hash': '0xtx1',
            'from': '0xcustomer',
            'to': '0xsanctioned',
        }])
        _, _, _, _, ma = make_ma(
            watch_list={'0xcustomer'},
            sanctions_addrs={'0xsanctioned'},
            rpc=rpc,
        )
        ma.scan_block(100)
        # Should have: block_scan_start (obs) + flag_decision (reasoning)
        # + flag_produced (action) + block_scan_complete (state)
        events = [f.payload.get('event') for f in ma._stream.frames]
        return ('block_scan_start' in events
                and 'flag_decision' in events
                and 'flag_produced' in events
                and 'block_scan_complete' in events)
    check("activity stream records all scan events", activity_stream_complete)

    # 12. End-to-end: MA produces flag → FA accepts
    def end_to_end_with_fa():
        from agents.filing_agent import FilingAgent
        import tempfile

        rpc = _MockRpcClient()
        rpc.add_block(100, [{
            'hash': '0xtx_realistic',
            'from': '0xcustomer',
            'to': '0xsanctioned',
        }])
        acreo, op, ma_id, ma_cred, ma = make_ma(
            watch_list={'0xcustomer'},
            sanctions_addrs={'0xsanctioned'},
            rpc=rpc,
        )

        # Set up FA on the same Acreo instance
        fa_id = acreo.create_agent('filing-agent')
        fa_cred = acreo.delegate(
            op, fa_id,
            permissions=['write', 'communicate'],
            scope=['compliance/crypto/*'],
            heartbeat_interval_ms=60000,
        )
        d = tempfile.mkdtemp(prefix='ma_ft_test_')
        try:
            fa = FilingAgent(
                identity=fa_id,
                credential=fa_cred,
                operator=op,
                verifier=acreo._verifier,
                filings_dir=d,
                trusted_ma_keys={ma_id.public_key},
            )

            # MA scans → produces proof → FA receives
            proofs = ma.scan_block(100)
            if len(proofs) != 1:
                return False

            result = fa.receive_flag(proofs[0])
            return (result.accepted
                    and result.filing_id is not None)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    check("end-to-end: MA flag → FA produces SAR", end_to_end_with_fa)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
