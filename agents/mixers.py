"""
agents/mixers.py — well-known crypto mixer contract addresses
=================================================================

For Phase 2 v1, a hardcoded list of well-known mixer contracts.
Detection of "transaction interacted with a mixer" is one of the
flag types MA produces.

HONEST LIMITATIONS:
  - This is a hardcoded list of ~10 well-known mixer addresses
  - Production AML deployments use commercial mixer/privacy-pool
    registries (Chainalysis, TRM Labs, Elliptic) which contain
    thousands of addresses and update continuously
  - Many mixers operate via short-lived contracts that rotate frequently;
    a static list catches only the long-tail residual interactions
  - This list is sufficient for Phase 2 v1 demonstration but is
    explicitly NOT production-grade mixer detection

The well-known set focuses on:
  - Tornado Cash router/proxy contracts (sanctioned 2022; addresses
    overlap with OFAC list but kept here for completeness)
  - Wasabi Wallet coordinator contracts
  - Privacy-focused token contracts that sometimes serve as de facto mixers

For real production use, customers should layer commercial mixer
registries on top of this baseline.

USAGE:
    from agents.mixers import MixerList

    ml = MixerList()
    if ml.is_mixer('0x...'):
        # flag mixer interaction

The interface mirrors SanctionsList for symmetry — MA uses both
in parallel and reports either type of hit.
"""

from __future__ import annotations
from typing import Set, Iterable


# Well-known mixer contracts. All lowercase for normalization.
# Comments indicate the source/category for each.
_WELL_KNOWN_MIXERS = (
    # Tornado Cash router contracts (multi-denomination ETH router)
    # These overlap with OFAC list but are documented mixer infrastructure
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # 0.1 ETH
    "0xa160cdab225685da1d56aa342ad8841c3b53f291",  # 1 ETH (mainnet)
    "0xd96f2b1c14db8458374d9aca76e26c3d18364307",  # 10 ETH
    "0x4736dcf1b7a3d580672ccce6213ca176d69c8b91",  # 100 ETH (delegated to deployer)

    # Tornado Cash mixer deployer
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",  # original deployer

    # Tornado Cash relayer registry (older deployments)
    "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # router proxy
    "0xdd4c48c0b24039969fc16d1cdf626eab821d3384",  # 100 ETH (alt)

    # Wasabi Wallet coordinator (older mainnet coordinator addresses
    # found on-chain, public)
    # Wasabi is primarily a desktop coinjoin client; on-chain
    # signatures are limited but coordinator key fingerprints
    # are documented. Skipping ETH-specific entries since Wasabi is
    # primarily Bitcoin.

    # Cyclone Protocol (Tornado Cash fork on multiple chains)
    "0xddbf07bb336bb22a18a9b6e6dec924b14a2cf3da",
)


class MixerList:
    """Hardcoded set of well-known mixer contract addresses.

    Phase 2 v1 baseline. Production deployments should layer commercial
    mixer registries on top via the extend() method or by passing
    additional addresses to __init__.
    """

    def __init__(self, additional_addresses: Iterable[str] = ()):
        self._addresses: Set[str] = {a.lower() for a in _WELL_KNOWN_MIXERS}
        self._addresses.update(a.lower() for a in additional_addresses)

    def is_mixer(self, address: str) -> bool:
        """O(1) lookup. Address is case-insensitive."""
        return address.lower() in self._addresses

    def count(self) -> int:
        return len(self._addresses)

    def extend(self, addresses: Iterable[str]) -> None:
        """Add additional mixer addresses (e.g. from a commercial feed)."""
        self._addresses.update(a.lower() for a in addresses)

    def addresses(self) -> Set[str]:
        """Return a copy of the current address set (read-only intent)."""
        return set(self._addresses)


# ─── Self-test ────────────────────────────────────────────────────

def _self_test() -> int:
    print("agents.mixers self-test")
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

    # 1. Default list is non-empty
    check("default list has entries",
          lambda: MixerList().count() > 0)

    # 2. Known Tornado Cash address detected
    check("Tornado Cash 0.1 ETH router detected",
          lambda: MixerList().is_mixer('0x910cbd523d972eb0a6f4cae4618ad62622b39dbf'))

    # 3. Random address not detected
    check("random address not detected",
          lambda: not MixerList().is_mixer('0x1234567890123456789012345678901234567890'))

    # 4. Case-insensitive lookup
    check("case-insensitive lookup",
          lambda: MixerList().is_mixer('0X910CBD523D972EB0A6F4CAE4618AD62622B39DBF'))

    # 5. Extend with additional addresses
    def extend_works():
        ml = MixerList()
        original_count = ml.count()
        ml.extend(['0xabc', '0xdef'])
        return (ml.count() == original_count + 2
                and ml.is_mixer('0xabc')
                and ml.is_mixer('0xDEF'))  # case insensitive
    check("extend adds new addresses", extend_works)

    # 6. Constructor accepts additional addresses
    def constructor_extends():
        ml = MixerList(additional_addresses=['0xnewmixer'])
        return ml.is_mixer('0xnewmixer')
    check("constructor accepts additional addresses", constructor_extends)

    # 7. addresses() returns a copy (mutating the copy doesn't affect the list)
    def addresses_returns_copy():
        ml = MixerList()
        copy = ml.addresses()
        copy.add('0xshouldnotaffect')
        return not ml.is_mixer('0xshouldnotaffect')
    check("addresses() returns copy, not reference", addresses_returns_copy)

    # 8. Empty extend is safe
    def empty_extend():
        ml = MixerList()
        before = ml.count()
        ml.extend([])
        return ml.count() == before
    check("empty extend is no-op", empty_extend)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
