"""
agents/sanctions_list.py — OFAC sanctioned crypto address ingestion
=====================================================================

Downloads and caches the OFAC sanctions list of crypto addresses from
the well-maintained 0xB10C GitHub repo. That repo parses Treasury's
XML SDN list and produces a clean JSON of addresses by chain.

Source URL:
  https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt

(Plus other chains: BTC, BCH, ETC, LTC, USDT_TRX, XLM, ZEC, USDT_ETH)

For Phase 2 v1, we only fetch ETH. Multi-chain expansion in Phase 2.5.

USAGE:
    from agents.sanctions_list import SanctionsList

    sl = SanctionsList()
    sl.refresh()  # downloads if cache is stale

    if sl.is_sanctioned('0xabc...'):
        # take action

CACHE BEHAVIOR:
  - Default cache file: ./sanctions_cache_eth.txt (next to the running script)
  - Default TTL: 6 hours (configurable)
  - Cache stores both the raw address list and a fetch timestamp

OFFLINE MODE:
  If network is unavailable on first refresh and there's no cache,
  SanctionsList.is_sanctioned returns False for everything (fail-open
  for development) but logs a warning. In production, the operator
  must ensure the cache is populated before running MA — pre-fetch
  via SanctionsList().refresh() in deployment scripts.

NORMALIZATION:
  All addresses lowercased on storage and lookup. Ethereum addresses
  are case-insensitive in practice (EIP-55 checksumming is purely
  display).
"""

from __future__ import annotations
import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Set


# Authoritative source. The repo updates whenever Treasury updates SDN.
DEFAULT_OFAC_ETH_URL = (
    "https://raw.githubusercontent.com/0xB10C/"
    "ofac-sanctioned-digital-currency-addresses/lists/"
    "sanctioned_addresses_ETH.txt"
)

# Default cache file lives next to wherever Python is being run from
DEFAULT_CACHE_PATH = Path("./sanctions_cache_eth.txt")

# Refresh after this many milliseconds
DEFAULT_TTL_MS = 6 * 60 * 60 * 1000  # 6 hours

# Network timeout for download
DOWNLOAD_TIMEOUT_S = 10


class SanctionsList:
    """OFAC sanctioned ETH address list with local caching.

    Thread-safe for read after refresh. refresh() should be called
    from a single thread (typically MA's startup or its periodic
    refresh task).
    """

    def __init__(self,
                 source_url: str = DEFAULT_OFAC_ETH_URL,
                 cache_path: Optional[Path] = None,
                 ttl_ms: int = DEFAULT_TTL_MS):
        self.source_url = source_url
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
        self.ttl_ms = ttl_ms
        self._addresses: Set[str] = set()
        self._last_fetch_ms: int = 0
        self._loaded_from_cache: bool = False

    # ─── Public API ───────────────────────────────────────────────

    def is_sanctioned(self, address: str) -> bool:
        """O(1) lookup. Address is case-insensitive (Ethereum normalization)."""
        return address.lower() in self._addresses

    def count(self) -> int:
        return len(self._addresses)

    def is_stale(self) -> bool:
        """True if cache is empty or older than TTL."""
        if not self._addresses:
            return True
        age_ms = int(time.time() * 1000) - self._last_fetch_ms
        return age_ms > self.ttl_ms

    def refresh(self, force: bool = False) -> dict:
        """Refresh the list. Returns status dict.

        Logic:
          1. If cache file exists and is fresh and not force: load cache
          2. Otherwise: try download + write cache
          3. If download fails and cache exists: load stale cache + warn
          4. If download fails and no cache: empty set, log warning
        """
        if not force and self._cache_is_fresh():
            return self._load_cache()

        # Try download
        try:
            addresses = self._download()
            self._addresses = {a.lower() for a in addresses if a.strip()}
            self._last_fetch_ms = int(time.time() * 1000)
            self._save_cache()
            return {
                'status': 'fresh',
                'source': 'download',
                'count': len(self._addresses),
            }
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            # Download failed — try cache fallback
            if self.cache_path.exists():
                self._load_cache()
                return {
                    'status': 'stale_fallback',
                    'source': 'cache',
                    'count': len(self._addresses),
                    'download_error': f'{type(e).__name__}: {e}',
                }
            else:
                # No cache, no network — fail-open with warning
                self._addresses = set()
                self._last_fetch_ms = 0
                return {
                    'status': 'unavailable',
                    'source': 'none',
                    'count': 0,
                    'download_error': f'{type(e).__name__}: {e}',
                    'warning': (
                        'No sanctions list available. '
                        'Production deployments must pre-populate cache.'
                    ),
                }

    # ─── Internals ────────────────────────────────────────────────

    def _cache_is_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        age_ms = int(time.time() * 1000) - int(self.cache_path.stat().st_mtime * 1000)
        return age_ms < self.ttl_ms

    def _download(self) -> list:
        """Fetch the address list from the source URL."""
        with urllib.request.urlopen(self.source_url, timeout=DOWNLOAD_TIMEOUT_S) as resp:
            data = resp.read().decode('utf-8')
        # Format: one address per line
        return [line.strip() for line in data.splitlines() if line.strip()]

    def _save_cache(self) -> None:
        self.cache_path.write_text(
            "\n".join(sorted(self._addresses)),
            encoding='utf-8'
        )

    def _load_cache(self) -> dict:
        try:
            text = self.cache_path.read_text(encoding='utf-8')
            self._addresses = {
                line.strip().lower() for line in text.splitlines()
                if line.strip()
            }
            self._last_fetch_ms = int(self.cache_path.stat().st_mtime * 1000)
            self._loaded_from_cache = True
            return {
                'status': 'fresh',
                'source': 'cache',
                'count': len(self._addresses),
            }
        except OSError as e:
            self._addresses = set()
            return {
                'status': 'unavailable',
                'source': 'none',
                'count': 0,
                'cache_error': f'{type(e).__name__}: {e}',
            }


# ─── Self-test ────────────────────────────────────────────────────

def _self_test() -> int:
    """Self-test that doesn't require network. Uses a mock cache file."""
    import tempfile

    print("agents.sanctions_list self-test")
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

    tmpdir = Path(tempfile.mkdtemp(prefix='sanctions_test_'))

    # 1. Empty list — nothing sanctioned
    def empty_list_lookup():
        sl = SanctionsList(cache_path=tmpdir / 'empty.txt')
        return not sl.is_sanctioned('0xabc')
    check("empty list returns False for any address", empty_list_lookup)

    # 2. Cache load round-trip
    def cache_round_trip():
        cache_path = tmpdir / 'roundtrip.txt'
        cache_path.write_text("0xaaaaaa\n0xbbbbbb\n0xCCCCCC")
        sl = SanctionsList(cache_path=cache_path, ttl_ms=10**12)  # huge TTL → cache is fresh
        sl._load_cache()
        return (sl.is_sanctioned('0xaaaaaa')
                and sl.is_sanctioned('0xbbbbbb')
                and sl.is_sanctioned('0xCCCCCC')
                and not sl.is_sanctioned('0xddddd'))
    check("cache load preserves addresses", cache_round_trip)

    # 3. Case-insensitive lookup
    def case_insensitive():
        cache_path = tmpdir / 'case.txt'
        cache_path.write_text("0xABCDEF1234567890")
        sl = SanctionsList(cache_path=cache_path, ttl_ms=10**12)
        sl._load_cache()
        return (sl.is_sanctioned('0xABCDEF1234567890')
                and sl.is_sanctioned('0xabcdef1234567890')
                and sl.is_sanctioned('0xAbCdEf1234567890'))
    check("address lookup is case-insensitive", case_insensitive)

    # 4. Count
    def count_correct():
        cache_path = tmpdir / 'count.txt'
        cache_path.write_text("0x1\n0x2\n0x3\n0x4\n0x5")
        sl = SanctionsList(cache_path=cache_path, ttl_ms=10**12)
        sl._load_cache()
        return sl.count() == 5
    check("count returns correct number of addresses", count_correct)

    # 5. is_stale: empty list is stale
    def empty_is_stale():
        sl = SanctionsList(cache_path=tmpdir / 'nonexistent.txt')
        return sl.is_stale()
    check("empty list reports as stale", empty_is_stale)

    # 6. is_stale: fresh cache is not stale
    def fresh_not_stale():
        cache_path = tmpdir / 'fresh.txt'
        cache_path.write_text("0x1")
        sl = SanctionsList(cache_path=cache_path, ttl_ms=10**12)
        sl._load_cache()
        return not sl.is_stale()
    check("fresh cache reports as not stale", fresh_not_stale)

    # 7. Save then load
    def save_load_round_trip():
        cache_path = tmpdir / 'savetest.txt'
        sl1 = SanctionsList(cache_path=cache_path, ttl_ms=10**12)
        sl1._addresses = {'0xaaa', '0xbbb', '0xccc'}
        sl1._last_fetch_ms = int(time.time() * 1000)
        sl1._save_cache()
        sl2 = SanctionsList(cache_path=cache_path, ttl_ms=10**12)
        sl2._load_cache()
        return sl2.is_sanctioned('0xaaa') and sl2.count() == 3
    check("save then load round-trips", save_load_round_trip)

    # 8. Empty lines and whitespace stripped
    def whitespace_handling():
        cache_path = tmpdir / 'whitespace.txt'
        cache_path.write_text("\n  0xaaa  \n\n0xbbb\n   \n")
        sl = SanctionsList(cache_path=cache_path, ttl_ms=10**12)
        sl._load_cache()
        return (sl.is_sanctioned('0xaaa')
                and sl.is_sanctioned('0xbbb')
                and sl.count() == 2)
    check("whitespace and empty lines handled", whitespace_handling)

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    print("─" * 50)
    passed = sum(results)
    total = len(results)
    print(f"  {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    import sys
    sys.exit(_self_test())
