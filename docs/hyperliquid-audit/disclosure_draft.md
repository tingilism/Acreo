# Disclosure: Threat model gaps in hyperliquid-python-sdk v0.23.0

**To:** Hyperliquid Security Team (via Discord ticket, per SECURITY.md)
**From:** Jimmy / Anba Labs — Acreo Protocol
**Date:** [DATE]
**Subject:** Coordinated disclosure: 10 findings in hyperliquid-python-sdk
**Proposed disclosure window:** 30 days from acknowledgment

---

Hi Hyperliquid team,

I'm writing to disclose findings from a source-level audit of `hyperliquid-python-sdk` v0.23.0 that I completed this week. None of these are protocol-level vulnerabilities or memory-safety issues — the SDK's cryptographic primitives are sound and used correctly. The findings are SDK design patterns and defensive-feature gaps that systematically push bot operators toward insecure deployments, and one observation about a documented limitation that I think deserves a more visible warning.

I'm following your SECURITY.md process and giving you the full audit plus a verification script before any public release.

## Summary

Ten findings, ranked by severity:

| # | Severity | Finding |
|---|----------|---------|
| 1 | High | `approve_agent()` generates the agent private key and returns it to the caller with no key-management hook. This is the design pattern downstream bots inherit — the ecosystem-wide result is plaintext-key-on-disk. |
| 2 | Medium-High | `expires_after` replay protection is silently inoperative for `usd_transfer`, `withdraw_from_bridge`, `spot_transfer`, `approve_agent`. Documented only in a source comment. |
| 3 | High | The SDK's own example pattern (`examples/config.json`) is plaintext JSON. Multiple downstream bot frameworks copy this exactly. |
| 4 | Medium | Default `base_url` is mainnet — omission errors hit production. |
| 5 | Medium | `DEFAULT_SLIPPAGE = 0.05` (5%) on market orders is permissive. |
| 6 | Medium | Multi-sig type enrichment failure prints to stdout instead of raising. |
| 7 | Low | Float-typed order interface encourages unsafe arithmetic. |
| 8 | Low | No default request timeout. |
| 9 | Informational | `LocalAccount` private key persists in memory for bot's full lifetime. |
| 10 | Low | `approve_agent()` mutates action dict after signing. |

## Empirical verification

Every source-readable finding was verified against the installed SDK on a Windows 11 + Python 3.11 environment. The verification script (`verify_audit.ps1`, attached) regexes the installed SDK files and prints the matched lines. Output below — 8 of 8 source-readable claims CONFIRMED:

```
SDK path:    .venv\Lib\site-packages\hyperliquid
SDK version: 0.23.0

Finding 4  CONFIRMED — api.py line 14
Finding 8  CONFIRMED — api.py line 13
Finding 5  CONFIRMED — exchange.py line 61
Finding 2  CONFIRMED — exchange.py line 115
Finding 1a CONFIRMED — exchange.py line 616
Finding 1b CONFIRMED — exchange.py line 636
Finding 10 CONFIRMED — exchange.py line 628
Finding 6  CONFIRMED — signing.py line 276
```

(Findings 3, 7, 9 are not source-regex-verifiable; methodology for each is in the full audit document.)

## Real-world impact context

Before the SDK audit, I built a targeted scavenger against a specific public Hyperliquid bot — `aiwebarchitects/Hyperliquid-Trading-Bot` (Apache 2.0, 3 stars, last update Oct 27 2025, v0.02 released Nov 9 2025). That bot stores its agent key at `config/api_config.json` in plaintext JSON, per its own README. The scavenger:

1. Walks standard clone locations on Windows (Documents, Desktop, Downloads, etc.) with no path hints
2. Identifies installations by structural fingerprint (specific files + directories)
3. Reads the plaintext config and extracts the agent key

Demonstrated working end-to-end on Windows 11 against a synthetic installation in a controlled test. The scavenger doesn't need elevated privileges, network access, or process memory inspection — just user-mode file reads.

This is the concrete realization of Finding 1's threat model: an attacker with user-mode code execution on the bot operator's machine has trivial access to the agent key, because the SDK design pattern leads everyone to store it in a predictable plaintext location.

The bot's author is following the SDK's own example pattern. The issue is upstream.

## What I'm asking for

1. Acknowledge receipt of this disclosure
2. Review the findings — push back on anything you think is overstated or misclassified
3. Indicate which findings you intend to address and on what timeline
4. Coordinate the public disclosure date

I'd like to publish the audit and verifier 30 days after this submission, or sooner if you release fixes or publish acknowledgment. If you need more time on a specific finding, I'm flexible.

## What's attached

- `hl_sdk_audit.md` — full audit document with all 10 findings, source citations, recommended remediations, and an "honest scope" section
- `verify_audit.ps1` — PowerShell verification script that reproduces 8 of 10 findings against any installed SDK 0.23.0

## Notes on Acreo

For transparency: I run Anba Labs, which is building Acreo Protocol — a ZK authorization layer for AI agents that's relevant to several of these findings (specifically 1, 3, 9, where threshold-signed principals address the single-party-key problem). The audit identifies SDK gaps that Acreo's architecture closes. I want to be upfront that I have a commercial interest in this work being read.

That said: the SDK findings stand on their own as security research, with reproducible empirical verification. I'm not asking you to endorse Acreo. I'm asking you to evaluate the findings on their merits and consider the SDK-level fixes regardless of any third-party layer.

Happy to walk through any of this on a call or async if useful.

Best,
Jimmy
Anba Labs
github.com/spencerkourpa-debug/acreo
