# Acreo Protocol

**Cryptographically enforced policy boundary for AI agents.**

> Nine of ten OWASP 2026 Agentic Application risks addressed with concrete, reproducible defenses. One acknowledged orthogonal limit.

Acreo is the policy-enforcement layer that lives **outside** the agent's trust domain. The agent never holds a usable signing key. Action requests pass through a threshold-signed principal whose cosigners verify the request against a declared policy. The agent can be compromised, the host can be compromised, the underlying LLM can be tampered with — the principal still refuses to sign actions outside policy, because the cosigner network is structurally outside the bypassable domain.

This repo contains the architecture, seven shipped policy contracts with 135 passing tests, a third-party SDK audit demonstrating the threat class, and the documented roadmap.

---

## Why this exists

In 2025-26 the AI agent economy crossed into production. So did the attacks against it. The OWASP Top 10 for Agentic Applications (December 2025) catalogued the risks. The October 2025 Hyperliquid incident — $21M lost to a single private key leak — demonstrated the cost of getting agent delegation wrong. Bessemer's March 2026 analysis identified context-aware in-flight policy enforcement as the most underdeveloped infrastructure category in the entire agentic security market.

Every existing agent-safety solution lives in the same trust domain as the agent. Runtime governance frameworks. In-process guardrails. Policy-as-code engines that share an address space with the LLM they're trying to constrain. They are bypassable the moment the agent's runtime is compromised.

Acreo's threshold-signed principal architecture is the only place in the stack where policy enforcement can be made cryptographically unbypassable. The agent gets a handle to a principal; the principal verifies actions against policy using cosigners and ZK proofs; nobody — including Anba Labs — holds the key.

---

## What's in this repo

```
acreo/
├── README.md                          (this file)
├── docs/
│   ├── roadmap.md                     OWASP 2026 mapping, architecture
│   ├── impact-analysis.pdf            17 pages, $535M+ documented losses
│   └── hyperliquid-audit/             SDK audit + verifier + POC fix
├── contracts/
│   ├── AgentVerifier.sol              ASI03, ASI05 (partial), ASI10
│   ├── IntentVerifiedPolicy.sol       ASI01 - 15 tests
│   ├── StatefulCumulativePolicy.sol   ASI02 v0.1 - 19 tests
│   ├── BehavioralFingerprintPolicy.sol ASI02 v0.2 - 17 tests
│   ├── OracleConfirmedPolicy.sol      ASI04 - 13 tests
│   ├── AttestedExecutionPolicy.sol    ASI06 v0.1 - 22 tests
│   ├── CircuitBreakerPolicy.sol       ASI07 - 24 tests
│   └── CrossPrincipalPolicy.sol       ASI08 - 25 tests
├── test/
│   └── ...                            135 tests, all green
├── threshold-signing/                  Tier 1.5 primitive, 184 tests
└── hardhat.config.js
```

---

## OWASP 2026 coverage

| ID | Risk | Status | Contract |
|----|------|--------|----------|
| ASI01 | Agent Goal Hijack | ✅ shipped | IntentVerifiedPolicy |
| ASI02 | Memory Poisoning | ✅ shipped (v0.1 + v0.2) | StatefulCumulativePolicy + BehavioralFingerprintPolicy |
| ASI03 | Identity/Privilege Abuse | ✅ shipped | AgentVerifier (threshold signing) |
| ASI04 | Tool/Oracle Misuse | ✅ shipped | OracleConfirmedPolicy |
| ASI05 | Unexpected Code Execution | 🟡 partial | AgentVerifier (action-type restriction) |
| ASI06 | Supply Chain Compromise | ✅ shipped (v0.1) | AttestedExecutionPolicy |
| ASI07 | Cascading Failures | ✅ shipped | CircuitBreakerPolicy |
| ASI08 | Agent Communication | ✅ shipped | CrossPrincipalPolicy |
| ASI09 | Human Trust Exploitation | ⚠️ acknowledged limit | orthogonal to cryptographic enforcement |
| ASI10 | Runaway Autonomy | ✅ shipped | AgentVerifier (bounded action space) |

**Nine of ten with concrete cryptographic coverage. One acknowledged limit.**

---

## Reproducing the receipts

Everything is verifiable. Each contract has its own test suite. To run them all:

```bash
git clone https://github.com/spencerkourpa-debug/acreo
cd acreo
npm install
npx hardhat compile
npx hardhat test
```

Expected output: 135 passing across the seven new policy contracts. Plus 184 passing for the threshold-signing primitive.

### Per-defense verification

Each contract is independent. To run one policy's tests:

```bash
npx hardhat test test/IntentVerifiedPolicy.test.js
```

### Hyperliquid SDK audit verification

```bash
cd docs/hyperliquid-audit
# Windows
powershell -ExecutionPolicy Bypass -File ./verify_audit.ps1
```

Verifies 8 of 10 source-readable findings against the installed `hyperliquid-python-sdk` v0.23.0.

---

## On-chain deployments

| Contract | Network | Address |
|----------|---------|---------|
| AgentVerifier | Polygon Amoy | `0x4A946938614f1C2CECB0c0F510A1E45B78689CFf` |

Additional deployments forthcoming. See `docs/deployments.md` for status.

---

## The Hyperliquid SDK audit

A separate piece of work in this repo: a source-level audit of `hyperliquid-python-sdk` v0.23.0 (2,970 lines). Ten findings, eight empirically verified by a reproducible PowerShell script that regexes the installed SDK files. The headline finding — `approve_agent()` hands the caller a raw private key with no key-management hook — is the design pattern that has propagated to every Python Hyperliquid bot in production.

We built a targeted scavenger against `aiwebarchitects/Hyperliquid-Trading-Bot` (a real public bot, Apache 2.0) that extracts the agent key from its plaintext storage location with no privilege escalation. The vulnerability is in the upstream SDK pattern, not the bot.

The audit was filed with the Hyperliquid team via their documented disclosure channel. POC fix bundle (proposed `approve_agent_v2(name, key_store)` interface) included.

See `docs/hyperliquid-audit/` for the full audit, verifier, POC, and disclosure record.

---

## How the policies compose

A real agent's policy stack runs all enabled layers in sequence. An action proceeds to threshold signing only if every enabled layer authorizes:

```
ASI07 CircuitBreakerPolicy      ← rate limits
ASI01 IntentVerifiedPolicy      ← intent category check
ASI02 StatefulCumulativePolicy  ← cumulative value caps
ASI02 BehavioralFingerprintPolicy ← action-mix shape
ASI04 OracleConfirmedPolicy     ← oracle confirmation
ASI06 AttestedExecutionPolicy   ← agent measurement check
ASI08 CrossPrincipalPolicy      ← dual-principal authorization (if applicable)
AgentVerifier                    ← threshold signature production
```

Each layer is independent. Different attacks fail at different layers. An attacker must simultaneously bypass every enabled defense — and on both principals' sides for cross-principal flows — to push through a malicious action.

---

## Honest limitations

Several pieces are v0.1:

- **ASI06 AttestedExecutionPolicy** uses a trusted-attestor model. v1.0 (Q1 2027 target) replaces this with direct on-chain ECDSA-P384 verification of SEV-SNP/TDX attestation reports. ~6 months of specialist cryptography work plus audit.
- **ASI02 v0.1 + v0.2** address cumulative-value and category-mix attacks. The full SOTA version (Q1 2027) replaces in-contract arithmetic with recursive ZK proofs over a Verkle accumulator, enabling semantic anomaly detection via TEE-attested behavioral models.
- **ASI05** is partial — bounded action types at the policy layer. Full coverage requires controls inside the agent's reasoning layer that Acreo's architecture doesn't reach.
- **ASI09** is acknowledged as orthogonal. Acreo enforces policy cryptographically; if a user is socially engineered into approving a harmful policy, Acreo correctly enforces what they approved. Layered defense via observability tooling is the recommendation.

These are documented in `docs/roadmap.md` along with the engineering plan for each.

---

## Contact

Built by [Anba Labs](https://github.com/spencerkourpa-debug). Founder: Jimmy.

For integration discussions, security disclosures, or partnership inquiries:
- GitHub Issues for technical questions
- Security disclosures: see `SECURITY.md`

---

## License

Apache 2.0. Build on it, fork it, send PRs. The cryptography is no good locked behind a paywall.
