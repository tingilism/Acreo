# Acreo

**Authorization layer for MCP agents.** ZK-based scoped delegation, agent wallets, fast revocation, and cryptographic audit trails — everything the Model Context Protocol punts on today.

```
zk proofs  ·  agent wallets  ·  ancestry  ·  dead-man's switch  ·  signed action trails
```

[→ Live demo](https://tingilism.github.io/Acreo/demo/) · [→ Blog post](./docs/mcp-agents-need-an-auth-layer.md) · [→ Deployed contract (Polygon Amoy)](https://amoy.polygonscan.com/address/0x4A946938614f1C2CECB0c0F510A1E45B78689CFf)

---

## The problem

You're building on MCP. Your agent needs to call an MCP server run by someone else — maybe another team, maybe another company. The auth story today is "share a bearer token." That means:

- A leaked token is a silent compromise. No revocation without rotating every consumer.
- No scope. The token can do anything the server allows.
- No payment metering, no lineage, no audit trail signed by the agent.
- When it goes wrong, you have logs. Not proofs.

Acreo is a drop-in substrate that solves these five problems as primitives:

| Problem | Acreo primitive |
|---|---|
| How does agent A know it can trust agent B? | **ZK proofs** — every action carries a zero-knowledge authorization proof |
| How does A pay B for work? | **Agent wallets** — metered credit, delegation-transferable |
| How do you revoke a compromised agent? | **Dead man's switch** — missed heartbeat = auto-revoke across the network |
| How does an agent prove its lineage? | **Ancestry proofs** — ZK proof of parent chain without exposing parent identity |
| How do you audit what the network did? | **Signed action trails** — cryptographic receipts, not log lines |

Read the [full writeup](./docs/mcp-agents-need-an-auth-layer.md) for why these problems are underserved by LangGraph, CrewAI, AutoGen, and the current MCP toolbox.

## What's in this repo

Six source files. That's it.

```
acreo.py              core SDK — Identity, Credential, Mandate, Verifier, Wallet
acreo_mcp.py          MCP server — exposes Acreo primitives as MCP tools
agent_network.py      multi-agent network helper — wires primitives into a cooperative network
AgentVerifier.sol     on-chain verifier (Solidity), deployed to Polygon Amoy
deploy.py             deployment script for the verifier contract
smithery.json         manifest for MCP registries (smithery.ai, glama.ai)
```

Plus `demo/index.html` (browser demo) and `docs/` (the blog post).

## Quickstart

```bash
git clone https://github.com/tingilism/Acreo.git
cd acreo
pip install -r requirements.txt

# Run Acreo's own test suite
python acreo.py

# Launch the MCP server (speaks MCP over stdio)
python acreo_mcp.py
```

## Use Acreo in your agent

```python
from acreo import Acreo, Identity, Permission

acreo = Acreo()

# Parent agent creates a scoped delegation for a child
parent = acreo.create_identity("parent")
child = acreo.create_identity("child")

credential = parent.delegate(
    to=child.public_key,
    permissions=[Permission.READ, Permission.WRITE],
    scope={"mcp_server": "my-mcp-server", "max_calls": 100},
    expires_in_seconds=300,
)

# Child signs an action with the credential
proof = child.sign_action(
    credential=credential,
    action={"tool": "database_query", "query": "SELECT * FROM users LIMIT 10"},
)

# Any verifier (including AgentVerifier.sol) can verify
acreo.verify(proof)  # True
```

## Using Acreo as an MCP server

Acreo ships as an MCP server so any MCP-compatible agent (Claude Desktop, Cursor, custom clients) can use its primitives as tools.

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "acreo": {
      "command": "python",
      "args": ["/path/to/acreo/acreo_mcp.py"]
    }
  }
}
```

Tools exposed by the MCP server:

- `acreo_create_identity` — create a cryptographic identity for a user or agent
- `acreo_issue_credential` — issue a scoped credential to a child agent
- `acreo_sign_action` — sign an action with a credential, produce a ZK proof
- `acreo_verify_proof` — verify an action proof against the issuing identity
- `acreo_revoke` — revoke a credential, propagates across the network
- `acreo_check_heartbeat` — dead-man's-switch status check

## Status

- **SDK:** v0.3 — tests pass
- **Contract:** deployed to Polygon Amoy testnet at `0x4A946938614f1C2CECB0c0F510A1E45B78689CFf`
- **MCP server:** functional, manifest in `smithery.json` for registry submission
- **End-to-end working:** delegation → proof → on-chain verification; heartbeat → auto-revocation; MCP server callable from Claude Desktop
- **Not yet:** formal security audit, mainnet deployment, framework-specific adapters beyond MCP

## Who this is for

- Teams building on **MCP** who need cross-organization authorization
- **LangGraph / CrewAI / AutoGen / OpenAI Agents SDK** projects hitting the trust-between-subgraphs problem
- **Agentic trading / DeFi** projects where a compromised agent costs real money
- **Multi-tenant agent platforms** that need signed audit trails for compliance

## Who this isn't for

- Single-agent applications (you don't need this)
- Agent systems within one trust boundary (too heavy for the benefit)
- Teams who haven't hit an authorization problem yet (you will — but don't adopt prophylactically)

## Roadmap

- **v0.3 (current):** MCP server + core SDK + on-chain verifier
- **v0.4:** LangGraph and CrewAI adapters
- **v0.5:** Mainnet deployment with first production integration
- **v0.6:** Formal security audit

## Contributing

The five-problem framing in [docs/mcp-agents-need-an-auth-layer.md](./docs/mcp-agents-need-an-auth-layer.md) is my current best articulation. Open issues telling me where it's wrong or which primitives you'd actually use.

## License

MIT

## About

Built by Anba Labs. If you're hitting one of the five problems and want to talk integration, my DMs are open.

**Twitter: [@Kourpokash](https://twitter.com/Kourpokash) · GitHub: [tingilism](https://github.com/tingilism)**
