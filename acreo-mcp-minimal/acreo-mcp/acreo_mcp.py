#!/usr/bin/env python3
"""
acreo_mcp.py — Acreo Protocol MCP Server
═════════════════════════════════════════
Exposes Acreo's ZK authorization, PII protection, and agent
credential system as MCP tools — discoverable by any AI agent.

Install:
  pip install mcp acreo

Run:
  python acreo_mcp.py

Publish to registry:
  smithery.ai/publish
  glama.ai/mcp/publish
"""

import json
import sys
import asyncio
from typing import Any

# MCP SDK
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
except ImportError:
    print("pip install mcp", file=sys.stderr)
    sys.exit(1)

# Acreo — import from same directory or installed package
sys.path.insert(0, ".")
from acreo import (
    Acreo, Identity, Credential, ActionProof,
    Permission, MandateConfig
)

# ── Single shared Acreo instance ────────────────────────────────────
_acreo = Acreo()

# In-memory identity store for the session
# Maps label → Identity object
_identities: dict[str, Any] = {}
_credentials: dict[str, Any] = {}

# ── Server ───────────────────────────────────────────────────────────
server = Server("acreo")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [

        Tool(
            name="acreo_create_identity",
            description=(
                "Create a cryptographic identity for a user or AI agent. "
                "Returns a public key. Private key is stored securely server-side "
                "and referenced by label. Use this before delegating credentials "
                "or generating ZK proofs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "description": "Unique name for this identity e.g. 'user_alice' or 'agent_trader'"
                    },
                    "kind": {
                        "type": "string",
                        "enum": ["user", "agent"],
                        "description": "Whether this is a human user or an AI agent"
                    }
                },
                "required": ["label", "kind"]
            }
        ),

        Tool(
            name="acreo_delegate",
            description=(
                "Delegate permissions from a user to an AI agent. "
                "Creates a signed credential that proves the agent is authorized "
                "to perform specific actions. The agent cannot act beyond what "
                "is granted here — this is cryptographically enforced."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": "Label of the user granting permissions"
                    },
                    "agent_label": {
                        "type": "string",
                        "description": "Label of the agent receiving permissions"
                    },
                    "permissions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of permissions to grant. Valid values: read, write, execute, transact, delegate, spend, communicate, search, memory, admin"
                    },
                    "scope": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Resources the agent can access e.g. ['documents/*', 'api/read']. Use ['*'] for full scope."
                    },
                    "ttl_hours": {
                        "type": "number",
                        "description": "How long this credential is valid in hours. Default 24."
                    },
                    "spend_limit": {
                        "type": "number",
                        "description": "Maximum USD the agent can spend with this credential. Optional."
                    }
                },
                "required": ["user_label", "agent_label", "permissions"]
            }
        ),

        Tool(
            name="acreo_prove_authorization",
            description=(
                "Generate a ZK proof that an agent is authorized to perform "
                "a specific action. This proof is cryptographically signed and "
                "time-bounded — it cannot be forged or replayed. "
                "Present this proof before any sensitive operation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_label": {
                        "type": "string",
                        "description": "Label of the agent requesting authorization"
                    },
                    "credential_id": {
                        "type": "string",
                        "description": "ID of the credential to use (returned by acreo_delegate)"
                    },
                    "action": {
                        "type": "string",
                        "description": "The action being authorized e.g. 'read', 'write', 'execute', 'transact'"
                    },
                    "resource": {
                        "type": "string",
                        "description": "The resource being accessed e.g. 'documents/report.pdf'. Use '*' for any."
                    }
                },
                "required": ["agent_label", "credential_id", "action"]
            }
        ),

        Tool(
            name="acreo_verify",
            description=(
                "Verify a ZK authorization proof. Returns whether the proof is valid, "
                "not expired, not replayed, and the agent has the required permission. "
                "Call this before executing any action on behalf of an agent."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "proof": {
                        "type": "object",
                        "description": "The ActionProof object returned by acreo_prove_authorization"
                    },
                    "credential_id": {
                        "type": "string",
                        "description": "Credential ID to verify against"
                    }
                },
                "required": ["proof"]
            }
        ),

        Tool(
            name="acreo_protect",
            description=(
                "Strip PII (personally identifiable information) from text before "
                "sending to an AI model or external service. Automatically removes "
                "emails, phone numbers, SSNs, credit card numbers, and more. "
                "Returns the cleaned text and a report of what was removed."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to scan and strip PII from"
                    }
                },
                "required": ["text"]
            }
        ),

        Tool(
            name="acreo_prove_identity",
            description=(
                "Generate a ZK identity proof for an agent or user. "
                "Proves the identity holds a private key without revealing it. "
                "Used for authentication without passwords or tokens."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "label": {
                        "type": "string",
                        "description": "Label of the identity to prove"
                    },
                    "claim": {
                        "type": "string",
                        "description": "The claim being proven e.g. 'authenticated', 'human-verified'"
                    }
                },
                "required": ["label", "claim"]
            }
        ),

        Tool(
            name="acreo_encrypt",
            description=(
                "End-to-end encrypt data for a specific user. "
                "Uses ChaCha20-Poly1305 + HKDF-SHA256. Only the intended "
                "recipient can decrypt. Use before storing sensitive agent outputs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "ID of the user who can decrypt this data"
                    },
                    "data": {
                        "type": "object",
                        "description": "Data to encrypt. Can be any JSON-serializable object."
                    }
                },
                "required": ["user_id", "data"]
            }
        ),

        Tool(
            name="acreo_status",
            description=(
                "Get Acreo Protocol status — active identities, credentials, "
                "verifications performed, and protocol version. "
                "Use to confirm Acreo is protecting the current agent session."
            ),
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),

    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:

    def ok(data: Any) -> list[TextContent]:
        return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]

    def err(msg: str) -> list[TextContent]:
        return [TextContent(type="text", text=json.dumps({"error": msg}))]

    # ── acreo_create_identity ────────────────────────────────────────
    if name == "acreo_create_identity":
        label = arguments["label"]
        kind  = arguments.get("kind", "agent")
        if label in _identities:
            return err(f"Identity '{label}' already exists")
        identity = (
            Identity.create_user(label) if kind == "user"
            else Identity.create_agent(label)
        )
        _identities[label] = identity
        return ok({
            "created": True,
            "label": label,
            "kind": kind,
            "public_key": identity.public_key,
            "message": f"Identity '{label}' created. Public key can be shared freely."
        })

    # ── acreo_delegate ───────────────────────────────────────────────
    elif name == "acreo_delegate":
        user_label  = arguments["user_label"]
        agent_label = arguments["agent_label"]
        permissions = arguments["permissions"]
        scope       = arguments.get("scope", ["*"])
        ttl_hours   = arguments.get("ttl_hours", 24.0)
        spend_limit = arguments.get("spend_limit")

        if user_label not in _identities:
            return err(f"User '{user_label}' not found. Create it first with acreo_create_identity.")
        if agent_label not in _identities:
            return err(f"Agent '{agent_label}' not found. Create it first with acreo_create_identity.")

        user  = _identities[user_label]
        agent = _identities[agent_label]

        try:
            cred = _acreo.delegate(
                user, agent, permissions,
                scope=scope,
                ttl_hours=ttl_hours,
                spend_limit=spend_limit
            )
        except Exception as e:
            return err(str(e))

        _credentials[cred.credential_id] = cred
        return ok({
            "credential_id": cred.credential_id,
            "agent": agent_label,
            "user": user_label,
            "permissions": cred.permissions,
            "scope": cred.scope,
            "expires_at": cred.expires_at,
            "valid": cred.valid(),
            "message": f"Agent '{agent_label}' is now authorized to {permissions} within scope {scope}"
        })

    # ── acreo_prove_authorization ────────────────────────────────────
    elif name == "acreo_prove_authorization":
        agent_label   = arguments["agent_label"]
        credential_id = arguments["credential_id"]
        action        = arguments["action"]
        resource      = arguments.get("resource", "*")

        if agent_label not in _identities:
            return err(f"Agent '{agent_label}' not found.")
        if credential_id not in _credentials:
            return err(f"Credential '{credential_id}' not found.")

        agent = _identities[agent_label]
        cred  = _credentials[credential_id]

        try:
            proof = _acreo.authorize(agent, cred, action, resource)
        except Exception as e:
            return err(str(e))

        return ok({
            "proof_id": proof.proof_id,
            "credential_id": proof.credential_id,
            "agent_key": proof.agent_key,
            "action": proof.action,
            "resource": proof.resource,
            "timestamp": proof.timestamp,
            "nonce": proof.nonce,
            "challenge": proof.challenge,
            "signature": proof.signature,
            "protocol": proof.protocol,
            "context": proof.context,
            "message": f"ZK proof generated. Agent '{agent_label}' is authorized to {action} on {resource}."
        })

    # ── acreo_verify ────────────────────────────────────────────────
    elif name == "acreo_verify":
        proof_data    = arguments["proof"]
        credential_id = arguments.get("credential_id")

        try:
            proof = ActionProof.from_dict(proof_data)
            cred  = _credentials.get(credential_id or proof.credential_id)
            result = _acreo.verify_action(proof, cred)
        except Exception as e:
            return err(str(e))

        return ok({
            **result,
            "message": "✓ Proof valid — agent is authorized." if result.get("valid")
                       else f"✗ Proof invalid — {result.get('reason')}"
        })

    # ── acreo_protect ────────────────────────────────────────────────
    elif name == "acreo_protect":
        text = arguments["text"]
        result = _acreo.protect(text)
        return ok({
            "protected_text": result["protected"],
            "pii_found": result["pii_found"],
            "clean": result["clean"],
            "pii_count": len(result["pii_found"]),
            "message": "Text is clean." if result["clean"]
                       else f"Removed {len(result['pii_found'])} PII field(s): {list(result['pii_found'].keys())}"
        })

    # ── acreo_prove_identity ─────────────────────────────────────────
    elif name == "acreo_prove_identity":
        label = arguments["label"]
        claim = arguments["claim"]

        if label not in _identities:
            return err(f"Identity '{label}' not found.")

        identity = _identities[label]
        try:
            proof = _acreo.prove(identity._priv.hex, claim)
        except Exception as e:
            return err(str(e))

        return ok({
            **proof,
            "message": f"ZK identity proof generated for '{label}' — claim: '{claim}'"
        })

    # ── acreo_encrypt ────────────────────────────────────────────────
    elif name == "acreo_encrypt":
        user_id = arguments["user_id"]
        data    = arguments["data"]
        try:
            encrypted = _acreo.encrypt(user_id, data)
        except Exception as e:
            return err(str(e))
        return ok({
            "encrypted": encrypted,
            "user_id": user_id,
            "message": f"Data encrypted for user '{user_id}'. Only they can decrypt it."
        })

    # ── acreo_status ─────────────────────────────────────────────────
    elif name == "acreo_status":
        verifier_summary = _acreo._verifier.summary()
        return ok({
            "protocol": "Acreo v1.0.0",
            "tagline": "Ward off threats. Protect what's real.",
            "active_identities": len(_identities),
            "active_credentials": len(_credentials),
            "verifications_total": verifier_summary["total"],
            "verifications_passed": verifier_summary["verified"],
            "verifications_denied": verifier_summary["denied"],
            "tools": [
                "acreo_create_identity",
                "acreo_delegate",
                "acreo_prove_authorization",
                "acreo_verify",
                "acreo_protect",
                "acreo_prove_identity",
                "acreo_encrypt",
                "acreo_status"
            ],
            "github": "github.com/anba-labs/acreo",
            "contract": "0x4A946938614f1C2CECB0c0F510A1E45B78689CFf"
        })

    return err(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
