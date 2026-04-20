# MCP Agents Need an Auth Layer

Every multi-agent system being built in 2026 eventually hits the same five problems. Most teams solve them badly, one at a time, when capital is on the line and it's too late to do it properly. This is a post about those five problems, why the current toolbox doesn't answer any of them cleanly, and what a proper substrate for trust and delegation between agents looks like.

I've been building in this space for the last year — shipped a ZK authorization verifier to Polygon Amoy last month, been watching the MCP ecosystem grow from the inside. What follows is the result of that work.

## The five problems

Let's make them concrete. You're building an agent system. Maybe it's a financial analyst agent that delegates execution to a trading sub-agent. Maybe it's a customer service orchestrator that spawns specialist agents per ticket. Maybe it's a research agent that calls out to MCP servers hosted by three different vendors.

Here are the questions you don't have clean answers to:

**1. How does agent A know it can trust agent B?** When agent A asks agent B to do something on its behalf, B needs to prove it's authorized — not just that it has an API key. A leaked key means any attacker can be "agent B." What you actually want is a credential scoped to this specific delegation, with an expiration and a signature.

**2. How does agent A pay agent B?** Most frameworks hand-wave this. In reality: if you're paying per-request to an external MCP server, or compensating a sub-agent for compute, you need metered authorization tied to payment. LangChain doesn't answer this. CrewAI doesn't either.

**3. How do you revoke a compromised agent?** An agent gets its credentials stolen. How do you cut it off *everywhere* in your system within seconds? Not in hours, not after a deploy. Seconds. The answer in most systems is "rotate the API key and restart all services." That's not good enough when your agents are handling real-time work.

**4. How does an agent prove its lineage?** Agent A spawned agent B which spawned agent C. When C takes an action, you need to be able to trace who authorized who, without exposing A's identity to C. This matters for audit. It matters more when something goes wrong and you need to figure out which orchestrator's instructions led to which mistake.

**5. How do you audit what the network did?** Every action an agent takes should leave a cryptographic receipt. Not a log line. A signed, non-repudiable record of "this agent, with this authorization, did this thing, at this time." Logs can be tampered with. Signatures can't.

If you're nodding along, you've hit these problems. If you haven't yet, you will.

## What the current toolbox offers

**LangGraph**: excellent state machine framework. Treats auth as the user's problem.

**CrewAI**: great role-based abstraction. Auth? Up to you.

**AutoGen**: solid messaging framework. Auth story: implicit, usually via whatever the model provider offers.

**OpenAI's Agents SDK**: handoffs and tracing. Guardrails on inputs/outputs. Auth *between* agents is mostly "share a bearer token."

**Claude Agent SDK + MCP**: the protocol is beautiful. The auth layer for cross-organization MCP calls — "my agent wants to use your MCP server with scoped permissions" — is underspecified today.

None of these are doing a bad job. They're doing the job they were designed for. Authorization and delegation between agents is a different concern, and treating it as an add-on rather than a substrate is how we got here.

## The mycelium metaphor

Forests have a substrate nobody sees. Mycorrhizal networks — fungal threads running through the soil — connect trees, route nutrients from sugar-rich trees to struggling ones, carry chemical distress signals when one tree is attacked. The network has no central brain. No individual fungal strand "owns" the network. But the trees above ground only work because the substrate below ground is doing its job.

Agent systems are the same. The agents are the visible, impressive part. The trust, authorization, payment, and audit infrastructure is the substrate. And right now, every team is growing the trees without thinking about the soil they're planted in.

What I've been building is the mycelium layer.

## Acreo: five primitives that map to the five problems

Acreo is an authorization and delegation substrate for multi-agent systems. It has five primitives, and each one answers one of the problems above.

**ZK proofs for scoped authorization.** Every action an agent takes carries a cryptographic proof that it was authorized — specifically, for this action, in this scope, by this parent. The proof is zero-knowledge: the verifier learns that the agent was authorized, but not by whom or under what broader authority. This answers problem #1.

**Agent wallets.** Every agent has a wallet with a balance. Actions cost credits. Delegations transfer credit allowances. This is metered authorization — not "can this agent do this?" but "can this agent do this *and* has it paid to do it?" Answers problem #2.

**Revocation with dead man's switch.** Every agent sends heartbeats. Miss a heartbeat window and the network assumes the agent is compromised. All its credentials die automatically. Child agents lose their authority. The network self-heals around the dead node. Answers problem #3.

**Ancestry proofs.** Each agent's credentials contain a zero-knowledge proof of its lineage — I was spawned by someone authorized by the root — without revealing the parent's identity to the verifier. Answers problem #4.

**Signed action trail.** Every action produces a signed record. Not an optional log. A required cryptographic receipt. Answers problem #5.

The primitives aren't revolutionary in isolation. Dead man's switches exist. ZK credentials exist. What's novel is treating them as the substrate a multi-agent system grows on, not five separate features bolted onto the agents themselves.

## The demo

Here's what it looks like when it runs. Four agents — Scout, Analyst, Executor, Auditor. The substrate is alive; you can see the breathing hyphae connecting them.

**Run task:** Scout searches, delegates to Analyst with a scoped proof. Analyst verifies, delegates to Executor. Wallets tick down with each proof. Auditor receives the action trail.

**Inject rogue:** An unauthorized agent appears at the perimeter and tries to issue a message to Analyst. No valid credential, no entry. The edge breaks. The event is logged.

**Compromise Executor:** Executor's heartbeat stops. Three seconds later, the dead man's switch fires. Its credentials are revoked. Analyst's next delegation has nowhere to go — until the network spawns a replacement Executor (with fresh credentials but preserved lineage), rewires the edges, and work resumes.

That's 90 seconds, four agents, five primitives. The whole thesis in one browser tab: **[demo link]**.

## Why this matters now

MCP adoption is accelerating. OpenAI supports it. Google supports it. Every serious agent framework is adding MCP compatibility. Which means: agents from company A are increasingly going to call MCP servers run by company B. Cross-organization agent workflows are about to be the norm, not the exception.

When that happens, the current "share an API key" model falls apart fast. You need scoped delegation. You need fast revocation. You need audit trails. You need all of it to work across organizational boundaries without central coordination.

The substrate has to exist before the ecosystem scales. And right now, it doesn't.

## What's next

Acreo is open source. The smart contract is deployed on Polygon Amoy testnet. The SDK is MIT-licensed. 452 tests pass.

What I'm looking for: teams building on MCP or in the Agent SDK ecosystem who've hit one of the five problems and want to talk about how Acreo might fit. If you're building multi-agent infrastructure and the trust-and-delegation layer has been your "we'll figure that out later" problem, let's figure it out now.

**Repo:** [github.com/tingilism/acreo]
**Demo:** [link to mycelium demo]
**Contact:** @Kourpokash

I'm publishing this because I want feedback. The five-problem framing is my current best articulation — I'd like to hear where it's wrong, which problems I've missed, and which of the primitives you'd actually use.

---

*Acreo is built by Anba Labs. If you're building agent infrastructure and want to talk through integration, my DMs are open.*
