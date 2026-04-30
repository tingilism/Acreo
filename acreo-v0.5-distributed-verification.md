# Acreo v0.5: Distributed Verification

**Status**: Design draft — April 2026
**Audience**: Future collaborators
**Companion to**: `acreo-negotiation-protocol-design.md` (Stage A/B), `README.md`

---

## 1. Problem Statement

Acreo v0.1 makes agent authorization cryptographically expressible. Credentials carry signed scope, action proofs are non-repudiable, heartbeats enable revocation, sealed messaging keeps operator notifications private, post-quantum primitives provide a migration path against future cryptanalytic capability, and verifiable activity streams record agent behavior in tamper-evident form. The codebase ships 178 tests across 12 chaos suites covering replay, forgery, scope violation, expiration, budget exhaustion, malformed inputs, concurrency, sealed-messaging tampering, anonymous-proof unlinkability, post-quantum cross-suite confusion, and activity stream chain integrity.

What v0.1 does not provide is *adversarial verifiability of history*. Every primitive in v0.1 assumes the verifier is trusted. The audit log lives in the verifier's process memory. The operator runs the verifier. The operator can drop entries, restart to wipe state, or simply not run the verifier when their actions are inconvenient. The activity stream primitive helps — frames are hash-chained and signed — but the stream itself is held by the operator, who can refuse to publish portions of it. This is the right design choice for v0.1; it lets operators run Acreo locally with no infrastructure dependencies. It is the wrong design choice for what comes next.

What comes next, and the reason v0.5 is worth building, is the agent insurance market. Agent operators today carry uninsurable risk. A trading bot with a $50,000 spend limit represents $50,000 of exposure. If the bot's signing key leaks, an attacker drains the limit before anyone notices. If the bot has a logic bug, it executes outside its intended scope. If the operator's infrastructure is compromised, every credential the bot holds becomes attacker-controlled. These risks keep agent deployments small. Operators who could profitably deploy at $5M of exposure deploy at $50K because tail risk is uninsurable.

Insurance for agents does not exist as a product because insurers cannot underwrite what they cannot verify. Underwriting requires three foundational primitives that no current agent infrastructure provides:

**Verifiable risk assessment.** The insurer needs to know what they are insuring against, with enough detail to price the premium. Auto insurance asks about driving history. Life insurance asks about health. The risk has to be assessable from outside the operator. Today, an operator describing their agent's risk profile produces operator-curated documentation with no cryptographic backing.

**Verifiable incident detection.** When something insurable happens, both parties need a neutral source of truth. Police reports, medical records, transaction logs from independent ledgers — traditional insurance relies on third-party evidence. Today, when an agent goes rogue, the operator's logs say one thing, the affected counterparty's logs say another, and there is no protocol-level record both parties trust.

**Verifiable scope of obligation.** The policy specifies what is covered. When a claim comes in, both parties need to agree whether the incident falls within scope. Today, agent permissions exist only in operator code; there is no cryptographic contract an insurer can point at.

For insurance to function, all three must be **adversarially verifiable** — meaning the determination does not depend on trusting the operator, who has financial incentive to hide bad behavior.

v0.1 Acreo addresses pieces of all three problems but does not fully solve any of them. Credentials have cryptographic scope, so risk profiles are technically expressible. ActionProofs are signed and non-repudiable, so individual events are technically verifiable. Permissions and scope are unambiguous, so policy boundaries are technically clear. v0.1 makes all three problems addressable. It does not make them adversarially verifiable, because the verifier is operator-controlled.

Five concrete gaps prevent insurance from functioning on v0.1:

**Gap 1: Operator-controlled audit trail.** The verifier runs on the operator's machine. The audit log is in-memory and lost on restart. The operator can selectively run the verifier only for actions they want recorded. Activity streams are signed but the operator can refuse to broadcast them.

**Gap 2: No historical state verification.** v0.1 verification is point-in-time. There is no way to ask "was this proof valid at the moment it was used" — only "is it valid now."

**Gap 3: No neutral oracle for incidents.** When something insurable happens, no party other than the operator has authoritative records. The operator has both the data and the incentive to hide.

**Gap 4: No standardized claim format.** Every potential insurer would need custom integration with each operator. Insurance integration becomes O(insurers × operators) instead of O(insurers + operators).

**Gap 5: No operator-blind verification at scale.** v0.1 anonymous proofs are external-observer-unlinkable but operator-correlatable. An insurer underwriting privacy-sensitive operators would learn things they should not be able to learn.

v0.5 closes these gaps. The reframing that matters is this: **v0.5 is not Acreo with better cryptography. v0.5 is the audit infrastructure layer that the agent insurance market will be built on.** Threshold-Schnorr verification is one component. Distributed audit logs, time-anchored historical state, threshold-signed query responses, standardized claim schemas, and operator-blind credential verification are equally load-bearing. Together they produce verifiable agent behavioral history that downstream applications — first insurance, then reputation systems, eventually regulatory audit and dispute resolution — can build on.

The strategic implication is that Acreo's defensibility comes from being the layer, not the application. Other agent infrastructure can compete on SDK quality, language support, and framework integration. The audit infrastructure layer is harder to compete with because it requires distributed trust, which requires independent validators, which requires partnership work that is slow to replicate. The team that gets the validator network running first has a moat.

This document specifies how to build it.

---

## 2. The Use Case: Insurance and Reputation

This section grounds the rest of the document. Architectural decisions in subsequent sections are evaluated against whether they make this use case work. If a design choice does not serve the use case, it is the wrong choice.

### 2.1 The market reality

Agent operators today self-insure or go uninsured. The agent insurance market does not exist as a product because the underwriting primitives do not exist. v0.5 changes this. The first insurer to integrate against the v0.5 query interface gets to underwrite a market that has no incumbents and grows with the agent economy itself. Acreo does not ship insurance products; Acreo ships the layer insurers build on.

The market for what Acreo enables is not theoretical. By early 2026, roughly half of enterprises have AI agents in production. Approximately 80% of those companies do not have a mature governance model for those agents. Project failure rates due to weak risk controls run 40%+. Shadow agent deployments — unsanctioned agents running without IT approval — account for over half of enterprise AI usage. The demand for adversarially-verifiable agent governance is acute right now, not future.

Insurance is the first vertical because the unit economics work cleanly: insurer charges premium, operator pays for coverage, transaction is bilateral. Other applications enabled by the same infrastructure (reputation systems, regulatory audit, dispute resolution) have public-goods dynamics that make initial bootstrapping harder. Insurance pulls the audit infrastructure into existence; everything else benefits as the network matures.

### 2.2 Reputation as the underwriting layer

A subtlety that is easy to miss: insurance and reputation are not parallel use cases. Reputation is the underwriting input that makes insurance pricing actually work.

An insurer pricing without behavioral history is shooting blind. They have to assume worst case, which means premiums are either prohibitively high (covers worst case, no one buys) or catastrophically low (covers nothing, insurer goes bankrupt on first cluster of claims). Reputation history — the verifiable behavioral track record of an agent and its operator — is what makes the math work. A credential operated by someone with 18 months of clean broadcast history, consistent within-scope action patterns, and no anomalies gets one premium. The same credential operated by a brand-new operator with no track record gets a much higher premium or no coverage at all.

This is exactly how traditional insurance works. The reputation/history piece is the foundation that makes pricing possible.

For v0.5 specifically, reputation is not a separate feature requiring separate architecture. It is a derived property of the audit infrastructure. The same distributed audit log that makes incident detection adversarially verifiable also produces the behavioral history that makes underwriting possible. Different insurers may compute reputation differently — one prioritizes recency, another prioritizes total volume, another prioritizes consistency — but they all work from the same underlying audit data. This mirrors how credit scoring works: multiple bureaus with different models, all working from the same underlying transaction history.

### 2.3 The actors

A worked example involves four actors:

**Alice (the operator)** runs a trading bot on Polymarket. The bot holds an Acreo credential with permissions `['transact']`, scope `['polymarket/*']`, and a `spend_limit` of $50,000. Alice's infrastructure is integrated with the v0.5 validator network — every credential issuance, action proof verification, activity stream frame, and revocation is broadcast to validators as part of her credential's broadcast obligation.

**Hedgepoint (the insurer)** is a hypothetical insurance company that has built underwriting models for agent failure modes. Hedgepoint integrates with the v0.5 validator network as a query consumer. They do not run validators themselves; they query the network to assess risk and adjudicate claims.

**The validator network** is a set of independent parties V1 through V21 running validator software. They collectively maintain the audit log, sign threshold attestations, and serve query requests. No single validator has enough information to manipulate outcomes; threshold cooperation is required for any signed answer.

**The attacker** is anonymous. The protocol does not need to specify them — what matters is that they obtain Alice's credential through some compromise.

### 2.4 The policy

Before any incident happens, Alice purchases coverage from Hedgepoint:

1. Alice queries the validator network for her credential's metadata. She gets back: scope, permissions, spend_limit, issuance time, current state, broadcast compliance history (what fraction of expected events her infrastructure has broadcast over the last 90 days), and aggregate behavioral statistics derived from her activity stream (frequency distribution, scope adherence rate, anomaly count).

2. Alice sends this metadata to Hedgepoint as part of her insurance application. The metadata is signed by the validator threshold; Hedgepoint verifies it independently without trusting Alice.

3. Hedgepoint runs its underwriting model. The reputation history feeds into premium pricing. The underwriting is grounded in adversarially-verifiable facts.

4. Hedgepoint issues a policy: $50,000 coverage against credential compromise, $X annual premium. The policy is a signed document referencing Alice's credential by ID.

The entire underwriting flow is based on cryptographic facts queryable from the validator network, not operator-supplied documentation. Hedgepoint never had to trust Alice's representations.

### 2.5 The incident

Some weeks later, the attacker compromises Alice's environment and exfiltrates her credential's signing key. The attacker begins generating action proofs, draining the bot's authorized spend.

Three things happen in parallel:

The attacker's actions hit Alice's verifier. Each action proof is signature-checked, replay-checked, scope-checked, and accepted because they are generated with the legitimate signing key.

Alice's infrastructure broadcasts each verification to the validator network. As required by the broadcast obligation, every action proof gets sent to validators within seconds, along with the corresponding activity stream frame.

The bot's Polymarket account drains. The actions are real because the validator network does not sit in the path of execution. By the time the third action proof has been broadcast, $30,000 has moved.

Alice notices the issue an hour later when her monitoring catches anomalous patterns. She immediately revokes the credential. Total elapsed time: 1 hour 12 minutes. Total loss: $34,500.

### 2.6 The claim flow

Hedgepoint queries the audit log:

- "Return all action proof verifications for credential C-7f3a... between [policy_start] and now." Validators return the full list, threshold-signed, with timestamps.
- "Return the credential's lifecycle events." Validators return: issued [time], active throughout [period], revoked at [time].
- "Return the historical state of credential C-7f3a... at the time of each action proof." Validators return Merkle-proof-backed state assertions.
- "Return the activity stream segment for agent A from [policy_start] to revocation." Validators return the chained frames; Hedgepoint verifies the chain is unbroken.

Hedgepoint's claim engine runs through the event list and asks four questions per event:

1. Was the credential valid at the time of this action? (Yes — credential wasn't revoked yet.)
2. Was the action within scope? (Yes — all actions matched `polymarket/*`.)
3. Was the action below spend_limit? (Yes — cumulative spend stayed within $50K.)
4. Did the action match Alice's pre-policy declared usage patterns? (No — frequency, timing, and order shapes deviate significantly from baseline.)

The first three establish protocol-validity. The fourth is the insurance signal. Hedgepoint's underwriting model identifies this pattern as credential compromise with high confidence.

Hedgepoint pays $30,000 in confirmed losses. The remaining $4,500 goes to human review for ambiguity. **Total automated claim adjudication time: ~8 minutes.**

Compare this to traditional insurance claim flows where investigators spend weeks reconstructing events. The validator network has the reconstructed history already, cryptographically attested.

### 2.7 The variations

The same architecture handles other failure modes:

**Scope violation**: Hedgepoint queries detect actions whose `resource` field does not match the credential's `scope`. Coverage flows to the affected counterparty — third-party liability insurance.

**Operator negligence**: Hedgepoint queries detect actions occurring after a documented revocation-trigger event but before actual revocation. Coverage limited because operator negligence reduces payout.

**Heartbeat failure**: The validator network detects heartbeat gaps automatically and revokes the credential. Insurance covers losses between last successful heartbeat and revocation.

In each case the architecture provides what insurance has never had: adversarially-verifiable agent action history with no operator manipulation possible.

---

## 3. Architecture Overview

The v0.5 architecture has three components: a permissioned validator network, a broadcast obligation enforced through credential lifecycle, and an oracle query interface that downstream consumers (insurers, auditors, reputation systems) integrate against.

### 3.1 The validator network

The validator network is a set of 21 independent parties running validator software. Parties are selected by Acreo and confirmed by a governance process; the set is permissioned, not permissionless. Each party stakes a bond as a condition of joining the network. Misbehavior — signing attestations for events that didn't happen, going offline frequently, refusing to serve queries — gets slashed.

The choice of 21 validators is deliberate. It is large enough that geographic and organizational diversity is achievable: validators can span multiple regulatory jurisdictions, multiple corporate structures, multiple cloud providers. It is small enough that threshold signing remains efficient — a 14-of-21 threshold (2/3+1, standard byzantine fault tolerance) requires aggregating 14 partial signatures, which is computationally tractable. It mirrors the size used by similar networks (Wormhole's Guardian set was 19 at most points of its history); this is a known-good operating point.

Validator selection should target three properties: independence (no two validators share infrastructure, jurisdiction, or ownership), competence (validators must be technically capable of running the software reliably), and economic alignment (validators must care about the network's success enough to behave honestly even when slashing is the only enforcement mechanism). The first version of the validator set will likely include a mix of cryptocurrency infrastructure providers (existing validator operators with proven uptime), specialized AI infrastructure companies, and possibly academic groups studying agent systems.

### 3.2 The broadcast obligation

Operators participate in the validator network through a broadcast obligation embedded in their credentials. When a credential is issued through the v0.5 protocol, the credential carries a commitment: the operator agrees to broadcast all events related to this credential — issuance, action proof verifications, activity stream frames, heartbeats, revocations — to the validator network.

The broadcast is asynchronous. Validators do not sit in the path of action verification. An operator can verify proofs locally for low-latency authorization, then broadcast the event to validators within seconds. This preserves the latency profile that high-frequency agent operations require — a Polymarket trading bot doing 100 actions per second can't wait for validator round-trip on every action.

Enforcement happens through validator-side detection. Validators cross-reference broadcasts: if validator V1 sees Alice broadcasting action proofs but V2 does not, that's a signal that Alice is selectively hiding events. If Alice's broadcast frequency drops suddenly, that's a signal she's gone dark. Validators jointly detect these patterns and can revoke Alice's credentials at the protocol level — the credential becomes invalid in the validator network's view, and any insurer querying for the credential's status gets back "broadcast obligation violated, credential effectively revoked."

This is the core trade-off of v0.5's architecture: low latency at action time (validators are out of band), strong audit guarantees (validators reach consensus on what happened), economically-priced detection window (the small period between action and broadcast is insurable risk that insurers price into premiums). The alternative — validators in the path of every action — would provide stronger guarantees but would make Acreo unusable for high-frequency operations. Broadcast obligation is the right point on the curve for the agent economy as it actually exists.

### 3.3 Threshold attestation

When validators agree on an event, they collectively produce a threshold signature attesting to it. This is the core cryptographic primitive that makes the network's outputs trustworthy.

Attestation flow:

1. Operator broadcasts event E to all 21 validators
2. Each validator independently records E in their local audit log
3. After a short coordination window, validators exchange views of recent events (anti-equivocation protocol)
4. When 14+ validators agree they all received E with the same content, they each produce a partial signature on E
5. Partial signatures are aggregated into a single threshold signature
6. The threshold-signed E becomes the canonical record

Anyone with the validator network's public key (a single 32-byte value, regardless of validator count) can verify any threshold-signed attestation. They do not need to know which 14 validators signed; the threshold signature is indistinguishable from a signature by the network as a whole. This is the property FROST (the chosen scheme) provides.

### 3.4 The oracle query interface

Downstream consumers (insurers, auditors, reputation systems, dispute resolution services) interact with the validator network through a standardized query interface. This is the API that Hedgepoint integrates against in the worked example.

Queries are signed by the requester and threshold-signed by the validator network in response. Standard query types include:

- **Credential metadata**: scope, permissions, spend_limit, current state
- **Credential lifecycle**: issued at, state changes, revocation events
- **Action history**: action proof verifications between time T1 and T2 for a given credential
- **Activity stream segment**: chained frames with verifiable inclusion proofs
- **Aggregate behavioral statistics**: action frequency distribution, scope adherence rate, anomaly count over a time window
- **Broadcast compliance**: what fraction of expected events have been broadcast over the last N days
- **Historical state**: was credential C valid at timestamp T

Each query type returns a threshold-signed response that the consumer can verify independently. Consumers do not have to trust the API endpoint they hit — they trust the threshold signature on the response.

The query interface is the substrate on which insurance products, reputation systems, and dispute resolution services are built. Acreo does not ship those products; Acreo ships the queryable infrastructure they depend on.

### 3.5 What this looks like end-to-end

Putting it all together, here's the full lifecycle for a single agent action under v0.5:

1. Alice's bot generates an action proof locally
2. Alice's verifier signature-checks, replay-checks, scope-checks the proof
3. If valid, Alice's infrastructure executes the action (places the trade, calls the API, etc.)
4. In parallel, Alice broadcasts the action proof + activity stream frame to all 21 validators
5. Validators record the broadcast, coordinate, and produce a threshold-signed attestation
6. The attestation is added to the audit log, which is queryable by any downstream consumer

The total overhead added by v0.5 over v0.1: one async broadcast per action (roughly 1KB of network traffic) plus the validator-side coordination cost (amortized across all events). For an agent doing 100 actions per second, that's 100KB/s of broadcast traffic — trivial. For an agent doing 1 action per minute, the overhead is unmeasurable.

---

## 4. Cryptographic Primitive: FROST Threshold-Schnorr

The cryptographic core of v0.5 is FROST (Flexible Round-Optimized Schnorr Threshold signatures). FROST allows N parties to jointly produce signatures that verify against a single public key, requiring threshold T parties to cooperate on each signature. With N=21 and T=14, any 14 validators can jointly sign; no 13 can.

### 4.1 Why FROST

Three reasons FROST is the right choice for v0.5:

**Standard Schnorr signature output.** FROST produces signatures that are bit-identical to standard Schnorr signatures. Anyone who can verify Schnorr can verify FROST output. There is no special verification path for the consumer side — they treat the validator network as a single signer with a single public key. This dramatically simplifies the integration story for insurers, auditors, and other downstream consumers.

**Round-optimal protocol.** FROST signing requires only two rounds of communication between validators per signature. This is asymptotically as fast as threshold signing can be. The protocol has been analyzed and proven secure; multiple implementations exist.

**Active cryptographic ecosystem.** FROST has been adopted by the Bitcoin community (BIP 327), various blockchain projects, and is the subject of ongoing academic work. Implementations exist in Rust, Go, and (partially) Python. The cryptographic community has attacked it. We are building on a foundation that has been pressure-tested.

### 4.2 What FROST does not do

Honest about limitations:

**FROST is interactive.** Validators must coordinate on every signature. This is fine for the v0.5 use case (validator network is a small number of parties with high-availability infrastructure) but FROST is not suitable for use cases where signers are intermittently online or where the signing parties don't know each other in advance.

**FROST requires trusted setup of validator key shares.** The initial distributed key generation (DKG) phase is more complex than the signing phase and has more potential failure modes. Production DKG protocols exist (with security proofs) but the operational complexity is real.

**FROST is not post-quantum.** FROST builds on Schnorr signatures over elliptic curves, which are not quantum-resistant. A sufficiently powerful quantum computer would break the validator network's threshold signature scheme. This is a long-term concern (probably 10-20 years out for cryptographically relevant quantum computers) but it's worth flagging that v0.5's threshold scheme will need to migrate to a post-quantum threshold scheme eventually. Active research exists on lattice-based threshold signatures; we expect production-grade options in the 5-10 year timeframe.

**The pure-Python implementation gap.** No production-grade pure-Python FROST implementation exists at the time of this writing. v0.5 will likely need to integrate against a Rust library (probably `frost-ed25519` from the ZF FROST project) via FFI, or develop its own implementation. Either path is real work; the FFI path is faster but introduces a dependency on the Rust ecosystem.

### 4.3 Operator-blind credential verification

Beyond the validator threshold signing, v0.5 needs operator-blind credential verification — the ability for the validator network to verify that a credential is valid and an action proof is properly authorized, *without learning which specific credential is being used*. This is what closes Gap 5 from the problem statement.

The cryptographic technique here is more involved. The current best candidates are:

- **BBS+ signatures** with selective disclosure
- **Threshold-issued credentials** using Coconut or similar schemes
- **zk-SNARKs** proving credential validity without revealing the credential

Each has trade-offs in computational cost, signature size, and implementation maturity. The decision between them is deferred to Phase 3 of implementation; it will be made based on which scheme has production-grade implementations available at that time.

Important: operator-blind verification is essential for v0.5, not optional. The agent insurance market does not yet exist; we cannot predict whether early customers will be privacy-sensitive or privacy-indifferent. By building operator-blind verification as a first-class feature, v0.5 covers both halves of an unknown market. Excluding it would structurally lock out privacy-sensitive segments.

---

## 5. Audit Infrastructure

The validator network's job is not just to sign attestations — it's to maintain a tamper-evident, queryable, time-anchored audit log that supports adversarial verification of historical state.

### 5.1 The append-only log

Each validator maintains an append-only log of events. Events are added when:

- An operator broadcasts a credential issuance, action proof, activity frame, heartbeat, or revocation
- The validator network reaches threshold agreement on the event

The log is append-only at the protocol level. Existing entries are never modified. New entries are added with monotonically increasing sequence numbers and timestamps.

### 5.2 Time-anchored Merkle commitments

Every N seconds (concrete value to be tuned during Phase 1, likely between 1 and 60 seconds), validators jointly compute a Merkle root over the current state of the audit log and produce a threshold signature on it. This commitment serves as a time anchor: anyone can prove "this event was in the log at time T" by providing the event, the Merkle path, and the threshold-signed root from time T.

The commitment cadence is a real design trade-off:

- **More frequent commitments** (every second) → finer temporal granularity for queries, more validator coordination overhead
- **Less frequent commitments** (every minute) → coarser temporal granularity, lower overhead

The right cadence depends on the use case. For insurance claims, finer granularity is better (otherwise claim adjudication has to handle "what was the state between commitment times"). For reputation queries, coarser is fine. v0.5's design assumes 5-second commitments as the default, with the option to query against any cadence.

### 5.3 On-chain anchoring (optional)

For maximum tamper-resistance, the periodic Merkle commitments can be additionally anchored to a public blockchain (Bitcoin or Ethereum). Every N minutes, the validator network posts the latest Merkle root to the chain. This provides an external trust anchor: even if every single validator goes offline, the historical commitments remain verifiable through the blockchain's history.

Whether to do this is an operational decision rather than a fundamental architectural one. On-chain anchoring adds cost (gas fees) and operational complexity (requires running blockchain infrastructure) but it strengthens the trust story significantly. The recommendation is to add on-chain anchoring in Phase 2 or Phase 3, not as part of the MVP.

### 5.4 Storage model

For v0.5's MVP and Beta phases, validators store the full event payloads. This is operationally simplest but doesn't scale indefinitely — if the agent economy reaches the scale that the insurance thesis requires, validators would be storing terabytes of event data per year.

For Phase 3 and beyond, the storage model shifts: validators store hashes of event payloads, full payloads are stored externally (operator-side, with cryptographic guarantees that the operator preserves them). Validator queries return commitments and Merkle proofs; consumers fetch full payloads from the operator and verify against the commitments. This is similar to how Certificate Transparency handles certificate storage at scale.

### 5.5 Broadcast attestation

The broadcast obligation requires concrete enforcement. The mechanism:

- Each validator signs a periodic attestation listing the events they received from each operator over the last attestation window
- These attestations are aggregated; if validator V1's view of events from Alice diverges significantly from V2's view, that's evidence of selective broadcast
- After some grace period (to handle network partitions and other benign causes of divergence), persistent broadcast violations trigger automatic credential revocation

This is the mechanism by which "the operator can't selectively hide events" becomes operationally real, not just theoretical. The validator-side detection is what makes broadcast obligation enforceable.

---

## 6. Migration Path: v0.1 → v0.5

v0.5 is a substantial architectural change but it preserves backward compatibility with v0.1 deployments. Existing operators do not have to throw away their work.

### 6.1 Backward-compatible credential issuance

A v0.5-aware operator can still issue v0.1-style credentials that don't require the validator network. These credentials work exactly as they do today. They simply don't get the v0.5 benefits (distributed audit, insurance integration, reputation history).

A v0.5-aware operator can additionally issue v0.5-style credentials that include a broadcast obligation. These credentials register with the validator network at issuance time and require broadcast for all subsequent events.

The credential's wire format includes a `version` field and an optional `validator_network` field. v0.1 verifiers ignore unknown fields and process v0.5 credentials as plain v0.1 credentials (with reduced security properties). v0.5 verifiers use the additional fields to enforce broadcast obligations.

### 6.2 Verifier upgrade

Operators migrating from v0.1 to v0.5 perform the following changes:

1. Upgrade their `acreo` library to a v0.5-compatible version
2. Configure their verifier with the validator network's public key and endpoint addresses
3. Choose which credentials to migrate (or issue new credentials with broadcast obligation)
4. Optional: integrate with insurance partners that consume the validator network's query interface

Existing v0.1 credentials continue to function unchanged. The migration can be incremental — operators upgrade credentials one at a time as the use case warrants.

### 6.3 What does not migrate

Some v0.1 features stay v0.1-only:

- **In-memory audit logs** for non-broadcasted credentials. v0.5 doesn't try to retroactively apply distributed audit to events that happened before the broadcast obligation existed.
- **Operator-correlatable anonymous proofs** (Stage C-3) remain in v0.5 as a backward-compatibility feature, but new privacy-sensitive deployments use Phase 3's threshold-issued anonymous credentials instead.

The migration story is "v0.5 is additive, not replacing." Existing v0.1 functionality keeps working; v0.5 functionality is opt-in per credential.

---

## 7. Implementation Phases

**Phase 1 (MVP, 4-6 weeks)**: Single-machine reference implementation with N processes simulating N validators. Distributed audit network, time-anchored Merkle commitments, oracle query interface, claim schema. Demonstrates the architecture works without requiring threshold-credential cryptography. Insurance integration not yet possible — this is a research artifact proving the architecture is sound.

**Phase 2 (Beta, 8-12 weeks more)**: Multi-machine deployment of Phase 1. Real network coordination, validator hosts on different machines, deployment tooling, network failure handling, operational monitoring. Operationally real but trust property is theatrical until validators are run by independent parties. Insurance integration becomes possible: an insurer can query the network and adjudicate claims against the audit log, even though the validators are all run by Acreo or affiliated parties.

**Phase 3 (Production, multi-month)**: FROST threshold-Schnorr credentials plus independent validators. The cryptographic depth of operator-blind verification, plus the partnership work to get 5-15 independent parties running validators. Multi-month effort. After Phase 3, the trust property is real: no single party (including the Acreo team) can manipulate audit history.

Insurance integration is possible at Phase 2 but only with theatrical trust. Real trust — the kind that supports privacy-sensitive operators — requires Phase 3.

The phasing is deliberate: each phase ships a real artifact that has independent value. Phase 1 is a research artifact useful for academic review and proof-of-concept demos. Phase 2 is a usable system suitable for design partnerships with early insurers. Phase 3 is the production version.

---

## 8. Honest Limitations and Open Questions

The point of this section is to surface what's hand-waved, what needs cryptographer review, what's unknown, and what might require iteration. This section deliberately undersells; readers should treat optimistic claims elsewhere in the document with appropriate skepticism.

**Pure-Python FROST does not exist at production grade.** v0.5 will need to either build on Rust libraries via FFI (introducing a Rust dependency) or develop a constant-time, side-channel-resistant Python implementation (significant work). This is real engineering effort, not just glue code.

**The DKG (distributed key generation) phase is operationally complex.** Setting up the validator network's key shares requires a coordinated ceremony with all 21 validators. Failures during DKG can require restarting from scratch. Operational playbooks for DKG ceremonies are not yet well-developed in the broader ecosystem.

**Validator selection is partly a partnership problem, not a technical one.** Getting 21 independent parties to run validator software requires partnership work, legal agreements, and ongoing relationship management. This is not on the engineering critical path for Phase 1 or Phase 2 but it is the critical path for Phase 3 and beyond. The team building v0.5 needs to start partner conversations early.

**The economic model is not yet specified.** Validators get slashed for misbehavior, but where does the funding for validator operations come from? Three plausible answers — query fees from insurers, subscription fees from operators, a small transaction fee on protocol events — each have trade-offs. v0.5's design accommodates any of these but the choice of which to use is a strategic decision that affects who participates.

**Operator-blind verification has implementation maturity risk.** BBS+, Coconut, and zk-SNARK approaches all exist but no single approach has the combination of efficiency, security proofs, and pure-Python implementation that v0.5 ideally wants. Phase 3 will likely require evaluating multiple approaches and possibly developing new implementations.

**The insurance thesis might be wrong.** Section 1 asserts that the agent insurance market will materialize and v0.5's audit infrastructure will be the substrate. This is a real bet. If insurance never becomes the dominant pattern for handling agent risk — if smart contract escrow, self-insurance at scale, or platform-level guarantees become dominant instead — v0.5's audit infrastructure is still useful (it serves multiple downstream applications) but the killer-application story changes. The architecture is robust to this; the marketing story is not.

**Regulatory questions are unresolved.** Agent insurance products will face regulatory scrutiny in every jurisdiction they operate in. Whether the validator network's audit log meets evidence requirements for legal disputes, whether threshold signatures qualify as "official records" for various regulatory purposes, whether agents themselves can have legal standing — none of these questions have clear answers today. The audit infrastructure can produce evidence; the legal/regulatory framework that consumes it is being built in parallel by other parties.

**The activity stream's chain state is per-Identity-instance.** v0.1 of the activity stream primitive (Stage E) holds chain state in process memory. An operator running multiple processes with the same Identity will get multiple divergent chains. Persistent chain state across processes is a v0.5 implementation detail that's not specified in this document. The validator network's broadcast log effectively serves as the persistent state layer once v0.5 is deployed.

**The broadcast detection window is an insurance pricing concern, not a security boundary.** Selective broadcast attacks have a window between action and detection. Insurers price this window into premiums. If the broadcast detection algorithm has higher false-positive rates than estimated, premiums get more expensive. If it has higher false-negative rates than estimated, insurers take losses. Calibrating this in production will require iteration.

**This document does not specify protocol details at a level sufficient for direct implementation.** It is a design document, not a specification. Concrete details — exact wire formats, exact threshold parameters, exact DKG protocol — are deferred to implementation and will likely require revision as we encounter real implementation constraints. Treat this document as the architectural skeleton; the implementation will add flesh and possibly correct bones.

---

*End of design draft v1.*
