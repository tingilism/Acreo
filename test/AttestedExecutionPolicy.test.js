// SPDX-License-Identifier: Apache-2.0
// Test suite for AttestedExecutionPolicy (Acreo ASI06 v0.1)

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("AttestedExecutionPolicy", function () {
    let policy;
    let operator;
    let attestor;
    let badAttestor;
    let agents;
    let agentAddresses;
    let other;
    let strategyId;

    const ATTESTATION_VALIDITY_SECONDS = 300;  // 5 minutes
    const EXPECTED_MEASUREMENT = ethers.keccak256(
        ethers.toUtf8Bytes("agent-binary-v1.0.0-sha384")
    );
    const WRONG_MEASUREMENT = ethers.keccak256(
        ethers.toUtf8Bytes("agent-binary-v0.9.9-tampered")
    );

    function makeActionHash(label) {
        return ethers.keccak256(ethers.toUtf8Bytes(label));
    }

    /**
     * Helper: build and sign an AttestationStatement.
     *
     * Finding M fix: the attestor now signs over actionHash too, so an
     * attestation is cryptographically bound to one specific action and
     * cannot be replayed across different actions within the validity
     * window. Signed payload:
     *   (strategyId, actionHash, agent, measurement, timestamp)
     */
    async function buildAttestation(
        signer,
        strategyId,
        actionHash,
        agent,
        measurement,
        timestamp
    ) {
        const messageHash = ethers.keccak256(
            ethers.solidityPacked(
                ["bytes32", "bytes32", "address", "bytes32", "uint256"],
                [strategyId, actionHash, agent, measurement, timestamp]
            )
        );
        const signature = await signer.signMessage(ethers.getBytes(messageHash));
        return {
            strategyId,
            agent,
            measurement,
            timestamp,
            attestorSignature: signature,
        };
    }

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        operator = signers[0];
        attestor = signers[1];
        badAttestor = signers[2];
        agents = signers.slice(3, 6);  // 3 authorized agents
        agentAddresses = agents.map((a) => a.address);
        other = signers[9];

        const Policy = await ethers.getContractFactory("AttestedExecutionPolicy");
        policy = await Policy.connect(operator).deploy();
        await policy.waitForDeployment();

        strategyId = ethers.keccak256(ethers.toUtf8Bytes("strat-attested"));

        await policy.connect(operator).registerStrategy(
            strategyId,
            attestor.address,
            EXPECTED_MEASUREMENT,
            ATTESTATION_VALIDITY_SECONDS,
            agentAddresses
        );
    });

    // ── Happy path ────────────────────────────────────────────────────

    it("authorizes a valid attested action", async function () {
        const now = await time.latest();
        const actionHash = makeActionHash("attested-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        const tx = await policy.connect(agents[0]).verifyAttestation(
            actionHash, attestation
        );
        const receipt = await tx.wait();

        const event = receipt.logs.find(
            (l) => l.fragment && l.fragment.name === "ActionAuthorized"
        );
        expect(event).to.not.be.undefined;
        expect(event.args.measurement).to.equal(EXPECTED_MEASUREMENT);
        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    // ── Core defense: measurement mismatch ────────────────────────────

    it("REJECTS attestation with mismatched measurement (the supply chain defense)", async function () {
        // Attacker has tampered the agent binary. The attestor — if it's
        // honest — produces an attestation with the new (wrong) measurement.
        // Acreo refuses because the measurement doesn't match the operator's
        // expected.
        const now = await time.latest();
        const actionHash = makeActionHash("tampered-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, WRONG_MEASUREMENT, now
        );

        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: measurement mismatch");
    });

    // ── Attestor signature checks ─────────────────────────────────────

    it("rejects attestation signed by non-attestor", async function () {
        const now = await time.latest();
        const actionHash = makeActionHash("bad-attestor-1");
        const attestation = await buildAttestation(
            badAttestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: bad attestor sig");
    });

    // ── Time-bound checks ─────────────────────────────────────────────

    it("rejects expired attestation", async function () {
        const now = await time.latest();
        // Attestation timestamp from before the validity window
        const oldTime = now - ATTESTATION_VALIDITY_SECONDS - 60;
        const actionHash = makeActionHash("expired-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, oldTime
        );

        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: attestation expired");
    });

    it("rejects future-dated attestation beyond clock skew tolerance", async function () {
        const now = await time.latest();
        // Timestamp far in the future
        const futureTime = now + 120;
        const actionHash = makeActionHash("future-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, futureTime
        );

        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: attestation future");
    });

    // ── Agent identity checks ─────────────────────────────────────────

    it("rejects attestation for an unauthorized agent", async function () {
        const now = await time.latest();
        const actionHash = makeActionHash("unauth-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, other.address, EXPECTED_MEASUREMENT, now
        );

        await expect(
            policy.connect(other).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: agent not authorized");
    });

    it("rejects when sender doesn't match attestation's claimed agent", async function () {
        // The attestation is for agents[0] but agents[1] is submitting
        const now = await time.latest();
        const actionHash = makeActionHash("mismatch-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        await expect(
            policy.connect(agents[1]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: agent mismatch");
    });

    // ── Unknown strategy ──────────────────────────────────────────────

    it("rejects attestation for unknown strategy", async function () {
        const now = await time.latest();
        const unknownId = ethers.keccak256(ethers.toUtf8Bytes("ghost"));
        const actionHash = makeActionHash("ghost-1");
        const attestation = await buildAttestation(
            attestor, unknownId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: unknown strategy");
    });

    // ── Replay protection ─────────────────────────────────────────────

    it("rejects replays of same action hash", async function () {
        const now = await time.latest();
        const actionHash = makeActionHash("replay-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        await policy.connect(agents[0]).verifyAttestation(actionHash, attestation);

        // Second time fails
        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: replay");
    });

    // ── Finding M regression — cross-action attestation replay ────────
    //
    // Surfaced by the Phase-1 integrity sandbox (self-asserted-trust
    // class) and confirmed in source: before the fix, the attestor
    // signed (strategyId, agent, measurement, timestamp) WITHOUT
    // actionHash, so one valid attestation authorized ANY action within
    // the validity window. The per-actionHash replay check did not bind
    // the attestation to the action. Fix: actionHash is now in the
    // signed payload (same shape as ASI04 Finding L).

    it("FINDING M: an attestation issued for one action cannot authorize a different action", async function () {
        const now = await time.latest();

        // Attestor legitimately attests action M1.
        const actionM1 = makeActionHash("M-action-1");
        const attForM1 = await buildAttestation(
            attestor, strategyId, actionM1, agents[0].address, EXPECTED_MEASUREMENT, now
        );
        await policy.connect(agents[0]).verifyAttestation(actionM1, attForM1);

        // The agent replays the SAME attestor signature for a different
        // action M2. Pre-fix this passed (signature didn't bind the
        // action). Post-fix the recovered signer no longer matches because
        // actionHash is part of the signed payload.
        const actionM2 = makeActionHash("M-action-2");
        await expect(
            policy.connect(agents[0]).verifyAttestation(actionM2, attForM1)
        ).to.be.revertedWith("AEP: bad attestor sig");
    });

    it("FINDING M: an attestation correctly signed for the new action still authorizes", async function () {
        const now = await time.latest();
        // Confirms the fix doesn't break legitimate per-action attestation.
        const actionM3 = makeActionHash("M-action-3");
        const attForM3 = await buildAttestation(
            attestor, strategyId, actionM3, agents[0].address, EXPECTED_MEASUREMENT, now
        );
        const tx = await policy.connect(agents[0]).verifyAttestation(actionM3, attForM3);
        const receipt = await tx.wait();
        const event = receipt.logs.find(
            (l) => l.fragment && l.fragment.name === "ActionAuthorized"
        );
        expect(event).to.not.be.undefined;
    });

    // ── Attestor rotation ─────────────────────────────────────────────

    it("operator can rotate the attestor", async function () {
        await policy.connect(operator).rotateAttestor(strategyId, badAttestor.address);

        // Attestations from the new attestor should now be valid
        const now = await time.latest();
        const actionHash = makeActionHash("rotated-1");
        const attestation = await buildAttestation(
            badAttestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        await policy.connect(agents[0]).verifyAttestation(actionHash, attestation);
        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    it("rotation invalidates old attestor's signatures", async function () {
        await policy.connect(operator).rotateAttestor(strategyId, badAttestor.address);

        // Attestation from old attestor should now fail
        const now = await time.latest();
        const actionHash = makeActionHash("after-rot-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: bad attestor sig");
    });

    it("non-operator cannot rotate attestor", async function () {
        await expect(
            policy.connect(other).rotateAttestor(strategyId, badAttestor.address)
        ).to.be.revertedWith("AEP: not operator");
    });

    it("rejects rotation to zero address", async function () {
        await expect(
            policy.connect(operator).rotateAttestor(strategyId, ethers.ZeroAddress)
        ).to.be.revertedWith("AEP: zero attestor");
    });

    it("rejects rotation to same attestor", async function () {
        await expect(
            policy.connect(operator).rotateAttestor(strategyId, attestor.address)
        ).to.be.revertedWith("AEP: same attestor");
    });

    // ── Measurement update ────────────────────────────────────────────

    it("operator can update expected measurement", async function () {
        const NEW_MEASUREMENT = ethers.keccak256(
            ethers.toUtf8Bytes("agent-binary-v1.1.0")
        );
        await policy.connect(operator).updateMeasurement(strategyId, NEW_MEASUREMENT);

        // Attestations with new measurement should pass
        const now = await time.latest();
        const actionHash = makeActionHash("new-meas-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, NEW_MEASUREMENT, now
        );

        await policy.connect(agents[0]).verifyAttestation(actionHash, attestation);
        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    it("measurement update invalidates attestations with old measurement", async function () {
        const NEW_MEASUREMENT = ethers.keccak256(
            ethers.toUtf8Bytes("agent-binary-v1.1.0")
        );
        await policy.connect(operator).updateMeasurement(strategyId, NEW_MEASUREMENT);

        // Attestation with OLD measurement should fail
        const now = await time.latest();
        const actionHash = makeActionHash("old-meas-1");
        const attestation = await buildAttestation(
            attestor, strategyId, actionHash, agents[0].address, EXPECTED_MEASUREMENT, now
        );

        await expect(
            policy.connect(agents[0]).verifyAttestation(actionHash, attestation)
        ).to.be.revertedWith("AEP: measurement mismatch");
    });

    // ── Registration safeguards ───────────────────────────────────────

    it("rejects registration with zero attestor", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-att"));
        await expect(
            policy.registerStrategy(
                id, ethers.ZeroAddress, EXPECTED_MEASUREMENT,
                ATTESTATION_VALIDITY_SECONDS, agentAddresses
            )
        ).to.be.revertedWith("AEP: zero attestor");
    });

    it("rejects registration with zero measurement", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-meas"));
        await expect(
            policy.registerStrategy(
                id, attestor.address, ethers.ZeroHash,
                ATTESTATION_VALIDITY_SECONDS, agentAddresses
            )
        ).to.be.revertedWith("AEP: zero measurement");
    });

    it("rejects registration with validity too short", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-val"));
        await expect(
            policy.registerStrategy(
                id, attestor.address, EXPECTED_MEASUREMENT, 10, agentAddresses
            )
        ).to.be.revertedWith("AEP: validity too short");
    });

    it("rejects registration with validity too long", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-long"));
        await expect(
            policy.registerStrategy(
                id, attestor.address, EXPECTED_MEASUREMENT, 7200, agentAddresses
            )
        ).to.be.revertedWith("AEP: validity too long");
    });

    it("rejects registration with duplicate agents", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("dup-agent"));
        await expect(
            policy.registerStrategy(
                id, attestor.address, EXPECTED_MEASUREMENT,
                ATTESTATION_VALIDITY_SECONDS,
                [agents[0].address, agents[0].address]
            )
        ).to.be.revertedWith("AEP: dup agent");
    });

    it("rejects re-registration of same strategy ID", async function () {
        await expect(
            policy.registerStrategy(
                strategyId, attestor.address, EXPECTED_MEASUREMENT,
                ATTESTATION_VALIDITY_SECONDS, agentAddresses
            )
        ).to.be.revertedWith("AEP: strategy exists");
    });
});
