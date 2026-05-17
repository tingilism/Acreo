// SPDX-License-Identifier: Apache-2.0
// Test suite for CrossPrincipalPolicy (Acreo ASI08 v0.1)

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("CrossPrincipalPolicy", function () {
    let policy;
    let operatorA;
    let operatorB;
    let other;
    let agentsA;
    let agentsB;
    let agentsAAddrs;
    let agentsBAddrs;
    let principalA;
    let principalB;
    let relationshipId;

    const CAT_PLACE_ORDER = 1;
    const CAT_CANCEL_ORDER = 2;
    const CAT_TRANSFER = 4;
    const CAT_WITHDRAW = 5;

    function makeActionHash(label) {
        return ethers.keccak256(ethers.toUtf8Bytes(label));
    }

    function makeHash(label) {
        return ethers.keccak256(ethers.toUtf8Bytes(label));
    }

    /**
     * Helper: sign a CrossAction message with one agent.
     */
    async function signAction(signer, relationshipId, actionHash, category, paramsHash, agentA, agentB) {
        const messageHash = ethers.keccak256(
            ethers.solidityPacked(
                ["bytes32", "bytes32", "uint8", "bytes32", "address", "address"],
                [relationshipId, actionHash, category, paramsHash, agentA, agentB]
            )
        );
        return await signer.signMessage(ethers.getBytes(messageHash));
    }

    async function buildAction(
        relationshipId, actionHash, category, paramsHash,
        agentASigner, agentBSigner,
        // optional overrides for testing bad-sig paths
        agentAClaimed, agentBClaimed
    ) {
        const aAddr = agentAClaimed || agentASigner.address;
        const bAddr = agentBClaimed || agentBSigner.address;
        const sigA = await signAction(
            agentASigner, relationshipId, actionHash, category, paramsHash, aAddr, bAddr
        );
        const sigB = await signAction(
            agentBSigner, relationshipId, actionHash, category, paramsHash, aAddr, bAddr
        );
        return {
            relationshipId,
            actionHash,
            category,
            parametersHash: paramsHash,
            agentA: aAddr,
            agentB: bAddr,
            signatureA: sigA,
            signatureB: sigB,
        };
    }

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        operatorA = signers[0];
        operatorB = signers[1];
        other = signers[2];
        agentsA = signers.slice(3, 5);   // 2 agents for principal A
        agentsB = signers.slice(5, 7);   // 2 agents for principal B
        agentsAAddrs = agentsA.map((a) => a.address);
        agentsBAddrs = agentsB.map((b) => b.address);

        const Policy = await ethers.getContractFactory("CrossPrincipalPolicy");
        policy = await Policy.connect(operatorA).deploy();
        await policy.waitForDeployment();

        // Use principal IDs that sort to A first
        principalA = makeHash("principal-aaa");  // hash starts low
        principalB = makeHash("principal-zzz");  // hash starts higher
        // Confirm sort order is what we expect
        if (BigInt(principalA) > BigInt(principalB)) {
            // swap so principalA actually sorts first
            const tmp = principalA;
            principalA = principalB;
            principalB = tmp;
        }

        // OperatorA registers — callerIsA path
        await policy.connect(operatorA).registerRelationship(
            principalA,                  // first arg (lower-sorted principal)
            principalB,                  // second arg
            operatorB.address,           // operatorOther
            agentsAAddrs,                // agents for caller side = A
            agentsBAddrs,                // agents for other side = B
            [CAT_PLACE_ORDER, CAT_CANCEL_ORDER, CAT_TRANSFER]
        );

        relationshipId = await policy.computeRelationshipId(principalA, principalB);
    });

    // ── Happy path ────────────────────────────────────────────────────

    it("authorizes a valid cross-principal action", async function () {
        const actionHash = makeActionHash("ca-1");
        const paramsHash = makeHash("params-1");
        const action = await buildAction(
            relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0], agentsB[0]
        );

        const tx = await policy.verifyCrossAction(action);
        const receipt = await tx.wait();

        const event = receipt.logs.find(
            (l) => l.fragment && l.fragment.name === "CrossActionAuthorized"
        );
        expect(event).to.not.be.undefined;
        expect(event.args.category).to.equal(CAT_PLACE_ORDER);
        expect(event.args.agentA).to.equal(agentsA[0].address);
        expect(event.args.agentB).to.equal(agentsB[0].address);
        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    it("can register relationship from either side and produce same ID", async function () {
        const Policy = await ethers.getContractFactory("CrossPrincipalPolicy");
        const policy2 = await Policy.connect(operatorB).deploy();
        await policy2.waitForDeployment();

        // OperatorB registers — pass principalB FIRST in the args, but the
        // sorting inside the contract should still produce the same relationshipId
        await policy2.connect(operatorB).registerRelationship(
            principalB,                  // caller's principal — but it sorts as B
            principalA,                  // other's principal — sorts as A
            operatorA.address,
            agentsBAddrs,                // caller side agents (B's)
            agentsAAddrs,                // other side agents (A's)
            [CAT_PLACE_ORDER, CAT_CANCEL_ORDER, CAT_TRANSFER]
        );

        const id1 = await policy.computeRelationshipId(principalA, principalB);
        const id2 = await policy2.computeRelationshipId(principalB, principalA);
        expect(id1).to.equal(id2);
    });

    // ── Core defense: dual-signature requirement ─────────────────────

    it("REJECTS action with invalid signature from agent A", async function () {
        // Sign A's slot with a different signer than claimed
        const actionHash = makeActionHash("badsig-a");
        const paramsHash = makeHash("p");
        const sigA = await signAction(
            agentsB[1], relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0].address, agentsB[0].address
        );
        const sigB = await signAction(
            agentsB[0], relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0].address, agentsB[0].address
        );
        const action = {
            relationshipId,
            actionHash,
            category: CAT_PLACE_ORDER,
            parametersHash: paramsHash,
            agentA: agentsA[0].address,
            agentB: agentsB[0].address,
            signatureA: sigA,
            signatureB: sigB,
        };

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: bad sig A");
    });

    it("REJECTS action with invalid signature from agent B", async function () {
        const actionHash = makeActionHash("badsig-b");
        const paramsHash = makeHash("p");
        const sigA = await signAction(
            agentsA[0], relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0].address, agentsB[0].address
        );
        const sigB = await signAction(
            agentsA[1], relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0].address, agentsB[0].address
        );
        const action = {
            relationshipId,
            actionHash,
            category: CAT_PLACE_ORDER,
            parametersHash: paramsHash,
            agentA: agentsA[0].address,
            agentB: agentsB[0].address,
            signatureA: sigA,
            signatureB: sigB,
        };

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: bad sig B");
    });

    // ── Authorization checks ──────────────────────────────────────────

    it("rejects action claiming an unauthorized agent for A", async function () {
        const actionHash = makeActionHash("unauth-a");
        const paramsHash = makeHash("p");
        const action = await buildAction(
            relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            other, agentsB[0]
        );

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: agent A not authorized");
    });

    it("rejects action claiming an unauthorized agent for B", async function () {
        const actionHash = makeActionHash("unauth-b");
        const paramsHash = makeHash("p");
        const action = await buildAction(
            relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0], other
        );

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: agent B not authorized");
    });

    it("rejects when same agent claimed on both sides", async function () {
        const actionHash = makeActionHash("same-agent");
        const paramsHash = makeHash("p");
        const action = await buildAction(
            relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0], agentsA[0]
        );

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: same agent both sides");
    });

    // ── Category enforcement ──────────────────────────────────────────

    it("REJECTS action with disallowed category (the confused-deputy defense)", async function () {
        // Strategy didn't whitelist WITHDRAW. Agent A or B can't trick
        // the other into authorizing a withdraw under this relationship.
        const actionHash = makeActionHash("bad-cat");
        const paramsHash = makeHash("withdraw-to-attacker");
        const action = await buildAction(
            relationshipId, actionHash, CAT_WITHDRAW, paramsHash,
            agentsA[0], agentsB[0]
        );

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: category not allowed");
    });

    // ── Unknown relationship ──────────────────────────────────────────

    it("rejects action for unknown relationship", async function () {
        const ghostId = makeHash("ghost-relationship");
        const actionHash = makeActionHash("ghost-action");
        const paramsHash = makeHash("p");
        const action = await buildAction(
            ghostId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0], agentsB[0]
        );

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: unknown relationship");
    });

    // ── Replay protection ─────────────────────────────────────────────

    it("rejects replays of same action hash", async function () {
        const actionHash = makeActionHash("replay-1");
        const paramsHash = makeHash("p");
        const action = await buildAction(
            relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0], agentsB[0]
        );

        await policy.verifyCrossAction(action);
        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: replay");
    });

    // ── Revocation ────────────────────────────────────────────────────

    it("operator A can revoke the relationship", async function () {
        await policy.connect(operatorA).revokeRelationship(relationshipId);
        const [, , , , , , , revoked] = await policy.getRelationship(relationshipId);
        expect(revoked).to.be.true;
    });

    it("operator B can revoke the relationship", async function () {
        await policy.connect(operatorB).revokeRelationship(relationshipId);
        const [, , , , , , , revoked] = await policy.getRelationship(relationshipId);
        expect(revoked).to.be.true;
    });

    it("non-operator cannot revoke", async function () {
        await expect(
            policy.connect(other).revokeRelationship(relationshipId)
        ).to.be.revertedWith("CPP: not operator");
    });

    it("revocation immediately blocks new cross-principal actions", async function () {
        await policy.connect(operatorA).revokeRelationship(relationshipId);

        const actionHash = makeActionHash("after-revoke");
        const paramsHash = makeHash("p");
        const action = await buildAction(
            relationshipId, actionHash, CAT_PLACE_ORDER, paramsHash,
            agentsA[0], agentsB[0]
        );

        await expect(
            policy.verifyCrossAction(action)
        ).to.be.revertedWith("CPP: revoked");
    });

    it("cannot revoke twice", async function () {
        await policy.connect(operatorA).revokeRelationship(relationshipId);
        await expect(
            policy.connect(operatorB).revokeRelationship(relationshipId)
        ).to.be.revertedWith("CPP: already revoked");
    });

    // ── Registration safeguards ───────────────────────────────────────

    it("rejects registration with same principal on both sides", async function () {
        await expect(
            policy.connect(other).registerRelationship(
                principalA, principalA, operatorB.address,
                agentsAAddrs, agentsBAddrs, [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: same principal");
    });

    it("rejects registration with caller as other operator", async function () {
        const fresh1 = makeHash("fresh-1");
        const fresh2 = makeHash("fresh-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, operatorA.address,    // caller = otherOperator
                agentsAAddrs, agentsBAddrs, [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: same operator");
    });

    // ── Finding N regression (Phase-2 seam test) ──────────────────────
    // A cross-principal dual-signature policy is only meaningful if the
    // two signing sides are independent. Before the fix, registerRelationship
    // accepted the same address on both agent lists, letting one attacker
    // domain satisfy the "dual" signature alone. Fix enforces address-level
    // disjointness of the two lists at registration.
    it("FINDING N: rejects registration where an agent appears on both sides", async function () {
        const fn1 = makeHash("finding-n-1");
        const fn2 = makeHash("finding-n-2");
        const shared = agentsAAddrs[0];
        await expect(
            policy.connect(operatorA).registerRelationship(
                fn1, fn2, operatorB.address,
                [shared],            // caller side
                [shared],            // other side — same address (collusion)
                [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: agent on both sides");
    });

    it("FINDING N: still allows registration with disjoint agent lists", async function () {
        const fn3 = makeHash("finding-n-3");
        const fn4 = makeHash("finding-n-4");
        // disjoint lists must still succeed (fix must not break legit use)
        await expect(
            policy.connect(operatorA).registerRelationship(
                fn3, fn4, operatorB.address,
                agentsAAddrs, agentsBAddrs, [CAT_PLACE_ORDER]
            )
        ).to.not.be.reverted;
    });

    it("rejects registration with zero other operator", async function () {
        const fresh1 = makeHash("zero-op-1");
        const fresh2 = makeHash("zero-op-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, ethers.ZeroAddress,
                agentsAAddrs, agentsBAddrs, [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: zero other operator");
    });

    it("rejects re-registration of same relationship", async function () {
        await expect(
            policy.connect(operatorA).registerRelationship(
                principalA, principalB, operatorB.address,
                agentsAAddrs, agentsBAddrs, [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: relationship exists");
    });

    it("rejects registration with empty categories", async function () {
        const fresh1 = makeHash("empty-cat-1");
        const fresh2 = makeHash("empty-cat-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, operatorB.address,
                agentsAAddrs, agentsBAddrs, []
            )
        ).to.be.revertedWith("CPP: no categories");
    });

    it("rejects registration with duplicate categories", async function () {
        const fresh1 = makeHash("dup-cat-1");
        const fresh2 = makeHash("dup-cat-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, operatorB.address,
                agentsAAddrs, agentsBAddrs,
                [CAT_PLACE_ORDER, CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: dup category");
    });

    it("rejects registration with zero-value category", async function () {
        const fresh1 = makeHash("zero-cat-1");
        const fresh2 = makeHash("zero-cat-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, operatorB.address,
                agentsAAddrs, agentsBAddrs, [0]
            )
        ).to.be.revertedWith("CPP: zero category");
    });

    it("rejects registration with empty caller-side agent list", async function () {
        const fresh1 = makeHash("empty-a-1");
        const fresh2 = makeHash("empty-a-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, operatorB.address,
                [], agentsBAddrs, [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: no caller agents");
    });

    it("rejects registration with empty other-side agent list", async function () {
        const fresh1 = makeHash("empty-b-1");
        const fresh2 = makeHash("empty-b-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, operatorB.address,
                agentsAAddrs, [], [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: no other agents");
    });

    it("rejects registration with duplicate caller-side agents", async function () {
        const fresh1 = makeHash("dup-ag-1");
        const fresh2 = makeHash("dup-ag-2");
        await expect(
            policy.connect(operatorA).registerRelationship(
                fresh1, fresh2, operatorB.address,
                [agentsA[0].address, agentsA[0].address],
                agentsBAddrs, [CAT_PLACE_ORDER]
            )
        ).to.be.revertedWith("CPP: dup agent");
    });
});
