// SPDX-License-Identifier: Apache-2.0
// Test suite for IntentVerifiedPolicy (Acreo ASI01)
//
// Verifies every security claim in the contract:
//   - Strategy registration with valid categories
//   - Authorization of in-category actions
//   - Refusal of out-of-category actions (the core goal-hijack defense)
//   - Refusal of unauthorized agents
//   - Refusal of invalid signatures
//   - Refusal of replays
//   - Refusal of unknown strategies
//   - Registration safeguards (duplicates, zero values, etc.)

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("IntentVerifiedPolicy", function () {
    let policy;
    let operator;
    let agents;            // signer objects
    let agentAddresses;
    let strategyId;

    // Match the constants in the contract
    const CATEGORY_PLACE_ORDER = 1;
    const CATEGORY_CANCEL_ORDER = 2;
    const CATEGORY_UPDATE_LEVERAGE = 3;
    const CATEGORY_TRANSFER = 4;
    const CATEGORY_WITHDRAW = 5;
    const CATEGORY_APPROVE_AGENT = 6;

    /**
     * Helper: build and sign an IntentStatement
     */
    async function buildIntent(
        signer,
        strategyId,
        actionHash,
        category,
        parametersHash,
        signerAddress
    ) {
        const claimedAgent = signerAddress || signer.address;
        const messageHash = ethers.keccak256(
            ethers.solidityPacked(
                ["bytes32", "bytes32", "uint8", "bytes32", "address"],
                [strategyId, actionHash, category, parametersHash, claimedAgent]
            )
        );
        const signature = await signer.signMessage(ethers.getBytes(messageHash));
        return {
            strategyId,
            actionHash,
            intentCategory: category,
            parametersHash,
            agent: claimedAgent,
            signature,
        };
    }

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        operator = signers[0];
        agents = signers.slice(1, 4);  // 3 authorized agents
        agentAddresses = agents.map((a) => a.address);

        const Policy = await ethers.getContractFactory("IntentVerifiedPolicy");
        policy = await Policy.connect(operator).deploy();
        await policy.waitForDeployment();

        strategyId = ethers.keccak256(ethers.toUtf8Bytes("market-make-btc-perp"));
        const assetHash = ethers.keccak256(ethers.toUtf8Bytes("BTC,ETH"));

        // Register a strategy that allows place_order, cancel_order, update_leverage
        // — but NOT transfer or withdraw. Goal-hijack should hit this boundary.
        await policy.connect(operator).registerStrategy(
            strategyId,
            [CATEGORY_PLACE_ORDER, CATEGORY_CANCEL_ORDER, CATEGORY_UPDATE_LEVERAGE],
            assetHash,
            5000,                  // max 50% position
            agentAddresses
        );
    });

    // ── Happy path ────────────────────────────────────────────────────

    it("authorizes a place_order intent from an authorized agent", async function () {
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-1"));
        const paramsHash = ethers.keccak256(ethers.toUtf8Bytes("buy 0.1 BTC at 95000"));

        const intent = await buildIntent(
            agents[0], strategyId, actionHash, CATEGORY_PLACE_ORDER, paramsHash
        );

        const tx = await policy.verifyIntent(intent);
        const receipt = await tx.wait();

        const event = receipt.logs.find(
            (l) => l.fragment && l.fragment.name === "IntentVerified"
        );
        expect(event).to.not.be.undefined;
        expect(event.args.intentCategory).to.equal(CATEGORY_PLACE_ORDER);
        expect(event.args.agent).to.equal(agents[0].address);
        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    it("authorizes all in-category intents", async function () {
        const allowed = [
            CATEGORY_PLACE_ORDER,
            CATEGORY_CANCEL_ORDER,
            CATEGORY_UPDATE_LEVERAGE,
        ];
        for (let i = 0; i < allowed.length; i++) {
            const actionHash = ethers.keccak256(
                ethers.toUtf8Bytes(`action-multi-${i}`)
            );
            const paramsHash = ethers.keccak256(
                ethers.toUtf8Bytes(`params-${i}`)
            );
            const intent = await buildIntent(
                agents[0], strategyId, actionHash, allowed[i], paramsHash
            );
            await policy.verifyIntent(intent);
        }
    });

    // ── Core goal-hijack defense ──────────────────────────────────────

    it("REJECTS out-of-category intent (the goal-hijack defense)", async function () {
        // The strategy is market-make BTC perp. A goal hijack tries to
        // get the agent to withdraw funds — a category NOT in the
        // strategy's allowed list. This is the load-bearing test.
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("hijack-1"));
        const paramsHash = ethers.keccak256(
            ethers.toUtf8Bytes("withdraw 100 USDC to 0xattacker")
        );

        const intent = await buildIntent(
            agents[0], strategyId, actionHash, CATEGORY_WITHDRAW, paramsHash
        );

        await expect(policy.verifyIntent(intent)).to.be.revertedWith(
            "IVP: category not allowed"
        );
        expect(await policy.isActionConsumed(actionHash)).to.be.false;
    });

    it("REJECTS transfer intent when strategy doesn't allow it", async function () {
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("hijack-2"));
        const paramsHash = ethers.keccak256(ethers.toUtf8Bytes("transfer all funds"));

        const intent = await buildIntent(
            agents[0], strategyId, actionHash, CATEGORY_TRANSFER, paramsHash
        );

        await expect(policy.verifyIntent(intent)).to.be.revertedWith(
            "IVP: category not allowed"
        );
    });

    it("REJECTS approve_agent intent (persistence backdoor attempt)", async function () {
        // Classic persistence attack: hijacked agent tries to install another
        // agent. Strategy doesn't allow APPROVE_AGENT category — refused.
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("hijack-3"));
        const paramsHash = ethers.keccak256(
            ethers.toUtf8Bytes("approve attacker agent")
        );

        const intent = await buildIntent(
            agents[0], strategyId, actionHash, CATEGORY_APPROVE_AGENT, paramsHash
        );

        await expect(policy.verifyIntent(intent)).to.be.revertedWith(
            "IVP: category not allowed"
        );
    });

    // ── Authorization checks ──────────────────────────────────────────

    it("rejects intent from agent not in strategy's authorized list", async function () {
        const signers = await ethers.getSigners();
        const outsider = signers[9];
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-outsider"));
        const paramsHash = ethers.keccak256(ethers.toUtf8Bytes("params"));

        const intent = await buildIntent(
            outsider, strategyId, actionHash, CATEGORY_PLACE_ORDER, paramsHash
        );

        await expect(policy.verifyIntent(intent)).to.be.revertedWith(
            "IVP: agent not authorized"
        );
    });

    it("rejects intent for unknown strategy", async function () {
        const unknownStrategy = ethers.keccak256(ethers.toUtf8Bytes("unknown"));
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-unk"));
        const paramsHash = ethers.keccak256(ethers.toUtf8Bytes("params"));

        const intent = await buildIntent(
            agents[0], unknownStrategy, actionHash, CATEGORY_PLACE_ORDER, paramsHash
        );

        await expect(policy.verifyIntent(intent)).to.be.revertedWith(
            "IVP: unknown strategy"
        );
    });

    // ── Signature checks ──────────────────────────────────────────────

    it("rejects intent with signature from a different signer", async function () {
        // Authorized agent's address, but signed by someone else
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-badsig"));
        const paramsHash = ethers.keccak256(ethers.toUtf8Bytes("params"));

        // agents[1] signs but we claim it's from agents[0]
        const intent = await buildIntent(
            agents[1],                // actual signer
            strategyId,
            actionHash,
            CATEGORY_PLACE_ORDER,
            paramsHash,
            agents[0].address         // claimed agent
        );

        await expect(policy.verifyIntent(intent)).to.be.revertedWith(
            "IVP: bad sig"
        );
    });

    // ── Replay protection ─────────────────────────────────────────────

    it("rejects replay of same action hash", async function () {
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-replay"));
        const paramsHash = ethers.keccak256(ethers.toUtf8Bytes("params"));

        const intent = await buildIntent(
            agents[0], strategyId, actionHash, CATEGORY_PLACE_ORDER, paramsHash
        );

        await policy.verifyIntent(intent);

        // Same hash second time — refused
        await expect(policy.verifyIntent(intent)).to.be.revertedWith(
            "IVP: replay"
        );
    });

    // ── Registration safeguards ───────────────────────────────────────

    it("rejects registration with duplicate intent categories", async function () {
        const sId = ethers.keccak256(ethers.toUtf8Bytes("dup-cat"));
        const assetHash = ethers.keccak256(ethers.toUtf8Bytes("X"));
        await expect(
            policy.connect(operator).registerStrategy(
                sId,
                [CATEGORY_PLACE_ORDER, CATEGORY_PLACE_ORDER],
                assetHash, 5000, agentAddresses
            )
        ).to.be.revertedWith("IVP: dup category");
    });

    it("rejects registration with duplicate agent addresses", async function () {
        const sId = ethers.keccak256(ethers.toUtf8Bytes("dup-agent"));
        const assetHash = ethers.keccak256(ethers.toUtf8Bytes("X"));
        await expect(
            policy.connect(operator).registerStrategy(
                sId,
                [CATEGORY_PLACE_ORDER],
                assetHash, 5000,
                [agents[0].address, agents[0].address]
            )
        ).to.be.revertedWith("IVP: dup agent");
    });

    it("rejects registration with zero-value category", async function () {
        const sId = ethers.keccak256(ethers.toUtf8Bytes("zero-cat"));
        const assetHash = ethers.keccak256(ethers.toUtf8Bytes("X"));
        await expect(
            policy.connect(operator).registerStrategy(
                sId, [0, 1], assetHash, 5000, agentAddresses
            )
        ).to.be.revertedWith("IVP: zero category");
    });

    it("rejects registration with empty category list", async function () {
        const sId = ethers.keccak256(ethers.toUtf8Bytes("empty-cat"));
        const assetHash = ethers.keccak256(ethers.toUtf8Bytes("X"));
        await expect(
            policy.connect(operator).registerStrategy(
                sId, [], assetHash, 5000, agentAddresses
            )
        ).to.be.revertedWith("IVP: no categories");
    });

    it("rejects re-registration of same strategy ID", async function () {
        const assetHash = ethers.keccak256(ethers.toUtf8Bytes("X"));
        await expect(
            policy.connect(operator).registerStrategy(
                strategyId, [CATEGORY_PLACE_ORDER], assetHash, 5000, agentAddresses
            )
        ).to.be.revertedWith("IVP: strategy exists");
    });

    it("rejects registration with maxPositionPctBps > 10000", async function () {
        const sId = ethers.keccak256(ethers.toUtf8Bytes("bad-pct"));
        const assetHash = ethers.keccak256(ethers.toUtf8Bytes("X"));
        await expect(
            policy.connect(operator).registerStrategy(
                sId, [CATEGORY_PLACE_ORDER], assetHash, 10001, agentAddresses
            )
        ).to.be.revertedWith("IVP: bad position bps");
    });
});
