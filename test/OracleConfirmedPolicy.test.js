// SPDX-License-Identifier: Apache-2.0
// Test suite for OracleConfirmedPolicy
//
// Verifies every security claim in the contract:
//   - Threshold enforcement (n-of-m)
//   - Tolerance enforcement (spread bound)
//   - Stale data rejection
//   - Future-dated rejection
//   - Unknown oracle rejection
//   - Duplicate signature rejection
//   - Replay rejection
//   - Successful authorization on valid input
//   - Median computation correctness
//
// Run with: npx hardhat test

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("OracleConfirmedPolicy", function () {
    let policy;
    let owner;
    let oracles;          // signer objects
    let oracleAddresses;  // their addresses
    let policyId;

    const FEED_BTC_USD = ethers.keccak256(ethers.toUtf8Bytes("BTC/USD"));
    const PRICE_18_DEC = (n) => ethers.parseUnits(n.toString(), 18);

    /**
     * Helper: sign an oracle attestation in the format the contract expects.
     */
    async function signAttestation(signer, feedId, price, timestamp) {
        const dataHash = ethers.keccak256(
            ethers.solidityPacked(
                ["bytes32", "uint256", "uint256"],
                [feedId, price, timestamp]
            )
        );
        // signMessage adds the "\x19Ethereum Signed Message:\n32" prefix
        const signature = await signer.signMessage(ethers.getBytes(dataHash));
        return {
            oracle: signer.address,
            dataFeedId: feedId,
            price: price,
            timestamp: timestamp,
            signature: signature,
        };
    }

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        owner = signers[0];
        oracles = signers.slice(1, 6);  // 5 oracles
        oracleAddresses = oracles.map((o) => o.address);

        const Policy = await ethers.getContractFactory("OracleConfirmedPolicy");
        policy = await Policy.connect(owner).deploy();
        await policy.waitForDeployment();

        policyId = ethers.keccak256(ethers.toUtf8Bytes("btc-strategy-v1"));

        // Register 5 oracles, threshold 3, tolerance 50 bps, max age 5 min
        await policy.connect(owner).registerOracleSet(
            policyId,
            oracleAddresses,
            3,            // 3 of 5
            50,           // 0.5% max spread
            300           // 5 minute max age
        );
    });

    // ── Happy path ────────────────────────────────────────────────────

    it("authorizes when 3 oracles agree within tolerance", async function () {
        const now = await time.latest();
        const attestations = await Promise.all([
            signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-1"));
        const tx = await policy.verifyAndAuthorize(policyId, actionHash, attestations);
        const receipt = await tx.wait();

        // Expect ActionAuthorized event with median = 95050
        const authEvent = receipt.logs.find(
            (l) => l.fragment && l.fragment.name === "ActionAuthorized"
        );
        expect(authEvent).to.not.be.undefined;
        expect(authEvent.args.medianPrice).to.equal(PRICE_18_DEC(95050));
        expect(authEvent.args.confirmingOracles).to.equal(3);

        // Action hash should now be consumed
        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    it("computes correct median for 5 oracle confirmations", async function () {
        const now = await time.latest();
        const prices = [95000, 95100, 95200, 95300, 95400];
        const attestations = await Promise.all(
            oracles.map((o, i) =>
                signAttestation(o, FEED_BTC_USD, PRICE_18_DEC(prices[i]), now)
            )
        );

        // Need wider tolerance for 5-way spread (0.42% = 42 bps)
        const widePolicyId = ethers.keccak256(ethers.toUtf8Bytes("wide"));
        await policy.connect(owner).registerOracleSet(
            widePolicyId, oracleAddresses, 3, 100, 300
        );

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-median"));
        const tx = await policy.verifyAndAuthorize(widePolicyId, actionHash, attestations);
        const receipt = await tx.wait();

        const authEvent = receipt.logs.find(
            (l) => l.fragment && l.fragment.name === "ActionAuthorized"
        );
        expect(authEvent.args.medianPrice).to.equal(PRICE_18_DEC(95200));
    });

    // ── Threshold enforcement ─────────────────────────────────────────

    it("rejects when fewer than threshold oracles attest", async function () {
        const now = await time.latest();
        const attestations = await Promise.all([
            signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95100), now),
        ]);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-2"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: below threshold");
    });

    // ── Tolerance enforcement ─────────────────────────────────────────

    it("rejects when oracle spread exceeds tolerance", async function () {
        const now = await time.latest();
        // 1% spread; tolerance is 50 bps (0.5%)
        const attestations = await Promise.all([
            signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(96000), now),
            signAttestation(oracles[2], FEED_BTC_USD, PRICE_18_DEC(95500), now),
        ]);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-3"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: tolerance exceeded");
    });

    // ── Staleness rejection ───────────────────────────────────────────

    it("rejects oracle data older than maxAgeSeconds", async function () {
        const now = await time.latest();
        const stale = now - 600;  // 10 min ago, max age is 5 min
        const attestations = await Promise.all([
            signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95000), stale),
            signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-4"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: stale");
    });

    it("rejects future-dated oracle timestamps beyond clock skew tolerance", async function () {
        const now = await time.latest();
        const future = now + 120;  // 2 min in the future, tolerance is 60s
        const attestations = await Promise.all([
            signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95000), future),
            signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-5"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: future");
    });

    // ── Unknown oracle rejection ──────────────────────────────────────

    it("rejects signatures from oracles not in the declared set", async function () {
        const now = await time.latest();
        const signers = await ethers.getSigners();
        const outsider = signers[9];  // not in oracle set

        const attestations = await Promise.all([
            signAttestation(outsider,  FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-6"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: unknown oracle");
    });

    // ── Bad signature rejection ───────────────────────────────────────

    it("rejects signatures that don't recover to the claimed oracle", async function () {
        const now = await time.latest();

        // Create a valid attestation, then claim it came from a different oracle
        const real = await signAttestation(
            oracles[3], FEED_BTC_USD, PRICE_18_DEC(95000), now
        );
        // Swap the oracle field to a different oracle — signature won't recover
        const tampered = { ...real, oracle: oracles[0].address };

        const attestations = [
            tampered,
            await signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95100), now),
            await signAttestation(oracles[2], FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ];

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-7"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: bad sig");
    });

    // ── Duplicate oracle rejection ────────────────────────────────────

    it("rejects when the same oracle signs twice in one submission", async function () {
        const now = await time.latest();
        const att1 = await signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95000), now);
        const att2 = await signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95100), now);
        const att3 = await signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95050), now);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-8"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, [att1, att2, att3])
        ).to.be.revertedWith("OCP: dup oracle in submission");
    });

    // ── Replay rejection ──────────────────────────────────────────────

    it("rejects replays of the same action hash", async function () {
        const now = await time.latest();
        const attestations = await Promise.all([
            signAttestation(oracles[0], FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-9"));
        await policy.verifyAndAuthorize(policyId, actionHash, attestations);

        // Same hash, same data — should fail as replay
        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: replay");
    });

    // ── Registration safeguards ───────────────────────────────────────

    it("rejects duplicate oracle addresses at registration", async function () {
        const dupId = ethers.keccak256(ethers.toUtf8Bytes("dup"));
        const dupSet = [oracleAddresses[0], oracleAddresses[1], oracleAddresses[0]];
        await expect(
            policy.connect(owner).registerOracleSet(dupId, dupSet, 2, 50, 300)
        ).to.be.revertedWith("OCP: dup oracle");
    });

    it("rejects threshold > oracle count", async function () {
        const badId = ethers.keccak256(ethers.toUtf8Bytes("bad-t"));
        await expect(
            policy.connect(owner).registerOracleSet(
                badId, oracleAddresses, 6, 50, 300  // 6-of-5, impossible
            )
        ).to.be.revertedWith("OCP: bad threshold");
    });

    it("rejects non-owner registration", async function () {
        const signers = await ethers.getSigners();
        const stranger = signers[8];
        const sId = ethers.keccak256(ethers.toUtf8Bytes("s"));
        await expect(
            policy.connect(stranger).registerOracleSet(
                sId, oracleAddresses, 3, 50, 300
            )
        ).to.be.revertedWith("OCP: not owner");
    });
});

// Time helpers compatible with Hardhat
const time = {
    latest: async () => {
        const block = await ethers.provider.getBlock("latest");
        return block.timestamp;
    },
};
