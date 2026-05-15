// SPDX-License-Identifier: Apache-2.0
// Test suite for OracleConfirmedPolicy (Acreo ASI04)
//
// Updated after the internal adversarial audit. The audit found three real
// bugs in this contract (Findings J, K, L) and they have been fixed:
//
//   J — dataFeedId not pinned to the policy        -> expectedFeedId added
//   K — zero price -> division-by-zero grief        -> explicit zero guard
//   L — attestations replayable across actions      -> signed payload now
//        binds policyId + actionHash, so each attestation is single-use
//
// The signing format therefore changed. Each oracle now signs
//   keccak256(policyId, actionHash, dataFeedId, price, timestamp)
// instead of the old
//   keccak256(dataFeedId, price, timestamp)
//
// All existing tests are updated for the new format; four new tests at the
// end specifically prove J/K/L are fixed (and that the L fix does not break
// legitimate per-action signing).

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("OracleConfirmedPolicy", function () {
    let policy;
    let owner;
    let oracles;          // signer objects
    let oracleAddresses;  // their addresses
    let policyId;

    const FEED_BTC_USD = ethers.keccak256(ethers.toUtf8Bytes("BTC/USD"));
    const FEED_ETH_USD = ethers.keccak256(ethers.toUtf8Bytes("ETH/USD"));
    const PRICE_18_DEC = (n) => ethers.parseUnits(n.toString(), 18);

    /**
     * Helper: sign an oracle attestation in the format the fixed contract
     * expects. The payload now binds policyId + actionHash so a signature
     * cannot be replayed for a different action or under a different policy
     * (Finding L fix).
     */
    async function signAttestation(signer, policyId, actionHash, feedId, price, timestamp) {
        const dataHash = ethers.keccak256(
            ethers.solidityPacked(
                ["bytes32", "bytes32", "bytes32", "uint256", "uint256"],
                [policyId, actionHash, feedId, price, timestamp]
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

        // Register 5 oracles, threshold 3, tolerance 50 bps, max age 5 min,
        // pinned to the BTC/USD feed (expectedFeedId — Finding J fix).
        await policy.connect(owner).registerOracleSet(
            policyId,
            oracleAddresses,
            3,            // 3 of 5
            50,           // 0.5% max spread
            300,          // 5 minute max age
            FEED_BTC_USD  // pinned feed
        );
    });

    // ── Happy path ────────────────────────────────────────────────────

    it("authorizes when 3 oracles agree within tolerance", async function () {
        const now = await time.latest();
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-1"));
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

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

        // Need wider tolerance for 5-way spread (0.42% = 42 bps)
        const widePolicyId = ethers.keccak256(ethers.toUtf8Bytes("wide"));
        await policy.connect(owner).registerOracleSet(
            widePolicyId, oracleAddresses, 3, 100, 300, FEED_BTC_USD
        );

        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-median"));
        const attestations = await Promise.all(
            oracles.map((o, i) =>
                signAttestation(o, widePolicyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(prices[i]), now)
            )
        );

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
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-2"));
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
        ]);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: below threshold");
    });

    // ── Tolerance enforcement ─────────────────────────────────────────

    it("rejects when oracle spread exceeds tolerance", async function () {
        const now = await time.latest();
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-3"));
        // 1% spread; tolerance is 50 bps (0.5%)
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(96000), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95500), now),
        ]);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: tolerance exceeded");
    });

    // ── Staleness rejection ───────────────────────────────────────────

    it("rejects oracle data older than maxAgeSeconds", async function () {
        const now = await time.latest();
        const stale = now - 600;  // 10 min ago, max age is 5 min
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-4"));
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), stale),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: stale");
    });

    it("rejects future-dated oracle timestamps beyond clock skew tolerance", async function () {
        const now = await time.latest();
        const future = now + 120;  // 2 min in the future, tolerance is 60s
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-5"));
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), future),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: future");
    });

    // ── Unknown oracle rejection ──────────────────────────────────────

    it("rejects signatures from oracles not in the declared set", async function () {
        const now = await time.latest();
        const signers = await ethers.getSigners();
        const outsider = signers[9];  // not in oracle set
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-6"));

        const attestations = await Promise.all([
            signAttestation(outsider,  policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: unknown oracle");
    });

    // ── Bad signature rejection ───────────────────────────────────────

    it("rejects signatures that don't recover to the claimed oracle", async function () {
        const now = await time.latest();
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-7"));

        // Create a valid attestation, then claim it came from a different oracle
        const real = await signAttestation(
            oracles[3], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now
        );
        // Swap the oracle field to a different oracle — signature won't recover
        const tampered = { ...real, oracle: oracles[0].address };

        const attestations = [
            tampered,
            await signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            await signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ];

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: bad sig");
    });

    // ── Duplicate oracle rejection ────────────────────────────────────

    it("rejects when the same oracle signs twice in one submission", async function () {
        const now = await time.latest();
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-8"));
        const att1 = await signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now);
        const att2 = await signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now);
        const att3 = await signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, [att1, att2, att3])
        ).to.be.revertedWith("OCP: dup oracle in submission");
    });

    // ── Replay rejection (same action hash) ───────────────────────────

    it("rejects replays of the same action hash", async function () {
        const now = await time.latest();
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-9"));
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

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
            policy.connect(owner).registerOracleSet(dupId, dupSet, 2, 50, 300, FEED_BTC_USD)
        ).to.be.revertedWith("OCP: dup oracle");
    });

    it("rejects threshold > oracle count", async function () {
        const badId = ethers.keccak256(ethers.toUtf8Bytes("bad-t"));
        await expect(
            policy.connect(owner).registerOracleSet(
                badId, oracleAddresses, 6, 50, 300, FEED_BTC_USD  // 6-of-5, impossible
            )
        ).to.be.revertedWith("OCP: bad threshold");
    });

    it("rejects non-owner registration", async function () {
        const signers = await ethers.getSigners();
        const stranger = signers[8];
        const sId = ethers.keccak256(ethers.toUtf8Bytes("s"));
        await expect(
            policy.connect(stranger).registerOracleSet(
                sId, oracleAddresses, 3, 50, 300, FEED_BTC_USD
            )
        ).to.be.revertedWith("OCP: not owner");
    });

    it("rejects registration with a zero expectedFeedId", async function () {
        // Finding J fix also guards against an unpinned (zero) feed id.
        const zId = ethers.keccak256(ethers.toUtf8Bytes("zero-feed"));
        await expect(
            policy.connect(owner).registerOracleSet(
                zId, oracleAddresses, 3, 50, 300, ethers.ZeroHash
            )
        ).to.be.revertedWith("OCP: zero feed id");
    });

    // ══ Audit regression tests — Findings J, K, L ═════════════════════
    //
    // These tests are the receipts that the internal adversarial audit's
    // findings are actually fixed. Each reproduces the exploit the audit ran
    // against the vulnerable contract and confirms it is now blocked.

    // ── Finding J: dataFeedId not pinned to the policy ────────────────

    it("FINDING J: rejects an attestation for a different feed than the policy is pinned to", async function () {
        const now = await time.latest();
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-J"));

        // The policy is pinned to BTC/USD. The audit's exploit mixed in an
        // attestation for a *different* feed (ETH/USD) whose price happened
        // to land in the tolerance band, and the vulnerable contract accepted
        // the mixed set. Two BTC/USD + one ETH/USD, all prices close.
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_ETH_USD, PRICE_18_DEC(95050), now),
        ]);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: feed mismatch");
    });

    // ── Finding K: zero price -> division-by-zero grief ───────────────

    it("FINDING K: rejects a zero-price attestation with a clean error instead of an arithmetic panic", async function () {
        const now = await time.latest();
        const actionHash = ethers.keccak256(ethers.toUtf8Bytes("action-K"));

        // The audit's exploit: a single oracle submits price = 0. In the
        // vulnerable contract this made minPrice == 0 and the spread
        // computation divided by zero, reverting every authorization with
        // an arithmetic panic — a one-oracle denial of service. The fix
        // rejects it explicitly with "OCP: zero price".
        const attestations = await Promise.all([
            signAttestation(oracles[0], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(0), now),
            signAttestation(oracles[1], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionHash, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        await expect(
            policy.verifyAndAuthorize(policyId, actionHash, attestations)
        ).to.be.revertedWith("OCP: zero price");
    });

    // ── Finding L: attestations replayable across actions ─────────────

    it("FINDING L: rejects a set of attestations replayed for a different action", async function () {
        const now = await time.latest();

        // Authorize action-L1 with a valid set of attestations.
        const actionL1 = ethers.keccak256(ethers.toUtf8Bytes("action-L1"));
        const attsForL1 = await Promise.all([
            signAttestation(oracles[0], policyId, actionL1, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionL1, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionL1, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);
        await policy.verifyAndAuthorize(policyId, actionL1, attsForL1);

        // The audit's exploit: take that *same* signed set and replay it for
        // a different action. The vulnerable contract accepted it because the
        // signed payload did not include the actionHash — only the per-action
        // consumedActionHashes nonce changed. The fix binds the signature to
        // the actionHash, so the recovered signer no longer matches when the
        // attestations are presented under a different action.
        const actionL2 = ethers.keccak256(ethers.toUtf8Bytes("action-L2"));
        await expect(
            policy.verifyAndAuthorize(policyId, actionL2, attsForL1)
        ).to.be.revertedWith("OCP: bad sig");
    });

    // ── Finding L corollary: correctly re-signed attestations still work ──

    it("FINDING L: attestations correctly signed for the new action still authorize", async function () {
        const now = await time.latest();

        // Confirms the Finding L fix does not break legitimate per-action
        // signing — a fresh action with attestations actually signed for it
        // authorizes normally.
        const actionL3 = ethers.keccak256(ethers.toUtf8Bytes("action-L3"));
        const attsForL3 = await Promise.all([
            signAttestation(oracles[0], policyId, actionL3, FEED_BTC_USD, PRICE_18_DEC(95000), now),
            signAttestation(oracles[1], policyId, actionL3, FEED_BTC_USD, PRICE_18_DEC(95100), now),
            signAttestation(oracles[2], policyId, actionL3, FEED_BTC_USD, PRICE_18_DEC(95050), now),
        ]);

        const tx = await policy.verifyAndAuthorize(policyId, actionL3, attsForL3);
        const receipt = await tx.wait();
        const authEvent = receipt.logs.find(
            (l) => l.fragment && l.fragment.name === "ActionAuthorized"
        );
        expect(authEvent).to.not.be.undefined;
        expect(authEvent.args.medianPrice).to.equal(PRICE_18_DEC(95050));
    });
});

// Time helpers compatible with Hardhat
const time = {
    latest: async () => {
        const block = await ethers.provider.getBlock("latest");
        return block.timestamp;
    },
    increase: async (seconds) => {
        await ethers.provider.send("evm_increaseTime", [seconds]);
        await ethers.provider.send("evm_mine", []);
    },
};
