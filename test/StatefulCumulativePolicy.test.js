// SPDX-License-Identifier: Apache-2.0
// Test suite for StatefulCumulativePolicy (Acreo ASI02 v0.1)

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("StatefulCumulativePolicy", function () {
    let policy;
    let operator;
    let submitters;
    let submitterAddresses;
    let other;
    let strategyId;

    // Default config:
    //   12-minute window (60s buckets)
    //   signed value cap: 1000 (so cumulative net flow in [-1000, +1000])
    //   gross volume cap: 5000 (so cumulative |action| <= 5000)
    const WINDOW_SECONDS = 720;
    const BUCKET_DURATION = WINDOW_SECONDS / 12;  // 60 seconds
    const SIGNED_VALUE_CAP = 1000n;
    const GROSS_VOLUME_CAP = 5000n;

    function makeActionHash(label) {
        return ethers.keccak256(ethers.toUtf8Bytes(label));
    }

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        operator = signers[0];
        submitters = signers.slice(1, 4);
        submitterAddresses = submitters.map((s) => s.address);
        other = signers[9];

        const Policy = await ethers.getContractFactory("StatefulCumulativePolicy");
        policy = await Policy.connect(operator).deploy();
        await policy.waitForDeployment();

        strategyId = ethers.keccak256(ethers.toUtf8Bytes("strat-1"));

        await policy.connect(operator).registerStrategy(
            strategyId,
            WINDOW_SECONDS,
            SIGNED_VALUE_CAP,
            GROSS_VOLUME_CAP,
            submitterAddresses
        );

        // Align to a bucket boundary so rapid actions land in same bucket
        const now = await time.latest();
        const nextBucket = Math.ceil(now / BUCKET_DURATION) * BUCKET_DURATION;
        if (nextBucket > now) {
            await time.increaseTo(nextBucket + 1);
        }
    });

    // ── Happy path ────────────────────────────────────────────────────

    it("authorizes a single action within bounds", async function () {
        const actionHash = makeActionHash("a-1");
        await policy.connect(submitters[0]).authorize(strategyId, actionHash, 100);

        const [signed, gross] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(100n);
        expect(gross).to.equal(100n);
    });

    it("tracks cumulative signed value across multiple actions", async function () {
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("c-1"), 200);
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("c-2"), 300);
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("c-3"), -100);

        const [signed, gross] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(400n);  // 200 + 300 - 100
        expect(gross).to.equal(600n);   // |200| + |300| + |-100|
    });

    // ── Core defense: slow-drain attack ───────────────────────────────

    it("REJECTS slow-drain attack (many small outflows summing past cap)", async function () {
        // Cumulative signed cap is 1000. Attempt 12 outflows of -100 each.
        // After 10, cumulative = -1000 (at cap). 11th should fail.
        for (let i = 0; i < 10; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`drain-${i}`), -100
            );
        }

        const [signed,] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(-1000n);

        // 11th outflow would push to -1100, exceeding cap
        await expect(
            policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash("drain-11"), -100
            )
        ).to.be.revertedWith("SCP: signed cap exceeded");
    });

    // ── Core defense: position buildup attack ─────────────────────────

    it("REJECTS position buildup attack (incremental positive accumulation)", async function () {
        // Same shape on the positive side
        for (let i = 0; i < 10; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`build-${i}`), 100
            );
        }

        const [signed,] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(1000n);

        // 11th inflow would push to 1100, exceeding cap
        await expect(
            policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash("build-11"), 100
            )
        ).to.be.revertedWith("SCP: signed cap exceeded");
    });

    // ── Gross volume defense ──────────────────────────────────────────

    it("REJECTS high-churn attack (gross volume cap exceeded)", async function () {
        // Gross cap is 5000. Alternating +500 / -500 keeps signed value at 0
        // but accumulates gross. 10 actions = 5000 gross. 11th exceeds.
        for (let i = 0; i < 10; i++) {
            const value = i % 2 === 0 ? 500 : -500;
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`churn-${i}`), value
            );
        }

        const [signed, gross] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(0n);
        expect(gross).to.equal(5000n);

        await expect(
            policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash("churn-11"), 500
            )
        ).to.be.revertedWith("SCP: gross cap exceeded");
    });

    // ── Sliding window: old actions age out ───────────────────────────

    it("recovers capacity as old actions age out of the window", async function () {
        // Fill to cap
        for (let i = 0; i < 10; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`age-${i}`), 100
            );
        }

        // Wait past the full window so old bucket ages out
        await time.increase(WINDOW_SECONDS + 60);

        // Should be able to authorize again — old actions no longer counted
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("after-age"), 100
        );

        const [signed,] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(100n);
    });

    // ── Authorization checks ──────────────────────────────────────────

    it("rejects authorize from non-submitter", async function () {
        await expect(
            policy.connect(other).authorize(
                strategyId, makeActionHash("unauth-1"), 100
            )
        ).to.be.revertedWith("SCP: not authorized");
    });

    it("rejects authorize against unknown strategy", async function () {
        const unknownId = ethers.keccak256(ethers.toUtf8Bytes("unknown"));
        await expect(
            policy.connect(submitters[0]).authorize(
                unknownId, makeActionHash("ghost"), 100
            )
        ).to.be.revertedWith("SCP: unknown strategy");
    });

    // ── Replay protection ─────────────────────────────────────────────

    it("rejects replays of same action hash", async function () {
        const actionHash = makeActionHash("replay");
        await policy.connect(submitters[0]).authorize(strategyId, actionHash, 100);
        await expect(
            policy.connect(submitters[0]).authorize(strategyId, actionHash, 100)
        ).to.be.revertedWith("SCP: replay");
    });

    // ── Edge cases ────────────────────────────────────────────────────

    it("handles transition through zero (sign change)", async function () {
        // Build up positive, drain past zero, build negative
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("z-1"), 500);
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("z-2"), -800);

        const [signed,] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(-300n);
    });

    it("rejects action that would push exactly past signed cap", async function () {
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("b-1"), 900);
        // Now at +900 against cap of 1000. +101 would push to 1001 (over).
        await expect(
            policy.connect(submitters[0]).authorize(strategyId, makeActionHash("b-2"), 101)
        ).to.be.revertedWith("SCP: signed cap exceeded");
    });

    it("authorizes action that pushes exactly TO the signed cap", async function () {
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("e-1"), 900);
        // Now at +900. +100 pushes to exactly +1000 (at cap, allowed).
        await policy.connect(submitters[0]).authorize(strategyId, makeActionHash("e-2"), 100);
        const [signed,] = await policy.getCumulative(strategyId);
        expect(signed).to.equal(1000n);
    });

    // ── Registration safeguards ───────────────────────────────────────

    it("rejects registration with zero signed cap", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-sc"));
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, 0, GROSS_VOLUME_CAP, submitterAddresses)
        ).to.be.revertedWith("SCP: zero signed cap");
    });

    it("rejects registration with zero gross cap", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-gc"));
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, SIGNED_VALUE_CAP, 0, submitterAddresses)
        ).to.be.revertedWith("SCP: zero gross cap");
    });

    it("rejects registration with window not divisible by 12", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-w"));
        await expect(
            policy.registerStrategy(id, 121, SIGNED_VALUE_CAP, GROSS_VOLUME_CAP, submitterAddresses)
        ).to.be.revertedWith("SCP: window not divisible");
    });

    it("rejects registration with duplicate submitters", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("dup-sub"));
        await expect(
            policy.registerStrategy(
                id, WINDOW_SECONDS, SIGNED_VALUE_CAP, GROSS_VOLUME_CAP,
                [submitters[0].address, submitters[0].address]
            )
        ).to.be.revertedWith("SCP: dup submitter");
    });

    it("rejects re-registration of same strategy ID", async function () {
        await expect(
            policy.registerStrategy(
                strategyId, WINDOW_SECONDS, SIGNED_VALUE_CAP, GROSS_VOLUME_CAP, submitterAddresses
            )
        ).to.be.revertedWith("SCP: strategy exists");
    });

    it("rejects registration with zero-address submitter", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("zero-sub"));
        await expect(
            policy.registerStrategy(
                id, WINDOW_SECONDS, SIGNED_VALUE_CAP, GROSS_VOLUME_CAP,
                [submitters[0].address, ethers.ZeroAddress]
            )
        ).to.be.revertedWith("SCP: zero submitter");
    });

    it("rejects registration with empty submitter list", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("empty-sub"));
        await expect(
            policy.registerStrategy(
                id, WINDOW_SECONDS, SIGNED_VALUE_CAP, GROSS_VOLUME_CAP, []
            )
        ).to.be.revertedWith("SCP: no submitters");
    });
});
