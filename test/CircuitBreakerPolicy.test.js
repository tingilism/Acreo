// SPDX-License-Identifier: Apache-2.0
// Test suite for CircuitBreakerPolicy (Acreo ASI07)

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("CircuitBreakerPolicy", function () {
    let policy;
    let operator;
    let other;
    let breakerId;

    // Default config: 12-minute window (60s buckets), trip at 10/window or 3/bucket,
    // cooldown 60 seconds
    const WINDOW_SECONDS = 720;     // 12 minutes
    const RATE_THRESHOLD = 10;
    const BURST_THRESHOLD = 3;
    const COOLDOWN_SECONDS = 60;
    const BUCKET_DURATION = WINDOW_SECONDS / 12;  // 60 seconds

    // State enum mirroring contract
    const STATE_NORMAL = 0;
    const STATE_TRIPPED = 1;
    const STATE_COOLDOWN = 2;

    async function signOverride(signer, breakerId, actionHash) {
        const messageHash = ethers.keccak256(
            ethers.solidityPacked(
                ["bytes32", "bytes32"],
                [breakerId, actionHash]
            )
        );
        return await signer.signMessage(ethers.getBytes(messageHash));
    }

    function makeActionHash(label) {
        return ethers.keccak256(ethers.toUtf8Bytes(label));
    }

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        operator = signers[0];
        other = signers[1];

        const Policy = await ethers.getContractFactory("CircuitBreakerPolicy");
        policy = await Policy.connect(operator).deploy();
        await policy.waitForDeployment();

        breakerId = ethers.keccak256(ethers.toUtf8Bytes("test-breaker"));

        await policy.connect(operator).registerBreaker(
            breakerId,
            WINDOW_SECONDS,
            RATE_THRESHOLD,
            BURST_THRESHOLD,
            COOLDOWN_SECONDS
        );

        // Align to a bucket boundary so a few rapid calls don't span buckets.
        // We advance to the start of the next bucket + a few seconds of headroom.
        const now = await time.latest();
        const nextBucket = Math.ceil(now / BUCKET_DURATION) * BUCKET_DURATION;
        if (nextBucket > now) {
            await time.increaseTo(nextBucket + 1);
        }
    });

    // ── Happy path ────────────────────────────────────────────────────

    it("allows authorization in NORMAL state", async function () {
        const actionHash = makeActionHash("action-1");
        await policy.authorize(breakerId, actionHash);

        const [state, , rate] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_NORMAL);
        expect(rate).to.equal(1);
        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    it("allows multiple authorizations within thresholds", async function () {
        // Send BURST_THRESHOLD authorizations — should all pass (boundary is >)
        for (let i = 0; i < BURST_THRESHOLD; i++) {
            await policy.authorize(breakerId, makeActionHash(`action-${i}`));
        }
        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_NORMAL);
    });

    // ── Burst threshold ───────────────────────────────────────────────

    it("trips when burst threshold exceeded in single bucket", async function () {
        // Fill up to burst threshold (allowed)
        for (let i = 0; i < BURST_THRESHOLD; i++) {
            await policy.authorize(breakerId, makeActionHash(`burst-${i}`));
        }
        // The next one crosses the burst threshold — it succeeds AND trips the breaker
        await policy.authorize(breakerId, makeActionHash("burst-trip"));

        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_TRIPPED);

        // The action AFTER the trip is the one that gets refused
        await expect(
            policy.authorize(breakerId, makeActionHash("after-burst"))
        ).to.be.revertedWith("CB: tripped");
    });

    // ── Rate threshold ────────────────────────────────────────────────

    it("trips when rate threshold exceeded across window", async function () {
        // Need to exceed rate threshold (10) WITHOUT exceeding burst (3)
        // Strategy: place BURST_THRESHOLD actions per bucket, advance time
        let tripped = false;
        for (let bucket = 0; bucket < 5 && !tripped; bucket++) {
            for (let i = 0; i < BURST_THRESHOLD && !tripped; i++) {
                await policy.authorize(
                    breakerId,
                    makeActionHash(`rate-${bucket}-${i}`)
                );
                const [state, ,] = await policy.getState(breakerId);
                if (state === BigInt(STATE_TRIPPED) || state === STATE_TRIPPED) {
                    tripped = true;
                }
            }
            if (!tripped) {
                await time.increase(BUCKET_DURATION + 1);
            }
        }
        expect(tripped).to.be.true;

        // Confirm subsequent actions refused
        await expect(
            policy.authorize(breakerId, makeActionHash("after-rate"))
        ).to.be.revertedWith("CB: tripped");
    });

    // ── Tripped state ─────────────────────────────────────────────────

    it("refuses authorize() when in TRIPPED state", async function () {
        // Trip the breaker (the threshold-crossing action succeeds)
        for (let i = 0; i < BURST_THRESHOLD + 1; i++) {
            await policy.authorize(breakerId, makeActionHash(`t-${i}`));
        }

        // State should now be TRIPPED
        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_TRIPPED);

        // Subsequent calls should be refused
        await expect(
            policy.authorize(breakerId, makeActionHash("after-trip"))
        ).to.be.revertedWith("CB: tripped");
    });

    it("refuses override during TRIPPED state", async function () {
        // Trip the breaker
        for (let i = 0; i < BURST_THRESHOLD + 1; i++) {
            await policy.authorize(breakerId, makeActionHash(`trip-${i}`));
        }
        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_TRIPPED);

        const actionHash = makeActionHash("override-while-tripped");
        const sig = await signOverride(operator, breakerId, actionHash);
        await expect(
            policy.authorizeWithOverride(breakerId, actionHash, sig)
        ).to.be.revertedWith("CB: tripped, must reset first");
    });

    // ── State transitions: TRIPPED -> COOLDOWN ───────────────────────

    it("transitions from TRIPPED to COOLDOWN after cooldownSeconds", async function () {
        // Trip
        for (let i = 0; i < BURST_THRESHOLD + 1; i++) {
            await policy.authorize(breakerId, makeActionHash(`tc-${i}`));
        }
        let [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_TRIPPED);

        // Advance past cooldown
        await time.increase(COOLDOWN_SECONDS + 1);

        // Try authorize() — should refuse with "cooldown requires override"
        // (the call advances state from TRIPPED -> COOLDOWN before checking)
        await expect(
            policy.authorize(breakerId, makeActionHash("after-cooldown"))
        ).to.be.revertedWith("CB: cooldown requires override");

        // The revert above rolls back the state advance. Use pokeState to
        // explicitly advance state without attempting authorization, then
        // verify it's now COOLDOWN.
        await policy.pokeState(breakerId);
        [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_COOLDOWN);
    });

    // ── COOLDOWN state with override ──────────────────────────────────

    it("allows authorizeWithOverride() during COOLDOWN", async function () {
        // Trip and transition to cooldown
        for (let i = 0; i < BURST_THRESHOLD + 1; i++) {
            await policy.authorize(breakerId, makeActionHash(`co-${i}`));
        }
        await time.increase(COOLDOWN_SECONDS + 1);

        // First, trigger a state advance to COOLDOWN by attempting authorize
        await expect(
            policy.authorize(breakerId, makeActionHash("trigger-state-advance"))
        ).to.be.revertedWith("CB: cooldown requires override");

        // Now authorize with operator override
        const actionHash = makeActionHash("override-cooldown");
        const sig = await signOverride(operator, breakerId, actionHash);
        await policy.authorizeWithOverride(breakerId, actionHash, sig);

        expect(await policy.isActionConsumed(actionHash)).to.be.true;
    });

    it("rejects override with non-operator signature", async function () {
        for (let i = 0; i < BURST_THRESHOLD + 1; i++) {
            await policy.authorize(breakerId, makeActionHash(`bs-${i}`));
        }
        await time.increase(COOLDOWN_SECONDS + 1);
        // Trigger state advance to COOLDOWN
        await expect(
            policy.authorize(breakerId, makeActionHash("trigger"))
        ).to.be.revertedWith("CB: cooldown requires override");

        const actionHash = makeActionHash("bad-override");
        const badSig = await signOverride(other, breakerId, actionHash);
        await expect(
            policy.authorizeWithOverride(breakerId, actionHash, badSig)
        ).to.be.revertedWith("CB: bad override sig");
    });

    it("rejects override in NORMAL state", async function () {
        const actionHash = makeActionHash("override-normal");
        const sig = await signOverride(operator, breakerId, actionHash);
        await expect(
            policy.authorizeWithOverride(breakerId, actionHash, sig)
        ).to.be.revertedWith("CB: not in cooldown");
    });

    // ── State transitions: COOLDOWN -> NORMAL ────────────────────────

    it("transitions from COOLDOWN to NORMAL after 2 * cooldownSeconds", async function () {
        // Trip
        for (let i = 0; i < BURST_THRESHOLD + 1; i++) {
            await policy.authorize(breakerId, makeActionHash(`cn-${i}`));
        }

        // Advance past full cycle (TRIPPED for cooldownSeconds, then COOLDOWN for cooldownSeconds)
        await time.increase(2 * COOLDOWN_SECONDS + 2);

        // Authorize should now succeed (NORMAL state restored)
        await policy.authorize(breakerId, makeActionHash("recovered"));

        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_NORMAL);
    });

    // ── Manual operator controls ──────────────────────────────────────

    it("operator can manually trip", async function () {
        await policy.connect(operator).manualTrip(breakerId);
        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_TRIPPED);
    });

    it("non-operator cannot manually trip", async function () {
        await expect(
            policy.connect(other).manualTrip(breakerId)
        ).to.be.revertedWith("CB: not operator");
    });

    it("operator can manually reset from TRIPPED", async function () {
        await policy.connect(operator).manualTrip(breakerId);
        await policy.connect(operator).manualReset(breakerId);
        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_NORMAL);

        // Should be able to authorize again immediately
        await policy.authorize(breakerId, makeActionHash("after-reset"));
    });

    it("manual reset clears the rate counter", async function () {
        // Fill bucket
        for (let i = 0; i < BURST_THRESHOLD; i++) {
            await policy.authorize(breakerId, makeActionHash(`mr-${i}`));
        }
        // Trip and reset
        await policy.connect(operator).manualTrip(breakerId);
        await policy.connect(operator).manualReset(breakerId);

        // Should accept BURST_THRESHOLD more without tripping
        for (let i = 0; i < BURST_THRESHOLD; i++) {
            await policy.authorize(breakerId, makeActionHash(`mr2-${i}`));
        }
        const [state, ,] = await policy.getState(breakerId);
        expect(state).to.equal(STATE_NORMAL);
    });

    it("cannot manually reset NORMAL breaker", async function () {
        await expect(
            policy.connect(operator).manualReset(breakerId)
        ).to.be.revertedWith("CB: not tripped or cooldown");
    });

    it("cannot manually trip already-tripped breaker", async function () {
        await policy.connect(operator).manualTrip(breakerId);
        await expect(
            policy.connect(operator).manualTrip(breakerId)
        ).to.be.revertedWith("CB: not in normal");
    });

    // ── Replay protection ─────────────────────────────────────────────

    it("rejects replays of same action hash via authorize()", async function () {
        const actionHash = makeActionHash("replay-test");
        await policy.authorize(breakerId, actionHash);
        await expect(
            policy.authorize(breakerId, actionHash)
        ).to.be.revertedWith("CB: replay");
    });

    it("rejects replays of same action hash via override path", async function () {
        // Trip and cooldown
        for (let i = 0; i < BURST_THRESHOLD + 1; i++) {
            await policy.authorize(breakerId, makeActionHash(`rp-${i}`));
        }
        await time.increase(COOLDOWN_SECONDS + 1);
        // Trigger state advance to COOLDOWN
        await expect(
            policy.authorize(breakerId, makeActionHash("rp-trigger"))
        ).to.be.revertedWith("CB: cooldown requires override");

        const actionHash = makeActionHash("override-replay");
        const sig = await signOverride(operator, breakerId, actionHash);
        await policy.authorizeWithOverride(breakerId, actionHash, sig);
        await expect(
            policy.authorizeWithOverride(breakerId, actionHash, sig)
        ).to.be.revertedWith("CB: replay");
    });

    // ── Registration safeguards ───────────────────────────────────────

    it("rejects registration with window < 60", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad1"));
        await expect(
            policy.registerBreaker(id, 12, 10, 3, 60)
        ).to.be.revertedWith("CB: window too short");
    });

    it("rejects registration with window not divisible by 12", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad2"));
        await expect(
            policy.registerBreaker(id, 121, 10, 3, 60)
        ).to.be.revertedWith("CB: window not divisible");
    });

    it("rejects registration with burst > rate", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad3"));
        await expect(
            policy.registerBreaker(id, 120, 5, 10, 60)
        ).to.be.revertedWith("CB: burst > rate");
    });

    it("rejects re-registration of same breaker ID", async function () {
        await expect(
            policy.registerBreaker(
                breakerId, WINDOW_SECONDS, RATE_THRESHOLD,
                BURST_THRESHOLD, COOLDOWN_SECONDS
            )
        ).to.be.revertedWith("CB: breaker exists");
    });

    it("rejects authorize() against unknown breaker", async function () {
        const unknownId = ethers.keccak256(ethers.toUtf8Bytes("ghost"));
        await expect(
            policy.authorize(unknownId, makeActionHash("ghost-action"))
        ).to.be.revertedWith("CB: unknown breaker");
    });
});
