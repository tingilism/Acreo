// SPDX-License-Identifier: Apache-2.0
// Test suite for BehavioralFingerprintPolicy (Acreo ASI02 v0.2)

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("BehavioralFingerprintPolicy", function () {
    let policy;
    let operator;
    let submitters;
    let submitterAddresses;
    let other;
    let strategyId;

    // Default config:
    //   12-minute window, 60s buckets
    //   Bands: PLACE_ORDER 60-80%, CANCEL_ORDER 15-35%, UPDATE_LEVERAGE 0-10%
    //   Bands enforced after 10 actions
    const WINDOW_SECONDS = 720;
    const BUCKET_DURATION = WINDOW_SECONDS / 12;
    const MIN_ACTIONS_FOR_BANDS = 10;

    const CAT_PLACE = 1;
    const CAT_CANCEL = 2;
    const CAT_LEVERAGE = 3;
    const CAT_OTHER = 4;  // not in the strategy

    function makeActionHash(label) {
        return ethers.keccak256(ethers.toUtf8Bytes(label));
    }

    beforeEach(async function () {
        const signers = await ethers.getSigners();
        operator = signers[0];
        submitters = signers.slice(1, 4);
        submitterAddresses = submitters.map((s) => s.address);
        other = signers[9];

        const Policy = await ethers.getContractFactory("BehavioralFingerprintPolicy");
        policy = await Policy.connect(operator).deploy();
        await policy.waitForDeployment();

        strategyId = ethers.keccak256(ethers.toUtf8Bytes("strat-fp"));

        // Standard market-maker fingerprint
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 6000, maxShareBps: 8000 },
            { categoryId: CAT_CANCEL, minShareBps: 1500, maxShareBps: 3500 },
            { categoryId: CAT_LEVERAGE, minShareBps: 0, maxShareBps: 1000 },
        ];

        await policy.connect(operator).registerStrategy(
            strategyId,
            WINDOW_SECONDS,
            bands,
            MIN_ACTIONS_FOR_BANDS,
            submitterAddresses
        );

        // Align time to bucket boundary
        const now = await time.latest();
        const nextBucket = Math.ceil(now / BUCKET_DURATION) * BUCKET_DURATION;
        if (nextBucket > now) {
            await time.increaseTo(nextBucket + 1);
        }
    });

    // â”€â”€ Warmup window â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("authorizes any in-category action below MIN_ACTIONS_FOR_BANDS threshold", async function () {
        // First 9 actions can be any mix â€” bands not enforced yet
        for (let i = 0; i < 9; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`warmup-${i}`), CAT_CANCEL
            );
        }
        // All 9 cancels, which would be 100% â€” but bands aren't enforced yet
        const total = await policy.getCurrentTotal(strategyId);
        expect(total).to.equal(9n);
    });

    // â”€â”€ Happy path: normal mix â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("authorizes a normal market-maker mix (70% place, 25% cancel, 5% leverage)", async function () {
        const warmup = [
            CAT_PLACE, CAT_CANCEL,
            CAT_PLACE, CAT_PLACE, CAT_CANCEL,
            CAT_PLACE, CAT_PLACE, CAT_PLACE, CAT_PLACE,
        ];
        for (let i = 0; i < warmup.length; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`mix-w-${i}`), warmup[i]
            );
        }
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("mix-10"), CAT_CANCEL
        );
        const total = await policy.getCurrentTotal(strategyId);
        expect(total).to.equal(10n);
        const placeCount = await policy.getCategoryCount(strategyId, CAT_PLACE);
        const cancelCount = await policy.getCategoryCount(strategyId, CAT_CANCEL);
        expect(placeCount).to.equal(7n);
        expect(cancelCount).to.equal(3n);
    });

    // â”€â”€ Mix-drift attack: too much of one category â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("REJECTS too-many-of-one-category attack", async function () {
        // Build to 10 actions of a normal mix
        for (let i = 0; i < 7; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`p-${i}`), CAT_PLACE
            );
        }
        for (let i = 0; i < 3; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`c-${i}`), CAT_CANCEL
            );
        }
        // Now at 7 place / 3 cancel = 70% / 30%, both inside bands.
        // Attacker tries to push place_order beyond max (80%).
        // 8 place / 3 cancel = 72.7% / 27.3% â€” still in bands.
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("p-7"), CAT_PLACE
        );
        // 9 place / 3 cancel = 75% / 25% â€” still in bands
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("p-8"), CAT_PLACE
        );
        // 10 place / 3 cancel = 76.9% / 23.1% â€” still in bands
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("p-9"), CAT_PLACE
        );
        // 11 place / 3 cancel = 78.6% / 21.4% â€” still in bands
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("p-10"), CAT_PLACE
        );
        // 12 place / 3 cancel = 80% / 20% â€” exactly at max
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("p-11"), CAT_PLACE
        );
        // 13 place / 3 cancel = 81.25% / 18.75% â€” ABOVE max for place
        await expect(
            policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash("p-12"), CAT_PLACE
            )
        ).to.be.revertedWith("BFP: above max share");
    });

    // â”€â”€ Suppression attack: cleaner setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("REJECTS suppression by raising other categories", async function () {
        // To test suppression we need bands where one category's max is loose
        // enough that increasing it can push another category's share below
        // its min. So use a separate strategy with permissive cancel band.
        const suppStrategyId = ethers.keccak256(ethers.toUtf8Bytes("strat-supp"));
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 6000, maxShareBps: 8000 },
            { categoryId: CAT_CANCEL, minShareBps: 1500, maxShareBps: 5000 },
            { categoryId: CAT_LEVERAGE, minShareBps: 0, maxShareBps: 1000 },
        ];
        await policy.connect(operator).registerStrategy(
            suppStrategyId, WINDOW_SECONDS, bands,
            MIN_ACTIONS_FOR_BANDS, submitterAddresses
        );

        // Build healthy 7 place / 3 cancel = 70/30, both inside bands.
        // Interleave so the running mix stays valid across the threshold.
        const warmup = [
            CAT_PLACE, CAT_PLACE, CAT_PLACE, CAT_CANCEL,  // 75/25 at action 4
            CAT_PLACE, CAT_PLACE, CAT_PLACE, CAT_CANCEL,  // 75/25 at action 8
            CAT_PLACE, CAT_CANCEL,                          // 70/30 at action 10
        ];
        for (let i = 0; i < warmup.length; i++) {
            await policy.connect(submitters[0]).authorize(
                suppStrategyId, makeActionHash(`sw-${i}`), warmup[i]
            );
        }
        // Now: 7 place, 3 cancel, total=10. place=70%, cancel=30%. Both inside.

        // Add cancel: 7 place / 4 cancel = 11 total. place share = 7/11 â‰ˆ 63.6% (inside).
        // cancel share = 4/11 â‰ˆ 36.4% (inside 15-50%). Should pass.
        await policy.connect(submitters[0]).authorize(
            suppStrategyId, makeActionHash("supp-extra-1"), CAT_CANCEL
        );

        // Another cancel: 7 place / 5 cancel = 12 total. place = 7/12 = 58.3% (BELOW 60% min).
        // cancel = 5/12 = 41.7% (inside). The suppression check on place should fire.
        await expect(
            policy.connect(submitters[0]).authorize(
                suppStrategyId, makeActionHash("supp-extra-2"), CAT_CANCEL
            )
        ).to.be.revertedWith("BFP: below min share");
    });

    // â”€â”€ Disallowed category â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("rejects an action with a category not in the strategy", async function () {
        await expect(
            policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash("bad-cat"), CAT_OTHER
            )
        ).to.be.revertedWith("BFP: category not allowed");
    });

    // â”€â”€ Sliding window â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("recovers capacity as old actions age out of the window", async function () {
        // Fill up with all cancels (would violate when bands enforce)
        for (let i = 0; i < 9; i++) {
            await policy.connect(submitters[0]).authorize(
                strategyId, makeActionHash(`old-${i}`), CAT_CANCEL
            );
        }
        // Advance past the whole window
        await time.increase(WINDOW_SECONDS + 60);

        // Old actions should have aged out â€” total should be 0
        const total = await policy.getCurrentTotal(strategyId);
        expect(total).to.equal(0n);

        // Fresh start â€” any single action is fine
        await policy.connect(submitters[0]).authorize(
            strategyId, makeActionHash("fresh"), CAT_PLACE
        );
    });

    // â”€â”€ Authorization checks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("rejects authorize from non-submitter", async function () {
        await expect(
            policy.connect(other).authorize(
                strategyId, makeActionHash("unauth"), CAT_PLACE
            )
        ).to.be.revertedWith("BFP: not authorized");
    });

    it("rejects authorize against unknown strategy", async function () {
        const unknownId = ethers.keccak256(ethers.toUtf8Bytes("unknown"));
        await expect(
            policy.connect(submitters[0]).authorize(
                unknownId, makeActionHash("ghost"), CAT_PLACE
            )
        ).to.be.revertedWith("BFP: unknown strategy");
    });

    // â”€â”€ Replay protection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("rejects replays of same action hash", async function () {
        const actionHash = makeActionHash("replay");
        await policy.connect(submitters[0]).authorize(
            strategyId, actionHash, CAT_PLACE
        );
        await expect(
            policy.connect(submitters[0]).authorize(
                strategyId, actionHash, CAT_PLACE
            )
        ).to.be.revertedWith("BFP: replay");
    });

    // â”€â”€ Registration safeguards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    it("rejects registration with min > max share", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-band"));
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 5000, maxShareBps: 3000 },
        ];
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, bands, 10, submitterAddresses)
        ).to.be.revertedWith("BFP: min > max");
    });

    it("rejects registration with max share > 100%", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("bad-max"));
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 5000, maxShareBps: 10001 },
        ];
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, bands, 10, submitterAddresses)
        ).to.be.revertedWith("BFP: max > 100%");
    });

    it("rejects registration with zero category", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("zero-cat"));
        const bands = [{ categoryId: 0, minShareBps: 0, maxShareBps: 10000 }];
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, bands, 10, submitterAddresses)
        ).to.be.revertedWith("BFP: zero category");
    });

    it("rejects registration with duplicate category", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("dup-cat"));
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 1000, maxShareBps: 5000 },
            { categoryId: CAT_PLACE, minShareBps: 2000, maxShareBps: 6000 },
        ];
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, bands, 10, submitterAddresses)
        ).to.be.revertedWith("BFP: dup category");
    });

    it("rejects registration with no bands", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("no-bands"));
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, [], 10, submitterAddresses)
        ).to.be.revertedWith("BFP: no bands");
    });

    it("rejects re-registration of same strategy ID", async function () {
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 5000, maxShareBps: 7000 },
        ];
        await expect(
            policy.registerStrategy(strategyId, WINDOW_SECONDS, bands, 10, submitterAddresses)
        ).to.be.revertedWith("BFP: strategy exists");
    });

    it("rejects registration with zero minActionsForBands", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("zero-min"));
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 5000, maxShareBps: 7000 },
        ];
        await expect(
            policy.registerStrategy(id, WINDOW_SECONDS, bands, 0, submitterAddresses)
        ).to.be.revertedWith("BFP: min actions zero");
    });

    it("rejects registration with duplicate submitters", async function () {
        const id = ethers.keccak256(ethers.toUtf8Bytes("dup-sub"));
        const bands = [
            { categoryId: CAT_PLACE, minShareBps: 5000, maxShareBps: 7000 },
        ];
        await expect(
            policy.registerStrategy(
                id, WINDOW_SECONDS, bands, 10,
                [submitters[0].address, submitters[0].address]
            )
        ).to.be.revertedWith("BFP: dup submitter");
    });
});

