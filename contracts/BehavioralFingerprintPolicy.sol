// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title BehavioralFingerprintPolicy
 * @notice Tracks per-category action counts in a sliding window and refuses
 *         actions that would push the agent's category mix outside its
 *         declared behavioral fingerprint.
 *
 * @dev Implements OWASP ASI02 (Memory Poisoning) defense, v0.2.
 *      Complements v0.1's cumulative caps with content-shape enforcement.
 *
 *      The attack v0.2 catches: agent's memory is poisoned over many
 *      turns, gradually shifting its action distribution toward an
 *      attacker-favorable pattern. Each individual action passes the
 *      cumulative caps (signed value, gross volume). The harm is in the
 *      mix — too many of one category, too few of another, drift from
 *      the declared strategy fingerprint.
 *
 *      The defense: at registration, the operator declares a fingerprint
 *      = {(categoryId, minShareBps, maxShareBps)} for each allowed
 *      category. Per-category counts are tracked in a sliding bucket
 *      window. Each new action's category increments its count; before
 *      authorizing, the contract checks that the resulting category mix
 *      stays inside the declared bands.
 *
 *      Honest scope:
 *
 *      WHAT v0.2 CATCHES:
 *        - Category-mix drift (agent shifts toward unusual action types)
 *        - Suppressed-category attacks (agent stops doing something normal)
 *        - Inflated-category attacks (agent does too much of one type)
 *
 *      WHAT v0.2 DOES NOT CATCH:
 *        - Size-mix drift (categories normal but sizes anomalous) — v0.3
 *        - Timing-distribution attacks (cluster bursts) — v0.3+
 *        - Counterparty concentration — separate per-counterparty policy
 *        - Semantic memory poisoning (content of reasoning) — SOTA layer
 *
 *      Bands are NOT enforced until the strategy has accumulated at
 *      least `minActionsForBands` actions in the current window. Below
 *      that threshold, all in-category actions pass — a strategy can't
 *      meaningfully have a "mix" with too few samples.
 */
contract BehavioralFingerprintPolicy {

    // ── Events ────────────────────────────────────────────────────────

    event StrategyRegistered(
        bytes32 indexed strategyId,
        address indexed operator,
        uint32 windowSeconds,
        uint8[] allowedCategories,
        uint32 minActionsForBands
    );

    event ActionAuthorized(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        uint8 categoryId,
        uint32 totalInWindow
    );

    event ActionRejected(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        RejectionReason reason,
        uint8 categoryId,
        uint16 observedShareBps,
        uint16 boundShareBps
    );

    // ── Types ─────────────────────────────────────────────────────────

    enum RejectionReason {
        UnknownStrategy,
        CategoryNotAllowed,
        BelowMinShare,         // accepting this action would push category share below min
        AboveMaxShare,         // accepting this action would push category share above max
        Replay,
        NotAuthorized
    }

    /**
     * @notice A category's allowed share band.
     * @dev Shares expressed in basis points (10000 = 100%).
     *      minShareBps and maxShareBps are bounds on (count / total).
     */
    struct CategoryBand {
        uint8 categoryId;
        uint16 minShareBps;
        uint16 maxShareBps;
    }

    struct Strategy {
        address operator;
        uint32 windowSeconds;
        uint32 minActionsForBands;          // bands not enforced below this count
        CategoryBand[] bands;
        address[] authorizedSubmitters;
        bool exists;
    }

    /**
     * @notice Sliding window of per-category counts per strategy.
     * @dev 12 buckets. Each bucket tracks counts for up to 32 categories.
     */
    struct WindowState {
        // bucketCategoryCounts[bucketIdx][categoryId] = count
        // we use a fixed-size array of mappings via a 2D mapping
        // for simplicity. Each bucket also records its start time.
        uint256[12] bucketStartTimes;
        // For each bucket, store per-category counts in a sub-mapping
        // keyed by (strategyId, bucketIdx, categoryId).
    }

    // ── Storage ───────────────────────────────────────────────────────

    mapping(bytes32 => Strategy) public strategies;
    mapping(bytes32 => WindowState) internal windows;

    // bucketCounts[strategyId][bucketIdx][categoryId] -> count for that bucket
    // Using nested mapping instead of fixed array because categoryId is uint8
    // (0-255) and we don't want to pay for 256-slot allocation per bucket.
    mapping(bytes32 => mapping(uint8 => mapping(uint8 => uint32))) internal bucketCounts;

    mapping(bytes32 => bool) public consumedActionHashes;

    uint8 public constant BUCKET_COUNT = 12;
    uint8 public constant MAX_CATEGORIES = 32;

    // ── Modifiers ─────────────────────────────────────────────────────

    modifier onlyAuthorized(bytes32 strategyId) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "BFP: unknown strategy");
        bool isAuth = false;
        for (uint256 i = 0; i < strat.authorizedSubmitters.length; i++) {
            if (strat.authorizedSubmitters[i] == msg.sender) {
                isAuth = true;
                break;
            }
        }
        require(isAuth, "BFP: not authorized");
        _;
    }

    // ── Strategy registration ─────────────────────────────────────────

    /**
     * @notice Register a behavioral fingerprint strategy.
     * @param strategyId             Unique identifier
     * @param windowSeconds          Sliding window duration (>=60, divisible by 12)
     * @param bands                  Per-category min/max share bands
     * @param minActionsForBands     Min total actions before bands enforced
     * @param authorizedSubmitters   Addresses allowed to submit actions
     */
    function registerStrategy(
        bytes32 strategyId,
        uint32 windowSeconds,
        CategoryBand[] calldata bands,
        uint32 minActionsForBands,
        address[] calldata authorizedSubmitters
    ) external {
        require(!strategies[strategyId].exists, "BFP: strategy exists");
        require(windowSeconds >= 60, "BFP: window too short");
        require(windowSeconds <= 86400, "BFP: window too long");
        require(windowSeconds % BUCKET_COUNT == 0, "BFP: window not divisible");
        require(bands.length > 0, "BFP: no bands");
        require(bands.length <= MAX_CATEGORIES, "BFP: too many bands");
        require(minActionsForBands >= 1, "BFP: min actions zero");
        require(authorizedSubmitters.length > 0, "BFP: no submitters");

        // Validate bands
        for (uint256 i = 0; i < bands.length; i++) {
            require(bands[i].categoryId > 0, "BFP: zero category");
            require(bands[i].minShareBps <= bands[i].maxShareBps, "BFP: min > max");
            require(bands[i].maxShareBps <= 10000, "BFP: max > 100%");
            for (uint256 j = i + 1; j < bands.length; j++) {
                require(
                    bands[i].categoryId != bands[j].categoryId,
                    "BFP: dup category"
                );
            }
        }

        // Validate submitters
        for (uint256 i = 0; i < authorizedSubmitters.length; i++) {
            require(authorizedSubmitters[i] != address(0), "BFP: zero submitter");
            for (uint256 j = i + 1; j < authorizedSubmitters.length; j++) {
                require(
                    authorizedSubmitters[i] != authorizedSubmitters[j],
                    "BFP: dup submitter"
                );
            }
        }

        Strategy storage strat = strategies[strategyId];
        strat.operator = msg.sender;
        strat.windowSeconds = windowSeconds;
        strat.minActionsForBands = minActionsForBands;
        strat.exists = true;
        for (uint256 i = 0; i < bands.length; i++) {
            strat.bands.push(bands[i]);
        }
        for (uint256 i = 0; i < authorizedSubmitters.length; i++) {
            strat.authorizedSubmitters.push(authorizedSubmitters[i]);
        }

        uint8[] memory allowedCategories = new uint8[](bands.length);
        for (uint256 i = 0; i < bands.length; i++) {
            allowedCategories[i] = bands[i].categoryId;
        }

        emit StrategyRegistered(
            strategyId, msg.sender, windowSeconds, allowedCategories, minActionsForBands
        );
    }

    // ── Authorization ─────────────────────────────────────────────────

    function authorize(
        bytes32 strategyId,
        bytes32 actionHash,
        uint8 categoryId
    ) external onlyAuthorized(strategyId) {
        Strategy storage strat = strategies[strategyId];

        if (consumedActionHashes[actionHash]) {
            emit ActionRejected(
                strategyId, actionHash, RejectionReason.Replay,
                categoryId, 0, 0
            );
            revert("BFP: replay");
        }

        // Find the band for this category
        (bool found, uint16 minShare, uint16 maxShare) =
            _findBand(strat.bands, categoryId);
        if (!found) {
            emit ActionRejected(
                strategyId, actionHash, RejectionReason.CategoryNotAllowed,
                categoryId, 0, 0
            );
            revert("BFP: category not allowed");
        }

        // Predict what counts would be if this action is accepted
        uint32 currentTotal = _currentTotal(strategyId, strat.windowSeconds);
        uint32 currentCategoryCount =
            _currentCategoryCount(strategyId, strat.windowSeconds, categoryId);

        uint32 newCategoryCount = currentCategoryCount + 1;
        uint32 newTotal = currentTotal + 1;

        // Bands only enforced once we have enough actions
        if (newTotal >= strat.minActionsForBands) {
            // Check the band for THIS category
            uint16 categoryShareBps = uint16((uint256(newCategoryCount) * 10000) / newTotal);

            if (categoryShareBps > maxShare) {
                emit ActionRejected(
                    strategyId, actionHash, RejectionReason.AboveMaxShare,
                    categoryId, categoryShareBps, maxShare
                );
                revert("BFP: above max share");
            }

            // Check bands for OTHER categories — accepting this action increases
            // the denominator, which can push other categories' shares below
            // their minimum (suppressed-category attack).
            for (uint256 i = 0; i < strat.bands.length; i++) {
                CategoryBand storage band = strat.bands[i];
                if (band.categoryId == categoryId) continue;

                uint32 otherCount = _currentCategoryCount(
                    strategyId, strat.windowSeconds, band.categoryId
                );
                uint16 otherShareBps = uint16((uint256(otherCount) * 10000) / newTotal);

                if (otherShareBps < band.minShareBps) {
                    emit ActionRejected(
                        strategyId, actionHash, RejectionReason.BelowMinShare,
                        band.categoryId, otherShareBps, band.minShareBps
                    );
                    revert("BFP: below min share");
                }
            }
        }

        // All checks passed — record this action
        _incrementCategory(strategyId, strat.windowSeconds, categoryId);
        consumedActionHashes[actionHash] = true;

        emit ActionAuthorized(strategyId, actionHash, categoryId, newTotal);
    }

    // ── Read-only ─────────────────────────────────────────────────────

    function getStrategy(bytes32 strategyId) external view returns (
        address operator,
        uint32 windowSeconds,
        uint32 minActionsForBands,
        CategoryBand[] memory bands,
        address[] memory authorizedSubmitters
    ) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "BFP: unknown strategy");
        return (
            strat.operator, strat.windowSeconds, strat.minActionsForBands,
            strat.bands, strat.authorizedSubmitters
        );
    }

    function getCategoryCount(bytes32 strategyId, uint8 categoryId)
        external view returns (uint32)
    {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "BFP: unknown strategy");
        return _currentCategoryCount(strategyId, strat.windowSeconds, categoryId);
    }

    function getCurrentTotal(bytes32 strategyId) external view returns (uint32) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "BFP: unknown strategy");
        return _currentTotal(strategyId, strat.windowSeconds);
    }

    function isActionConsumed(bytes32 actionHash) external view returns (bool) {
        return consumedActionHashes[actionHash];
    }

    // ── Internal: band lookup ─────────────────────────────────────────

    function _findBand(CategoryBand[] storage bands, uint8 categoryId)
        internal view returns (bool found, uint16 minShare, uint16 maxShare)
    {
        for (uint256 i = 0; i < bands.length; i++) {
            if (bands[i].categoryId == categoryId) {
                return (true, bands[i].minShareBps, bands[i].maxShareBps);
            }
        }
        return (false, 0, 0);
    }

    // ── Internal: sliding window ──────────────────────────────────────

    function _bucketDuration(uint32 windowSeconds) internal pure returns (uint32) {
        return windowSeconds / BUCKET_COUNT;
    }

    function _currentTotal(bytes32 strategyId, uint32 windowSeconds)
        internal view returns (uint32 total)
    {
        WindowState storage win = windows[strategyId];
        uint256 nowTime = block.timestamp;
        uint256 windowStart = nowTime > windowSeconds ? nowTime - windowSeconds : 0;

        for (uint8 b = 0; b < BUCKET_COUNT; b++) {
            if (win.bucketStartTimes[b] > windowStart) {
                // Sum counts across all categories for this bucket.
                // We need to iterate all category IDs that might have counts —
                // bound it by looking at this strategy's declared bands.
                Strategy storage strat = strategies[strategyId];
                for (uint256 i = 0; i < strat.bands.length; i++) {
                    total += bucketCounts[strategyId][b][strat.bands[i].categoryId];
                }
            }
        }
    }

    function _currentCategoryCount(
        bytes32 strategyId,
        uint32 windowSeconds,
        uint8 categoryId
    ) internal view returns (uint32 count) {
        WindowState storage win = windows[strategyId];
        uint256 nowTime = block.timestamp;
        uint256 windowStart = nowTime > windowSeconds ? nowTime - windowSeconds : 0;

        for (uint8 b = 0; b < BUCKET_COUNT; b++) {
            if (win.bucketStartTimes[b] > windowStart) {
                count += bucketCounts[strategyId][b][categoryId];
            }
        }
    }

    function _incrementCategory(
        bytes32 strategyId,
        uint32 windowSeconds,
        uint8 categoryId
    ) internal {
        WindowState storage win = windows[strategyId];
        uint32 bucketDuration = _bucketDuration(windowSeconds);
        uint256 nowTime = block.timestamp;

        uint8 currentIdx = uint8((nowTime / bucketDuration) % BUCKET_COUNT);
        uint256 currentBucketStart = (nowTime / bucketDuration) * bucketDuration;

        // Reset bucket if recycled into a new period
        if (win.bucketStartTimes[currentIdx] != currentBucketStart) {
            // Zero out counts for this bucket across all declared categories
            Strategy storage strat = strategies[strategyId];
            for (uint256 i = 0; i < strat.bands.length; i++) {
                bucketCounts[strategyId][currentIdx][strat.bands[i].categoryId] = 0;
            }
            win.bucketStartTimes[currentIdx] = currentBucketStart;
        }

        bucketCounts[strategyId][currentIdx][categoryId] += 1;
    }
}
