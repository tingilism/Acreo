// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title StatefulCumulativePolicy
 * @notice Stateful policy that tracks cumulative signed action values over a
 *         sliding window and refuses actions that would push cumulative
 *         totals outside declared bounds.
 *
 * @dev Implements OWASP ASI02 (Memory Poisoning) defense, v0.1.
 *
 *      The attack: long-running agent accumulates context. Each individual
 *      action passes policy in isolation, but the cumulative pattern across
 *      a sequence of actions causes harm. Stateless policies miss this
 *      entirely. Attacker plants context in earlier turns that the agent
 *      later uses to justify a slow-drain or position-buildup attack.
 *
 *      The defense: track cumulative metrics — signed sum of action values
 *      and unsigned sum (gross volume) — over a sliding window. Before
 *      authorizing a new action, compute (cumulative + new_action_value)
 *      and refuse if it would exceed the declared cap.
 *
 *      Scope honestly stated:
 *
 *      WHAT v0.1 CATCHES:
 *        - Slow exfiltration (1000 small transfers summing to a large amount)
 *        - Position buildup attacks (agent accumulating exposure beyond cap)
 *        - Gross-volume excess (high churn that compounds fees / market impact)
 *
 *      WHAT v0.1 DOES NOT CATCH:
 *        - Behavioral anomalies (action pattern shifts that stay within bounds)
 *        - Counterparty concentration (single attacker address gets many small actions)
 *        - Time-distribution attacks (clustering of actions in unusual windows)
 *
 *      The full SOTA version (Q1 2027 roadmap) replaces this in-contract
 *      arithmetic with recursive ZK proofs over a Verkle accumulator,
 *      enabling richer invariants and behavioral consistency checks
 *      via TEE-attested models.
 *
 *      v0.1 uses the same bucket-based sliding window machinery as ASI07
 *      to keep gas bounded. 12 buckets per window.
 */
contract StatefulCumulativePolicy {

    // ── Events ────────────────────────────────────────────────────────

    event StrategyRegistered(
        bytes32 indexed strategyId,
        address indexed operator,
        uint32 windowSeconds,
        int256 signedValueCap,
        uint256 grossVolumeCap
    );

    event ActionAuthorized(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        int256 actionSignedValue,
        int256 cumulativeSignedValue,
        uint256 cumulativeGrossVolume
    );

    event ActionRejected(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        RejectionReason reason
    );

    // ── Types ─────────────────────────────────────────────────────────

    enum RejectionReason {
        UnknownStrategy,
        SignedValueCapExceeded,    // |cumulative + action| > signedValueCap
        GrossVolumeCapExceeded,     // gross + |action| > grossVolumeCap
        Replay,
        NotAuthorized
    }

    struct Strategy {
        address operator;
        uint32 windowSeconds;            // total sliding window duration
        int256 signedValueCap;            // |cumulative signed value| must stay <= this
        uint256 grossVolumeCap;           // cumulative |action values| must stay <= this
        address[] authorizedSubmitters;   // who can submit actions for this strategy
        bool exists;
    }

    /**
     * @notice Sliding window of cumulative metrics per strategy.
     * @dev 12 buckets. Each holds signed sum and gross volume sum for that
     *      time period. Stale buckets are reset when the bucket is reused
     *      for a new period (lazy invalidation, same as ASI07).
     */
    struct WindowState {
        int256[12] signedSums;
        uint256[12] grossSums;
        uint256[12] bucketStartTimes;
    }

    // ── Storage ───────────────────────────────────────────────────────

    mapping(bytes32 => Strategy) public strategies;
    mapping(bytes32 => WindowState) internal windows;
    mapping(bytes32 => bool) public consumedActionHashes;

    uint8 public constant BUCKET_COUNT = 12;

    // ── Modifiers ─────────────────────────────────────────────────────

    modifier onlyAuthorized(bytes32 strategyId) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "SCP: unknown strategy");
        bool isAuth = false;
        for (uint256 i = 0; i < strat.authorizedSubmitters.length; i++) {
            if (strat.authorizedSubmitters[i] == msg.sender) {
                isAuth = true;
                break;
            }
        }
        require(isAuth, "SCP: not authorized");
        _;
    }

    // ── Strategy registration ─────────────────────────────────────────

    /**
     * @notice Register a stateful cumulative policy.
     * @param strategyId             Unique identifier
     * @param windowSeconds          Sliding window duration (must be >= 60, divisible by 12)
     * @param signedValueCap         Max |cumulative signed value| over the window
     * @param grossVolumeCap         Max cumulative gross volume (sum of |action values|)
     * @param authorizedSubmitters   Addresses allowed to submit actions
     */
    function registerStrategy(
        bytes32 strategyId,
        uint32 windowSeconds,
        int256 signedValueCap,
        uint256 grossVolumeCap,
        address[] calldata authorizedSubmitters
    ) external {
        require(!strategies[strategyId].exists, "SCP: strategy exists");
        require(windowSeconds >= 60, "SCP: window too short");
        require(windowSeconds <= 86400, "SCP: window too long");
        require(windowSeconds % BUCKET_COUNT == 0, "SCP: window not divisible");
        require(signedValueCap > 0, "SCP: zero signed cap");
        require(grossVolumeCap > 0, "SCP: zero gross cap");
        require(authorizedSubmitters.length > 0, "SCP: no submitters");

        // Reject duplicates in submitter list
        for (uint256 i = 0; i < authorizedSubmitters.length; i++) {
            require(authorizedSubmitters[i] != address(0), "SCP: zero submitter");
            for (uint256 j = i + 1; j < authorizedSubmitters.length; j++) {
                require(
                    authorizedSubmitters[i] != authorizedSubmitters[j],
                    "SCP: dup submitter"
                );
            }
        }

        strategies[strategyId] = Strategy({
            operator: msg.sender,
            windowSeconds: windowSeconds,
            signedValueCap: signedValueCap,
            grossVolumeCap: grossVolumeCap,
            authorizedSubmitters: authorizedSubmitters,
            exists: true
        });

        emit StrategyRegistered(
            strategyId, msg.sender, windowSeconds, signedValueCap, grossVolumeCap
        );
    }

    // ── Authorization ─────────────────────────────────────────────────

    /**
     * @notice Submit an action; succeed and update cumulative state, or refuse.
     * @param strategyId          Which strategy
     * @param actionHash          Unique action identifier
     * @param actionSignedValue   Signed value of this action (+ for inflow, - for outflow)
     */
    function authorize(
        bytes32 strategyId,
        bytes32 actionHash,
        int256 actionSignedValue
    ) external onlyAuthorized(strategyId) {
        Strategy storage strat = strategies[strategyId];

        if (consumedActionHashes[actionHash]) {
            emit ActionRejected(strategyId, actionHash, RejectionReason.Replay);
            revert("SCP: replay");
        }

        // Compute current cumulative metrics across the live window
        (int256 currentSigned, uint256 currentGross) =
            _currentCumulative(strategyId, strat.windowSeconds);

        // Compute the new totals if this action is accepted
        int256 newSigned = currentSigned + actionSignedValue;
        uint256 actionGross = _abs(actionSignedValue);
        uint256 newGross = currentGross + actionGross;

        // Check signed value cap — |newSigned| must stay within +/- signedValueCap
        if (newSigned > strat.signedValueCap || newSigned < -strat.signedValueCap) {
            emit ActionRejected(
                strategyId, actionHash, RejectionReason.SignedValueCapExceeded
            );
            revert("SCP: signed cap exceeded");
        }

        // Check gross volume cap
        if (newGross > strat.grossVolumeCap) {
            emit ActionRejected(
                strategyId, actionHash, RejectionReason.GrossVolumeCapExceeded
            );
            revert("SCP: gross cap exceeded");
        }

        // Update the current bucket
        _addToBucket(strategyId, strat.windowSeconds, actionSignedValue);
        consumedActionHashes[actionHash] = true;

        emit ActionAuthorized(
            strategyId, actionHash, actionSignedValue, newSigned, newGross
        );
    }

    // ── Read-only ─────────────────────────────────────────────────────

    function getStrategy(bytes32 strategyId) external view returns (
        address operator,
        uint32 windowSeconds,
        int256 signedValueCap,
        uint256 grossVolumeCap,
        address[] memory authorizedSubmitters
    ) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "SCP: unknown strategy");
        return (
            strat.operator, strat.windowSeconds, strat.signedValueCap,
            strat.grossVolumeCap, strat.authorizedSubmitters
        );
    }

    function getCumulative(bytes32 strategyId) external view returns (
        int256 cumulativeSigned,
        uint256 cumulativeGross
    ) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "SCP: unknown strategy");
        return _currentCumulative(strategyId, strat.windowSeconds);
    }

    function isActionConsumed(bytes32 actionHash) external view returns (bool) {
        return consumedActionHashes[actionHash];
    }

    // ── Internal: sliding window ──────────────────────────────────────

    function _bucketDuration(uint32 windowSeconds) internal pure returns (uint32) {
        return windowSeconds / BUCKET_COUNT;
    }

    /**
     * @notice Sum live buckets into current cumulative metrics.
     * @dev A bucket is "live" if its startTime falls within the sliding window
     *      ending at block.timestamp.
     */
    function _currentCumulative(bytes32 strategyId, uint32 windowSeconds)
        internal
        view
        returns (int256 cumulativeSigned, uint256 cumulativeGross)
    {
        WindowState storage win = windows[strategyId];
        uint256 nowTime = block.timestamp;
        uint256 windowStart = nowTime > windowSeconds ? nowTime - windowSeconds : 0;

        for (uint8 i = 0; i < BUCKET_COUNT; i++) {
            if (win.bucketStartTimes[i] > windowStart) {
                cumulativeSigned += win.signedSums[i];
                cumulativeGross += win.grossSums[i];
            }
        }
    }

    /**
     * @notice Add an action value to the current bucket, resetting if stale.
     */
    function _addToBucket(
        bytes32 strategyId,
        uint32 windowSeconds,
        int256 actionSignedValue
    ) internal {
        WindowState storage win = windows[strategyId];
        uint32 bucketDuration = _bucketDuration(windowSeconds);
        uint256 nowTime = block.timestamp;

        uint8 currentIdx = uint8((nowTime / bucketDuration) % BUCKET_COUNT);
        uint256 currentBucketStart = (nowTime / bucketDuration) * bucketDuration;

        // Reset bucket if it's been recycled into a new period
        if (win.bucketStartTimes[currentIdx] != currentBucketStart) {
            win.signedSums[currentIdx] = 0;
            win.grossSums[currentIdx] = 0;
            win.bucketStartTimes[currentIdx] = currentBucketStart;
        }

        win.signedSums[currentIdx] += actionSignedValue;
        win.grossSums[currentIdx] += _abs(actionSignedValue);
    }

    // ── Utility ───────────────────────────────────────────────────────

    function _abs(int256 x) internal pure returns (uint256) {
        if (x >= 0) return uint256(x);
        return uint256(-x);
    }
}
