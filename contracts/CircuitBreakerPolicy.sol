// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title CircuitBreakerPolicy
 * @notice Rate-limited authorization layer for Acreo principals. Tracks the
 *         rate of authorizations per principal and enters a fail-closed state
 *         when the rate exceeds configured thresholds.
 *
 * @dev Implements OWASP ASI07 (Cascading Failures) defense.
 *
 *      The attack: agent encounters error and retries. Retry produces another
 *      error. Behavior degrades into a loop that drains funds, generates spam
 *      transactions, or consumes resources. Could be triggered by malicious
 *      input or genuine bug. Vanilla policy enforcement signs each individual
 *      action because each one is technically valid in isolation.
 *
 *      The defense: a circuit breaker monitors authorization rate. When the
 *      rate exceeds either a sustained threshold (rate per window) or a burst
 *      threshold (count per short window), the breaker trips. While tripped,
 *      authorizations fail closed. After a cooldown period, the breaker
 *      enters degraded operation requiring operator override for each
 *      authorization, then returns to normal.
 *
 *      Architecture:
 *        - Sliding window: 12 buckets of configurable duration (default 5min)
 *        - Rate threshold: max authorizations across full window
 *        - Burst threshold: max authorizations in single bucket
 *        - States: NORMAL, TRIPPED, COOLDOWN
 *        - Operator override: manual trip, manual reset, cooldown-time override
 */
contract CircuitBreakerPolicy {

    // ── Events ────────────────────────────────────────────────────────

    event BreakerRegistered(
        bytes32 indexed breakerId,
        address indexed operator,
        uint32 windowSeconds,
        uint32 rateThreshold,
        uint32 burstThreshold,
        uint32 cooldownSeconds
    );

    event AuthorizationAllowed(
        bytes32 indexed breakerId,
        bytes32 indexed actionHash,
        uint32 currentRate
    );

    event BreakerTripped(
        bytes32 indexed breakerId,
        TripReason reason,
        uint32 observedRate,
        uint256 trippedAt
    );

    event BreakerStateChanged(
        bytes32 indexed breakerId,
        BreakerState fromState,
        BreakerState toState
    );

    event BreakerManuallyReset(
        bytes32 indexed breakerId,
        address indexed operator
    );

    event AuthorizationRejected(
        bytes32 indexed breakerId,
        bytes32 indexed actionHash,
        RejectionReason reason
    );

    // ── Types ─────────────────────────────────────────────────────────

    enum BreakerState {
        NORMAL,      // operating normally; rate tracked, authorizations flow
        TRIPPED,     // fail-closed; all authorizations refused until cooldown
        COOLDOWN     // degraded; authorizations require operator override
    }

    enum TripReason {
        RateExceeded,    // sustained rate over window exceeded rateThreshold
        BurstExceeded,   // burst rate in single bucket exceeded burstThreshold
        ManualTrip       // operator manually tripped the breaker
    }

    enum RejectionReason {
        UnknownBreaker,
        BreakerTripped,
        CooldownNoOverride,
        OverrideSignatureInvalid,
        Replay
    }

    struct Breaker {
        address operator;            // who registered and can override
        uint32 windowSeconds;        // total sliding window duration
        uint32 rateThreshold;        // max authorizations across full window
        uint32 burstThreshold;       // max authorizations in single bucket
        uint32 cooldownSeconds;      // how long TRIPPED -> COOLDOWN lasts
        BreakerState state;
        uint256 trippedAt;           // timestamp when state became TRIPPED
        bool exists;
    }

    /**
     * @notice Sliding window of authorization counts per breaker.
     * @dev 12 buckets, each represents (windowSeconds / 12) of time. When a
     *      bucket ages out of the window, it's reset to 0 before being used
     *      for a new period.
     */
    struct WindowState {
        uint32[12] bucketCounts;
        uint256[12] bucketStartTimes;
    }

    // ── Storage ───────────────────────────────────────────────────────

    mapping(bytes32 => Breaker) public breakers;
    mapping(bytes32 => WindowState) internal windows;
    mapping(bytes32 => bool) public consumedActionHashes;

    uint8 public constant BUCKET_COUNT = 12;

    // ── Modifiers ─────────────────────────────────────────────────────

    modifier onlyOperator(bytes32 breakerId) {
        require(breakers[breakerId].operator == msg.sender, "CB: not operator");
        _;
    }

    // ── Registration ──────────────────────────────────────────────────

    /**
     * @notice Register a new circuit breaker.
     * @param breakerId         Unique identifier
     * @param windowSeconds     Total sliding window duration (must be >= 60, divisible by 12)
     * @param rateThreshold     Max authorizations across the full window
     * @param burstThreshold    Max authorizations in a single bucket (windowSeconds/12)
     * @param cooldownSeconds   How long the breaker stays in COOLDOWN after TRIPPED
     */
    function registerBreaker(
        bytes32 breakerId,
        uint32 windowSeconds,
        uint32 rateThreshold,
        uint32 burstThreshold,
        uint32 cooldownSeconds
    ) external {
        require(!breakers[breakerId].exists, "CB: breaker exists");
        require(windowSeconds >= 60, "CB: window too short");
        require(windowSeconds <= 86400, "CB: window too long");
        require(windowSeconds % BUCKET_COUNT == 0, "CB: window not divisible");
        require(rateThreshold > 0, "CB: zero rate threshold");
        require(burstThreshold > 0, "CB: zero burst threshold");
        require(burstThreshold <= rateThreshold, "CB: burst > rate");
        require(cooldownSeconds >= 30, "CB: cooldown too short");
        require(cooldownSeconds <= 86400, "CB: cooldown too long");

        breakers[breakerId] = Breaker({
            operator: msg.sender,
            windowSeconds: windowSeconds,
            rateThreshold: rateThreshold,
            burstThreshold: burstThreshold,
            cooldownSeconds: cooldownSeconds,
            state: BreakerState.NORMAL,
            trippedAt: 0,
            exists: true
        });

        emit BreakerRegistered(
            breakerId, msg.sender,
            windowSeconds, rateThreshold, burstThreshold, cooldownSeconds
        );
    }

    // ── Authorization ─────────────────────────────────────────────────

    /**
     * @notice Request authorization. Increments the rate counter and checks
     *         thresholds. Reverts if the breaker is tripped or rate exceeded.
     * @param breakerId    Which circuit breaker to check against
     * @param actionHash   Unique hash for this action (replay protection)
     */
    function authorize(bytes32 breakerId, bytes32 actionHash) external {
        Breaker storage br = breakers[breakerId];
        if (!br.exists) {
            emit AuthorizationRejected(
                breakerId, actionHash, RejectionReason.UnknownBreaker
            );
            revert("CB: unknown breaker");
        }

        if (consumedActionHashes[actionHash]) {
            emit AuthorizationRejected(
                breakerId, actionHash, RejectionReason.Replay
            );
            revert("CB: replay");
        }

        // Advance state machine first — TRIPPED may transition to COOLDOWN
        // automatically, and COOLDOWN may transition to NORMAL.
        _maybeAdvanceState(br, breakerId);

        if (br.state == BreakerState.TRIPPED) {
            emit AuthorizationRejected(
                breakerId, actionHash, RejectionReason.BreakerTripped
            );
            revert("CB: tripped");
        }

        if (br.state == BreakerState.COOLDOWN) {
            // Authorization through this path is not allowed during cooldown.
            // The caller must use authorizeWithOverride() with an operator
            // signature.
            emit AuthorizationRejected(
                breakerId, actionHash, RejectionReason.CooldownNoOverride
            );
            revert("CB: cooldown requires override");
        }

        // NORMAL state — increment counter and check thresholds
        (uint32 rateInWindow, uint32 currentBucketCount) =
            _incrementAndQuery(breakerId, br.windowSeconds);

        // Burst check fires first (more aggressive trip).
        //
        // CRITICAL SEMANTICS: when the threshold is crossed, we trip the
        // breaker AND accept this action. The next action will hit the
        // TRIPPED check at the top and fail. This is necessary because
        // reverting here would roll back the state change to TRIPPED,
        // leaving the breaker in NORMAL state forever. Standard circuit
        // breaker pattern — the action that crosses the threshold is
        // the "last action through the door" before fail-closed.
        if (currentBucketCount > br.burstThreshold) {
            _trip(br, breakerId, TripReason.BurstExceeded, currentBucketCount);
            consumedActionHashes[actionHash] = true;
            emit AuthorizationAllowed(breakerId, actionHash, rateInWindow);
            return;
        }

        if (rateInWindow > br.rateThreshold) {
            _trip(br, breakerId, TripReason.RateExceeded, rateInWindow);
            consumedActionHashes[actionHash] = true;
            emit AuthorizationAllowed(breakerId, actionHash, rateInWindow);
            return;
        }

        // All checks passed
        consumedActionHashes[actionHash] = true;
        emit AuthorizationAllowed(breakerId, actionHash, rateInWindow);
    }

    /**
     * @notice Authorize during COOLDOWN with operator signature.
     * @param breakerId         Circuit breaker
     * @param actionHash        Action being authorized
     * @param operatorSignature Operator's signature over (breakerId, actionHash)
     */
    function authorizeWithOverride(
        bytes32 breakerId,
        bytes32 actionHash,
        bytes calldata operatorSignature
    ) external {
        Breaker storage br = breakers[breakerId];
        require(br.exists, "CB: unknown breaker");

        if (consumedActionHashes[actionHash]) {
            emit AuthorizationRejected(
                breakerId, actionHash, RejectionReason.Replay
            );
            revert("CB: replay");
        }

        _maybeAdvanceState(br, breakerId);

        if (br.state == BreakerState.TRIPPED) {
            // Even with override, TRIPPED requires manual reset
            emit AuthorizationRejected(
                breakerId, actionHash, RejectionReason.BreakerTripped
            );
            revert("CB: tripped, must reset first");
        }

        if (br.state == BreakerState.NORMAL) {
            // Don't accept override in normal state — that would be a way
            // around rate limits
            revert("CB: not in cooldown");
        }

        // We're in COOLDOWN. Verify operator signature.
        bytes32 messageHash = keccak256(abi.encodePacked(
            breakerId, actionHash
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        address recovered = _recoverSigner(ethSignedHash, operatorSignature);
        if (recovered != br.operator) {
            emit AuthorizationRejected(
                breakerId, actionHash, RejectionReason.OverrideSignatureInvalid
            );
            revert("CB: bad override sig");
        }

        // Override granted. Still increment the counter (helps detect if
        // even overrides are firing too fast — a sign the breaker config
        // is wrong).
        _incrementAndQuery(breakerId, br.windowSeconds);

        consumedActionHashes[actionHash] = true;
        emit AuthorizationAllowed(breakerId, actionHash, 0);
    }

    // ── Operator actions ──────────────────────────────────────────────

    function manualTrip(bytes32 breakerId) external onlyOperator(breakerId) {
        Breaker storage br = breakers[breakerId];
        require(br.state == BreakerState.NORMAL, "CB: not in normal");
        _trip(br, breakerId, TripReason.ManualTrip, 0);
    }

    function manualReset(bytes32 breakerId) external onlyOperator(breakerId) {
        Breaker storage br = breakers[breakerId];
        require(
            br.state == BreakerState.TRIPPED || br.state == BreakerState.COOLDOWN,
            "CB: not tripped or cooldown"
        );
        BreakerState old = br.state;
        br.state = BreakerState.NORMAL;
        br.trippedAt = 0;
        // Clear the window so the rate counter starts fresh
        WindowState storage win = windows[breakerId];
        for (uint8 i = 0; i < BUCKET_COUNT; i++) {
            win.bucketCounts[i] = 0;
            win.bucketStartTimes[i] = 0;
        }
        emit BreakerStateChanged(breakerId, old, BreakerState.NORMAL);
        emit BreakerManuallyReset(breakerId, msg.sender);
    }

    // ── Read-only ─────────────────────────────────────────────────────

    function getState(bytes32 breakerId)
        external
        view
        returns (BreakerState state, uint256 trippedAt, uint32 currentRate)
    {
        Breaker storage br = breakers[breakerId];
        require(br.exists, "CB: unknown breaker");

        // Compute the rate without modifying state
        uint32 rate = _currentRate(breakerId, br.windowSeconds);
        return (br.state, br.trippedAt, rate);
    }

    function isActionConsumed(bytes32 actionHash) external view returns (bool) {
        return consumedActionHashes[actionHash];
    }

    /**
     * @notice Advance the state machine to the current time without attempting
     *         to authorize anything. Use this before reading state if you need
     *         to see the post-time-advance state.
     * @dev This exists because `authorize()` reverts during TRIPPED/COOLDOWN
     *      states, which would roll back any state machine advance. By
     *      separating the advance from the authorize, callers can advance
     *      state via this call (which doesn't revert) and then read it via
     *      getState().
     */
    function pokeState(bytes32 breakerId) external {
        Breaker storage br = breakers[breakerId];
        require(br.exists, "CB: unknown breaker");
        _maybeAdvanceState(br, breakerId);
    }

    // ── Internal: state machine ───────────────────────────────────────

    function _maybeAdvanceState(Breaker storage br, bytes32 breakerId) internal {
        if (br.state == BreakerState.TRIPPED) {
            // TRIPPED -> COOLDOWN after cooldownSeconds elapsed
            if (block.timestamp >= br.trippedAt + br.cooldownSeconds) {
                br.state = BreakerState.COOLDOWN;
                emit BreakerStateChanged(
                    breakerId, BreakerState.TRIPPED, BreakerState.COOLDOWN
                );
                // Fall through to check COOLDOWN -> NORMAL in case enough
                // time has elapsed for both transitions
            } else {
                return;
            }
        }
        if (br.state == BreakerState.COOLDOWN) {
            // COOLDOWN -> NORMAL after another cooldownSeconds in cooldown
            if (block.timestamp >= br.trippedAt + 2 * br.cooldownSeconds) {
                br.state = BreakerState.NORMAL;
                br.trippedAt = 0;
                // Clear the window for fresh start
                WindowState storage win = windows[breakerId];
                for (uint8 i = 0; i < BUCKET_COUNT; i++) {
                    win.bucketCounts[i] = 0;
                    win.bucketStartTimes[i] = 0;
                }
                emit BreakerStateChanged(
                    breakerId, BreakerState.COOLDOWN, BreakerState.NORMAL
                );
            }
        }
    }

    function _trip(
        Breaker storage br,
        bytes32 breakerId,
        TripReason reason,
        uint32 observedRate
    ) internal {
        BreakerState old = br.state;
        br.state = BreakerState.TRIPPED;
        br.trippedAt = block.timestamp;
        emit BreakerTripped(breakerId, reason, observedRate, block.timestamp);
        emit BreakerStateChanged(breakerId, old, BreakerState.TRIPPED);
    }

    // ── Internal: sliding window ──────────────────────────────────────

    function _bucketDuration(uint32 windowSeconds) internal pure returns (uint32) {
        return windowSeconds / BUCKET_COUNT;
    }

    /**
     * @notice Increment counter for current bucket and return rate metrics.
     * @return rateInWindow         Sum of all live buckets
     * @return currentBucketCount   Count in the current bucket
     */
    function _incrementAndQuery(bytes32 breakerId, uint32 windowSeconds)
        internal
        returns (uint32 rateInWindow, uint32 currentBucketCount)
    {
        WindowState storage win = windows[breakerId];
        uint32 bucketDuration = _bucketDuration(windowSeconds);
        uint256 nowTime = block.timestamp;

        // Find the current bucket index based on timestamp
        uint8 currentIdx = uint8((nowTime / bucketDuration) % BUCKET_COUNT);
        uint256 currentBucketStart = (nowTime / bucketDuration) * bucketDuration;

        // If the bucket's recorded start time is older than its current
        // period, reset it before incrementing
        if (win.bucketStartTimes[currentIdx] != currentBucketStart) {
            win.bucketCounts[currentIdx] = 0;
            win.bucketStartTimes[currentIdx] = currentBucketStart;
        }

        win.bucketCounts[currentIdx]++;
        currentBucketCount = win.bucketCounts[currentIdx];

        // Sum across live buckets — buckets whose start time is within
        // (now - windowSeconds, now]
        uint256 windowStart = nowTime - windowSeconds;
        for (uint8 i = 0; i < BUCKET_COUNT; i++) {
            if (win.bucketStartTimes[i] > windowStart) {
                rateInWindow += win.bucketCounts[i];
            }
        }
    }

    function _currentRate(bytes32 breakerId, uint32 windowSeconds)
        internal
        view
        returns (uint32 rateInWindow)
    {
        WindowState storage win = windows[breakerId];
        uint256 windowStart = block.timestamp - windowSeconds;
        for (uint8 i = 0; i < BUCKET_COUNT; i++) {
            if (win.bucketStartTimes[i] > windowStart) {
                rateInWindow += win.bucketCounts[i];
            }
        }
    }

    // ── Internal: signature recovery ──────────────────────────────────

    function _recoverSigner(bytes32 hash, bytes calldata signature)
        internal
        pure
        returns (address)
    {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(add(signature.offset, 0))
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }
}
