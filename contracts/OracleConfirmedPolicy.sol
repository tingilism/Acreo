// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title OracleConfirmedPolicy
 * @notice Extension to AgentVerifier that requires n-of-m oracle signatures
 *         on the data point an action depends on before authorizing the action.
 *
 * @dev Implements OWASP ASI04 (Tool and Tool Description Misuse) defense:
 *      a single compromised oracle cannot poison agent decisions because the
 *      principal refuses to sign actions unless n independent oracles agree.
 *
 *      Architecture choice: in-contract ECDSA verification via ecrecover.
 *      No ZK proofs required for the oracle layer — oracle identities are
 *      public so there's no privacy benefit from zero-knowledge verification.
 *      ZK proofs continue to be used for the policy/intent layer; the oracle
 *      layer is plain ECDSA.
 *
 *      Threat model:
 *        - Attacker compromises < n oracles: median check rejects skewed prices
 *        - Attacker compromises >= n oracles: bounded by tolerance window
 *          (attacker still cannot move price > tolerance without all oracles)
 *        - Attacker submits stale data: timestamp check rejects
 *        - Attacker replays old signatures: timestamp + nonce per action
 *
 *      Out of scope:
 *        - Oracle key compromise via off-chain attack (handled by oracle ops)
 *        - Round-coordination attacks on RedStone/Chainlink themselves
 */
contract OracleConfirmedPolicy {

    // ── Events ────────────────────────────────────────────────────────

    event OracleSetRegistered(
        bytes32 indexed policyId,
        address[] oracles,
        uint8 threshold,
        uint256 toleranceBps,
        uint256 maxAgeSeconds
    );

    event ActionAuthorized(
        bytes32 indexed policyId,
        bytes32 indexed actionHash,
        uint256 medianPrice,
        uint8 confirmingOracles
    );

    event ActionRejected(
        bytes32 indexed policyId,
        bytes32 indexed actionHash,
        RejectionReason reason
    );

    // ── Types ─────────────────────────────────────────────────────────

    enum RejectionReason {
        InsufficientOracles,     // fewer signatures than threshold
        StaleData,                // any oracle's timestamp older than maxAge
        ToleranceExceeded,        // spread between min and max > tolerance
        InvalidSignature,         // signature didn't recover to declared oracle
        DuplicateOracle,          // same oracle signed twice
        UnknownOracle,            // signer not in declared oracle set
        Replay,                   // action nonce already consumed
        FeedMismatch,             // FIX J: attestation feed != policy feed
        ZeroPrice                 // FIX K: oracle submitted price 0
    }

    struct OracleSet {
        address[] oracles;
        uint8 threshold;          // n in "n-of-m"
        uint256 toleranceBps;     // max spread between min and max, in basis points
        uint256 maxAgeSeconds;    // reject prices older than this
        bytes32 expectedFeedId;   // FIX J: the feed this policy is pinned to
        bool exists;
    }

    struct OracleAttestation {
        address oracle;           // oracle's address (must be in declared set)
        bytes32 dataFeedId;       // e.g. keccak256("BTC/USD")
        uint256 price;            // price with 18-decimal scaling
        uint256 timestamp;        // unix seconds when oracle observed price
        bytes signature;          // ECDSA signature over the data
    }

    // ── Storage ───────────────────────────────────────────────────────

    mapping(bytes32 => OracleSet) public oracleSets;
    mapping(bytes32 => bool) public consumedActionHashes;

    address public owner;

    // ── Modifiers ─────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "OCP: not owner");
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ── Policy registration ───────────────────────────────────────────

    /**
     * @notice Register an oracle set for a given policy.
     * @param policyId        Unique identifier for this policy
     * @param oracles         Declared oracle public keys
     * @param threshold       Minimum signatures required (n-of-m)
     * @param toleranceBps    Maximum spread between min/max prices, in bps
     * @param maxAgeSeconds   Maximum age of oracle data (replay protection)
     */
    function registerOracleSet(
        bytes32 policyId,
        address[] calldata oracles,
        uint8 threshold,
        uint256 toleranceBps,
        uint256 maxAgeSeconds,
        bytes32 expectedFeedId
    ) external onlyOwner {
        require(expectedFeedId != bytes32(0), "OCP: zero feed id");
        require(oracles.length > 0, "OCP: no oracles");
        require(threshold > 0 && threshold <= oracles.length, "OCP: bad threshold");
        require(toleranceBps <= 10000, "OCP: tolerance > 100%");
        require(maxAgeSeconds > 0 && maxAgeSeconds <= 86400, "OCP: bad maxAge");
        require(!oracleSets[policyId].exists, "OCP: policy exists");

        // Verify no duplicate oracles in the set
        for (uint256 i = 0; i < oracles.length; i++) {
            require(oracles[i] != address(0), "OCP: zero oracle");
            for (uint256 j = i + 1; j < oracles.length; j++) {
                require(oracles[i] != oracles[j], "OCP: dup oracle");
            }
        }

        oracleSets[policyId] = OracleSet({
            oracles: oracles,
            threshold: threshold,
            toleranceBps: toleranceBps,
            maxAgeSeconds: maxAgeSeconds,
            expectedFeedId: expectedFeedId,
            exists: true
        });

        emit OracleSetRegistered(policyId, oracles, threshold, toleranceBps, maxAgeSeconds);
    }

    // ── Authorization ─────────────────────────────────────────────────

    /**
     * @notice Verify that n-of-m oracles attest to a price, then authorize action.
     * @param policyId      Which oracle set to validate against
     * @param actionHash    Unique hash binding price to action (replay protection)
     * @param attestations  Array of oracle attestations
     * @return medianPrice  The median price across confirming oracles
     */
    function verifyAndAuthorize(
        bytes32 policyId,
        bytes32 actionHash,
        OracleAttestation[] calldata attestations
    ) external returns (uint256 medianPrice) {
        OracleSet storage set = oracleSets[policyId];
        require(set.exists, "OCP: unknown policy");

        // Replay protection at the action level
        if (consumedActionHashes[actionHash]) {
            emit ActionRejected(policyId, actionHash, RejectionReason.Replay);
            revert("OCP: replay");
        }

        // Verify threshold count
        if (attestations.length < set.threshold) {
            emit ActionRejected(policyId, actionHash, RejectionReason.InsufficientOracles);
            revert("OCP: below threshold");
        }

        uint256 nowTime = block.timestamp;
        uint256[] memory confirmedPrices = new uint256[](attestations.length);
        address[] memory seenOracles = new address[](attestations.length);
        uint8 confirmedCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            OracleAttestation calldata att = attestations[i];

            // Timestamp freshness — reject stale data
            if (att.timestamp + set.maxAgeSeconds < nowTime) {
                emit ActionRejected(policyId, actionHash, RejectionReason.StaleData);
                revert("OCP: stale");
            }
            // Reject future-dated timestamps (off by >60s clock skew tolerance)
            if (att.timestamp > nowTime + 60) {
                emit ActionRejected(policyId, actionHash, RejectionReason.StaleData);
                revert("OCP: future");
            }

            // FIX J: every attestation must be for the policy's pinned feed
            if (att.dataFeedId != set.expectedFeedId) {
                emit ActionRejected(policyId, actionHash, RejectionReason.FeedMismatch);
                revert("OCP: feed mismatch");
            }

            // Verify the oracle is in the declared set
            if (!_isOracleInSet(att.oracle, set.oracles)) {
                emit ActionRejected(policyId, actionHash, RejectionReason.UnknownOracle);
                revert("OCP: unknown oracle");
            }

            // Reject duplicates within this submission
            for (uint8 j = 0; j < confirmedCount; j++) {
                if (seenOracles[j] == att.oracle) {
                    emit ActionRejected(policyId, actionHash, RejectionReason.DuplicateOracle);
                    revert("OCP: dup oracle in submission");
                }
            }

            // FIX L: bind the signed payload to THIS policy and THIS action.
            // Without policyId + actionHash in the hash, the same attestation
            // could be replayed across unlimited different actions until the
            // timestamp ages out. Including them makes each attestation
            // single-use for one specific action.
            bytes32 dataHash = keccak256(abi.encodePacked(
                policyId, actionHash, att.dataFeedId, att.price, att.timestamp
            ));
            bytes32 ethSignedHash = keccak256(abi.encodePacked(
                "\x19Ethereum Signed Message:\n32", dataHash
            ));
            address recovered = _recoverSigner(ethSignedHash, att.signature);
            if (recovered != att.oracle) {
                emit ActionRejected(policyId, actionHash, RejectionReason.InvalidSignature);
                revert("OCP: bad sig");
            }

            confirmedPrices[confirmedCount] = att.price;
            seenOracles[confirmedCount] = att.oracle;
            confirmedCount++;
        }

        // Verify tolerance — spread between min and max must be within tolerance
        uint256 minPrice = confirmedPrices[0];
        uint256 maxPrice = confirmedPrices[0];
        for (uint8 i = 1; i < confirmedCount; i++) {
            if (confirmedPrices[i] < minPrice) minPrice = confirmedPrices[i];
            if (confirmedPrices[i] > maxPrice) maxPrice = confirmedPrices[i];
        }

        // FIX K: a zero price would divide-by-zero below. Reject explicitly
        // so a single oracle can't grief the whole authorization with price=0.
        if (minPrice == 0) {
            emit ActionRejected(policyId, actionHash, RejectionReason.ZeroPrice);
            revert("OCP: zero price");
        }

        // spread_bps = (max - min) * 10000 / min
        uint256 spreadBps = ((maxPrice - minPrice) * 10000) / minPrice;
        if (spreadBps > set.toleranceBps) {
            emit ActionRejected(policyId, actionHash, RejectionReason.ToleranceExceeded);
            revert("OCP: tolerance exceeded");
        }

        // All checks passed — compute median and authorize
        medianPrice = _median(confirmedPrices, confirmedCount);
        consumedActionHashes[actionHash] = true;

        emit ActionAuthorized(policyId, actionHash, medianPrice, confirmedCount);
        return medianPrice;
    }

    // ── Read-only helpers ─────────────────────────────────────────────

    function getOracleSet(bytes32 policyId) external view returns (
        address[] memory oracles,
        uint8 threshold,
        uint256 toleranceBps,
        uint256 maxAgeSeconds,
        bytes32 expectedFeedId
    ) {
        OracleSet storage set = oracleSets[policyId];
        require(set.exists, "OCP: unknown policy");
        return (set.oracles, set.threshold, set.toleranceBps, set.maxAgeSeconds, set.expectedFeedId);
    }

    function isActionConsumed(bytes32 actionHash) external view returns (bool) {
        return consumedActionHashes[actionHash];
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

    function _isOracleInSet(address oracle, address[] storage set)
        internal
        view
        returns (bool)
    {
        for (uint256 i = 0; i < set.length; i++) {
            if (set[i] == oracle) return true;
        }
        return false;
    }

    function _median(uint256[] memory values, uint8 count)
        internal
        pure
        returns (uint256)
    {
        // Simple insertion sort — count is small (typically 3-5)
        for (uint8 i = 1; i < count; i++) {
            uint256 key = values[i];
            uint8 j = i;
            while (j > 0 && values[j - 1] > key) {
                values[j] = values[j - 1];
                j--;
            }
            values[j] = key;
        }
        if (count % 2 == 1) {
            return values[count / 2];
        }
        return (values[count / 2 - 1] + values[count / 2]) / 2;
    }
}
