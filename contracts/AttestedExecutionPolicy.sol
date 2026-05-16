// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title AttestedExecutionPolicy
 * @notice Verifies that an agent's execution environment matches a
 *         pre-registered measurement, via a trusted attestor service.
 *
 * @dev Implements OWASP ASI06 (Supply Chain Compromise) defense, v0.1.
 *
 *      The attack: the agent's binary, model weights, or runtime
 *      configuration is tampered with. The agent runs unmodified at the
 *      interface level but its behavior has been backdoored.
 *      Stateless and behavioral policies (ASI01, ASI02) catch SOME of
 *      the resulting actions, but a sophisticated backdoor stays inside
 *      the declared policy envelope. The fix is to gate authorization
 *      on cryptographic proof that the agent IS what the operator
 *      expects.
 *
 *      Architecture (v0.1, trusted-attestor):
 *        - Operator registers an "attestor" address (typically a service
 *          they run that verifies TEE attestation reports off-chain).
 *        - Operator registers an "expectedMeasurement" — the hash of
 *          the agent binary + configuration that should be running.
 *        - For each action, the agent submits an AttestationStatement
 *          signed by the attestor saying "as of timestamp T, agent A
 *          has measurement M." The contract checks: signature recovers
 *          to registered attestor, measurement matches registered
 *          expectedMeasurement, statement is not expired, agent in the
 *          statement matches the agent submitting.
 *
 *      Trust model:
 *        - Operator trusts attestor service to honestly verify TEEs
 *        - Attestor trusts TEE hardware to honestly report measurement
 *        - Acreo verifies attestor's signature on-chain via ecrecover
 *        - Same trust shape used by Marlin, Phala, Flashbots BuilderNet
 *
 *      Roadmap v1.0 (Q1 2027):
 *        - Replace trusted-attestor with on-chain ECDSA-P384 verifier
 *          for direct SEV-SNP and TDX attestation report verification
 *        - Direct chain-of-trust to AMD/Intel root CAs
 *        - On-chain ASN.1/DER parser for certificate chains
 *        - Requires ~6 months of specialist cryptography work
 *
 *      What v0.1 does NOT defend against:
 *        - Compromise of the attestor service itself (gates collapse)
 *        - Operator registering wrong measurement (configuration error)
 *        - Future-state attacks (zero-day in TEE hardware itself)
 *      These are out-of-scope for v0.1 and addressed by the v1.0 design.
 */
contract AttestedExecutionPolicy {

    // ── Events ────────────────────────────────────────────────────────

    event StrategyRegistered(
        bytes32 indexed strategyId,
        address indexed operator,
        address attestor,
        bytes32 expectedMeasurement,
        uint32 attestationValiditySeconds
    );

    event AttestorRotated(
        bytes32 indexed strategyId,
        address indexed oldAttestor,
        address indexed newAttestor
    );

    event MeasurementUpdated(
        bytes32 indexed strategyId,
        bytes32 oldMeasurement,
        bytes32 newMeasurement
    );

    event ActionAuthorized(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        address indexed agent,
        bytes32 measurement
    );

    event ActionRejected(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        RejectionReason reason
    );

    // ── Types ─────────────────────────────────────────────────────────

    enum RejectionReason {
        UnknownStrategy,
        AgentNotAuthorized,
        MeasurementMismatch,
        AttestationExpired,
        AttestationFutureDated,
        InvalidAttestorSignature,
        AgentMismatch,
        Replay
    }

    struct Strategy {
        address operator;
        address attestor;                       // who signs attestations
        bytes32 expectedMeasurement;            // expected agent binary hash
        uint32 attestationValiditySeconds;      // max age of an attestation
        address[] authorizedAgents;
        bool exists;
    }

    /**
     * @notice An attestation that an agent is running an expected measurement.
     * @dev Signed by the attestor over (strategyId, agent, measurement, timestamp).
     */
    struct AttestationStatement {
        bytes32 strategyId;
        address agent;
        bytes32 measurement;
        uint256 timestamp;
        bytes attestorSignature;   // sig over (strategyId, actionHash,
                                   // agent, measurement, timestamp)
    }

    // ── Storage ───────────────────────────────────────────────────────

    mapping(bytes32 => Strategy) public strategies;
    mapping(bytes32 => bool) public consumedActionHashes;

    // ── Modifiers ─────────────────────────────────────────────────────

    modifier onlyOperator(bytes32 strategyId) {
        require(strategies[strategyId].operator == msg.sender, "AEP: not operator");
        _;
    }

    // ── Strategy registration ─────────────────────────────────────────

    /**
     * @notice Register a strategy with an attestor and expected measurement.
     * @param strategyId                    Unique identifier
     * @param attestor                      Address that signs attestation statements
     * @param expectedMeasurement           Expected agent binary measurement hash
     * @param attestationValiditySeconds    Max age of an attestation (replay window)
     * @param authorizedAgents              Agents allowed to act under this strategy
     */
    function registerStrategy(
        bytes32 strategyId,
        address attestor,
        bytes32 expectedMeasurement,
        uint32 attestationValiditySeconds,
        address[] calldata authorizedAgents
    ) external {
        require(!strategies[strategyId].exists, "AEP: strategy exists");
        require(attestor != address(0), "AEP: zero attestor");
        require(expectedMeasurement != bytes32(0), "AEP: zero measurement");
        require(attestationValiditySeconds >= 30, "AEP: validity too short");
        require(attestationValiditySeconds <= 3600, "AEP: validity too long");
        require(authorizedAgents.length > 0, "AEP: no agents");

        for (uint256 i = 0; i < authorizedAgents.length; i++) {
            require(authorizedAgents[i] != address(0), "AEP: zero agent");
            for (uint256 j = i + 1; j < authorizedAgents.length; j++) {
                require(
                    authorizedAgents[i] != authorizedAgents[j],
                    "AEP: dup agent"
                );
            }
        }

        strategies[strategyId] = Strategy({
            operator: msg.sender,
            attestor: attestor,
            expectedMeasurement: expectedMeasurement,
            attestationValiditySeconds: attestationValiditySeconds,
            authorizedAgents: authorizedAgents,
            exists: true
        });

        emit StrategyRegistered(
            strategyId, msg.sender, attestor,
            expectedMeasurement, attestationValiditySeconds
        );
    }

    // ── Attestor & measurement rotation (operator only) ──────────────

    /**
     * @notice Rotate the attestor for a strategy.
     * @dev Used when the attestor service's key is rotated, or when
     *      switching attestor providers.
     */
    function rotateAttestor(bytes32 strategyId, address newAttestor)
        external
        onlyOperator(strategyId)
    {
        require(newAttestor != address(0), "AEP: zero attestor");
        Strategy storage strat = strategies[strategyId];
        require(newAttestor != strat.attestor, "AEP: same attestor");
        address oldAttestor = strat.attestor;
        strat.attestor = newAttestor;
        emit AttestorRotated(strategyId, oldAttestor, newAttestor);
    }

    /**
     * @notice Update the expected measurement for a strategy.
     * @dev Used when the agent binary or configuration is intentionally
     *      updated. Old measurements stop being valid immediately.
     */
    function updateMeasurement(bytes32 strategyId, bytes32 newMeasurement)
        external
        onlyOperator(strategyId)
    {
        require(newMeasurement != bytes32(0), "AEP: zero measurement");
        Strategy storage strat = strategies[strategyId];
        require(newMeasurement != strat.expectedMeasurement, "AEP: same measurement");
        bytes32 oldMeasurement = strat.expectedMeasurement;
        strat.expectedMeasurement = newMeasurement;
        emit MeasurementUpdated(strategyId, oldMeasurement, newMeasurement);
    }

    // ── Authorization ─────────────────────────────────────────────────

    /**
     * @notice Verify that an attested-execution agent can take this action.
     * @param actionHash    Unique action identifier
     * @param attestation   Signed statement from the attestor
     */
    function verifyAttestation(
        bytes32 actionHash,
        AttestationStatement calldata attestation
    ) external returns (bool) {
        Strategy storage strat = strategies[attestation.strategyId];
        if (!strat.exists) {
            emit ActionRejected(
                attestation.strategyId, actionHash, RejectionReason.UnknownStrategy
            );
            revert("AEP: unknown strategy");
        }

        if (consumedActionHashes[actionHash]) {
            emit ActionRejected(
                attestation.strategyId, actionHash, RejectionReason.Replay
            );
            revert("AEP: replay");
        }

        // Verify the claimed agent is in the strategy's authorized list
        if (!_isAgentAuthorized(attestation.agent, strat.authorizedAgents)) {
            emit ActionRejected(
                attestation.strategyId, actionHash,
                RejectionReason.AgentNotAuthorized
            );
            revert("AEP: agent not authorized");
        }

        // Verify the agent submitting matches the attestation's claim
        // (the attestation is bound to a specific agent, and only that
        // agent should be using it)
        if (attestation.agent != msg.sender) {
            emit ActionRejected(
                attestation.strategyId, actionHash, RejectionReason.AgentMismatch
            );
            revert("AEP: agent mismatch");
        }

        // Verify measurement matches expected
        if (attestation.measurement != strat.expectedMeasurement) {
            emit ActionRejected(
                attestation.strategyId, actionHash,
                RejectionReason.MeasurementMismatch
            );
            revert("AEP: measurement mismatch");
        }

        // Verify attestation is not expired
        uint256 nowTime = block.timestamp;
        if (attestation.timestamp + strat.attestationValiditySeconds < nowTime) {
            emit ActionRejected(
                attestation.strategyId, actionHash, RejectionReason.AttestationExpired
            );
            revert("AEP: attestation expired");
        }

        // Verify attestation is not future-dated beyond clock skew tolerance (60s)
        if (attestation.timestamp > nowTime + 60) {
            emit ActionRejected(
                attestation.strategyId, actionHash, RejectionReason.AttestationFutureDated
            );
            revert("AEP: attestation future");
        }

        // Verify the attestor signature.
        //
        // FINDING M (Phase-1 sandbox lead -> confirmed in source): the
        // attestor must sign over the actionHash too. Without it, a single
        // valid attestation authorizes ANY action within the validity
        // window — the agent supplies actionHash freely and the per-
        // actionHash replay check does not bind the attestation to the
        // action. Including actionHash makes each attestation single-use
        // for one specific action (same fix shape as ASI04 Finding L).
        bytes32 messageHash = keccak256(abi.encodePacked(
            attestation.strategyId,
            actionHash,
            attestation.agent,
            attestation.measurement,
            attestation.timestamp
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        address recovered = _recoverSigner(ethSignedHash, attestation.attestorSignature);
        if (recovered != strat.attestor) {
            emit ActionRejected(
                attestation.strategyId, actionHash,
                RejectionReason.InvalidAttestorSignature
            );
            revert("AEP: bad attestor sig");
        }

        // All checks passed
        consumedActionHashes[actionHash] = true;
        emit ActionAuthorized(
            attestation.strategyId, actionHash,
            attestation.agent, attestation.measurement
        );
        return true;
    }

    // ── Read-only ─────────────────────────────────────────────────────

    function getStrategy(bytes32 strategyId) external view returns (
        address operator,
        address attestor,
        bytes32 expectedMeasurement,
        uint32 attestationValiditySeconds,
        address[] memory authorizedAgents
    ) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "AEP: unknown strategy");
        return (
            strat.operator,
            strat.attestor,
            strat.expectedMeasurement,
            strat.attestationValiditySeconds,
            strat.authorizedAgents
        );
    }

    function isActionConsumed(bytes32 actionHash) external view returns (bool) {
        return consumedActionHashes[actionHash];
    }

    // ── Internal helpers ──────────────────────────────────────────────

    function _isAgentAuthorized(address agent, address[] storage authorized)
        internal view returns (bool)
    {
        for (uint256 i = 0; i < authorized.length; i++) {
            if (authorized[i] == agent) return true;
        }
        return false;
    }

    function _recoverSigner(bytes32 hash, bytes calldata signature)
        internal pure returns (address)
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
