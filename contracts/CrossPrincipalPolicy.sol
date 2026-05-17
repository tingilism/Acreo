// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title CrossPrincipalPolicy
 * @notice Bilateral inter-principal multi-signature for actions that cross
 *         principal trust boundaries. Each cross-principal action requires
 *         signatures from authorized agents of BOTH principals.
 *
 * @dev Implements OWASP ASI08 (Agent Communication Exploitation) defense.
 *
 *      The attack: multi-agent system where agent A talks to agent B.
 *      One is compromised or malicious. The honest agent gets steered
 *      toward bad actions through AI-to-AI conversation — classic
 *      confused deputy. Agent A uses agent B's privileges incorrectly
 *      because it trusts B's representations.
 *
 *      The defense: when an action crosses a principal boundary (touches
 *      both A's resources and B's resources, or takes effect under both
 *      principals' authority), require signatures from BOTH principals'
 *      authorized agents. Each principal evaluates the action against
 *      its own policy independently. The action proceeds only if both
 *      principals approve.
 *
 *      Architecture choices (v0.1):
 *        - BILATERAL: relationships are pairwise (A ↔ B). Each cross-
 *          principal action is between two specific registered partners.
 *          Multilateral relationships (A signing with anyone in a group)
 *          come in a later version.
 *        - CATEGORY WHITELIST: at registration, the partners declare
 *          which action categories can be cross-authorized. Uses the
 *          same 8-category canonical enum as ASI01.
 *        - REVOCATION: either operator can unilaterally revoke. Revocation
 *          is immediate — no notice period, no in-flight grace.
 *
 *      What v0.1 catches:
 *        - One agent in a multi-agent flow gets compromised — the other
 *          principal's policy refuses, cross-principal action dies
 *        - Confused deputy attacks where the honest agent is tricked into
 *          authorizing on the partner's behalf — both principals must
 *          independently approve
 *        - Persistence attempts via partner manipulation — revocation
 *          is unilateral, immediate, on-chain
 *
 *      What v0.1 does NOT catch:
 *        - Coordinated compromise of both principals' agents (out of
 *          scope for any single defense)
 *        - Off-chain social engineering between operators (orthogonal
 *          to cryptographic enforcement)
 *        - Long-running collusion that produces individually-valid signatures
 *          across many in-policy actions (composes with ASI02 stateful
 *          policies on both sides)
 */
contract CrossPrincipalPolicy {

    // ── Events ────────────────────────────────────────────────────────

    event RelationshipRegistered(
        bytes32 indexed relationshipId,
        bytes32 indexed principalA,
        bytes32 indexed principalB,
        uint8[] allowedCategories
    );

    event RelationshipRevoked(
        bytes32 indexed relationshipId,
        address indexed revokedBy,
        bytes32 revokingPrincipal
    );

    event CrossActionAuthorized(
        bytes32 indexed relationshipId,
        bytes32 indexed actionHash,
        uint8 category,
        address agentA,
        address agentB
    );

    event CrossActionRejected(
        bytes32 indexed relationshipId,
        bytes32 indexed actionHash,
        RejectionReason reason
    );

    // ── Types ─────────────────────────────────────────────────────────

    enum RejectionReason {
        UnknownRelationship,
        RelationshipRevoked,
        CategoryNotAllowed,
        AgentANotAuthorized,
        AgentBNotAuthorized,
        InvalidSignatureA,
        InvalidSignatureB,
        AgentsAreSame,           // a and b must be different agents
        Replay
    }

    /**
     * @notice A bilateral cross-principal relationship.
     * @dev Identified by hash(principalA, principalB) where the two
     *      principal IDs are sorted to give a canonical relationshipId.
     */
    struct Relationship {
        bytes32 principalA;                  // first principal (sorted lower)
        bytes32 principalB;                  // second principal (sorted higher)
        address operatorA;                   // who controls principal A
        address operatorB;                   // who controls principal B
        address[] agentsA;                   // authorized agents for A
        address[] agentsB;                   // authorized agents for B
        uint8[] allowedCategories;           // which categories are allowed
        bool exists;
        bool revoked;
    }

    /**
     * @notice A cross-principal action submission with dual signatures.
     */
    struct CrossAction {
        bytes32 relationshipId;
        bytes32 actionHash;
        uint8 category;
        bytes32 parametersHash;
        address agentA;
        address agentB;
        bytes signatureA;     // agentA's signature over the action
        bytes signatureB;     // agentB's signature over the action
    }

    // Canonical categories (match ASI01)
    uint8 public constant CATEGORY_PLACE_ORDER = 1;
    uint8 public constant CATEGORY_CANCEL_ORDER = 2;
    uint8 public constant CATEGORY_UPDATE_LEVERAGE = 3;
    uint8 public constant CATEGORY_TRANSFER = 4;
    uint8 public constant CATEGORY_WITHDRAW = 5;
    uint8 public constant CATEGORY_APPROVE_AGENT = 6;
    uint8 public constant CATEGORY_REBALANCE = 7;
    uint8 public constant CATEGORY_CLOSE_POSITION = 8;

    // ── Storage ───────────────────────────────────────────────────────

    mapping(bytes32 => Relationship) public relationships;
    mapping(bytes32 => bool) public consumedActionHashes;

    // ── Relationship registration ─────────────────────────────────────

    /**
     * @notice Compute the canonical relationship ID from two principal IDs.
     * @dev Sorting ensures (A, B) and (B, A) produce the same relationshipId.
     */
    function computeRelationshipId(bytes32 principalX, bytes32 principalY)
        public pure returns (bytes32)
    {
        if (principalX < principalY) {
            return keccak256(abi.encodePacked(principalX, principalY));
        }
        return keccak256(abi.encodePacked(principalY, principalX));
    }

    /**
     * @notice Register a bilateral cross-principal relationship.
     * @param principalX           First principal
     * @param principalY           Second principal
     * @param operatorOther        Operator address for the OTHER principal (msg.sender
     *                             is implicitly the operator for one side; the other
     *                             must be provided so both sides are bound at registration)
     * @param agentsForCallerSide  Agents authorized for the caller's principal
     * @param agentsForOtherSide   Agents authorized for the other principal
     * @param allowedCategories    Action categories that can be cross-authorized
     *
     * @dev The party calling registerRelationship implicitly registers as the
     *      operator for whichever of (principalX, principalY) lands at the "A"
     *      slot after sorting. They must provide the OTHER operator's address
     *      so both control sides are committed at registration time.
     */
    function registerRelationship(
        bytes32 principalX,
        bytes32 principalY,
        address operatorOther,
        address[] calldata agentsForCallerSide,
        address[] calldata agentsForOtherSide,
        uint8[] calldata allowedCategories
    ) external {
        require(principalX != principalY, "CPP: same principal");
        require(operatorOther != address(0), "CPP: zero other operator");
        require(operatorOther != msg.sender, "CPP: same operator");
        require(agentsForCallerSide.length > 0, "CPP: no caller agents");
        require(agentsForOtherSide.length > 0, "CPP: no other agents");
        require(allowedCategories.length > 0, "CPP: no categories");
        require(allowedCategories.length <= 32, "CPP: too many categories");

        bytes32 relationshipId = computeRelationshipId(principalX, principalY);
        require(!relationships[relationshipId].exists, "CPP: relationship exists");

        // Determine which side is A vs B based on sort order
        bool callerIsA = principalX < principalY ? true : false;
        bytes32 principalA = principalX < principalY ? principalX : principalY;
        bytes32 principalB = principalX < principalY ? principalY : principalX;

        // Validate categories
        for (uint256 i = 0; i < allowedCategories.length; i++) {
            require(allowedCategories[i] > 0, "CPP: zero category");
            for (uint256 j = i + 1; j < allowedCategories.length; j++) {
                require(
                    allowedCategories[i] != allowedCategories[j],
                    "CPP: dup category"
                );
            }
        }

        _validateAgentList(agentsForCallerSide);
        _validateAgentList(agentsForOtherSide);

        // FINDING N (Phase-2 seam test): a cross-principal dual-signature
        // policy is only meaningful if the two signing sides are
        // INDEPENDENT. Without this check, registerRelationship accepts the
        // same address on both sides (or an operator's two own addresses),
        // letting a single trust domain satisfy the "dual" signature
        // alone — collapsing the cross-principal guarantee to a single-
        // principal one. Enforce disjoint agent sets at registration.
        for (uint256 i = 0; i < agentsForCallerSide.length; i++) {
            for (uint256 j = 0; j < agentsForOtherSide.length; j++) {
                require(
                    agentsForCallerSide[i] != agentsForOtherSide[j],
                    "CPP: agent on both sides"
                );
            }
        }
        // The two controlling operators must also differ (already checked
        // above as operatorOther != msg.sender) — together these make the
        // two sides independent by construction at registration time.

        Relationship storage rel = relationships[relationshipId];
        rel.principalA = principalA;
        rel.principalB = principalB;
        rel.exists = true;
        rel.revoked = false;

        if (callerIsA) {
            rel.operatorA = msg.sender;
            rel.operatorB = operatorOther;
            for (uint256 i = 0; i < agentsForCallerSide.length; i++) {
                rel.agentsA.push(agentsForCallerSide[i]);
            }
            for (uint256 i = 0; i < agentsForOtherSide.length; i++) {
                rel.agentsB.push(agentsForOtherSide[i]);
            }
        } else {
            rel.operatorB = msg.sender;
            rel.operatorA = operatorOther;
            for (uint256 i = 0; i < agentsForCallerSide.length; i++) {
                rel.agentsB.push(agentsForCallerSide[i]);
            }
            for (uint256 i = 0; i < agentsForOtherSide.length; i++) {
                rel.agentsA.push(agentsForOtherSide[i]);
            }
        }

        for (uint256 i = 0; i < allowedCategories.length; i++) {
            rel.allowedCategories.push(allowedCategories[i]);
        }

        emit RelationshipRegistered(
            relationshipId, principalA, principalB, allowedCategories
        );
    }

    // ── Revocation ────────────────────────────────────────────────────

    /**
     * @notice Either operator can revoke the relationship unilaterally.
     */
    function revokeRelationship(bytes32 relationshipId) external {
        Relationship storage rel = relationships[relationshipId];
        require(rel.exists, "CPP: unknown relationship");
        require(!rel.revoked, "CPP: already revoked");

        bool isOperatorA = msg.sender == rel.operatorA;
        bool isOperatorB = msg.sender == rel.operatorB;
        require(isOperatorA || isOperatorB, "CPP: not operator");

        rel.revoked = true;
        bytes32 revokingPrincipal = isOperatorA ? rel.principalA : rel.principalB;
        emit RelationshipRevoked(relationshipId, msg.sender, revokingPrincipal);
    }

    // ── Authorization ─────────────────────────────────────────────────

    /**
     * @notice Verify a cross-principal action — both sides must sign.
     */
    function verifyCrossAction(CrossAction calldata action) external returns (bool) {
        Relationship storage rel = relationships[action.relationshipId];

        if (!rel.exists) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.UnknownRelationship
            );
            revert("CPP: unknown relationship");
        }

        if (rel.revoked) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.RelationshipRevoked
            );
            revert("CPP: revoked");
        }

        if (consumedActionHashes[action.actionHash]) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.Replay
            );
            revert("CPP: replay");
        }

        if (action.agentA == action.agentB) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.AgentsAreSame
            );
            revert("CPP: same agent both sides");
        }

        // Check category is in the allowed list
        if (!_isCategoryAllowed(action.category, rel.allowedCategories)) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.CategoryNotAllowed
            );
            revert("CPP: category not allowed");
        }

        // Check agentA is authorized for principal A
        if (!_isAgentIn(action.agentA, rel.agentsA)) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.AgentANotAuthorized
            );
            revert("CPP: agent A not authorized");
        }

        // Check agentB is authorized for principal B
        if (!_isAgentIn(action.agentB, rel.agentsB)) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.AgentBNotAuthorized
            );
            revert("CPP: agent B not authorized");
        }

        // Verify both signatures
        bytes32 messageHash = keccak256(abi.encodePacked(
            action.relationshipId,
            action.actionHash,
            action.category,
            action.parametersHash,
            action.agentA,
            action.agentB
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));

        address recoveredA = _recoverSigner(ethSignedHash, action.signatureA);
        if (recoveredA != action.agentA) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.InvalidSignatureA
            );
            revert("CPP: bad sig A");
        }

        address recoveredB = _recoverSigner(ethSignedHash, action.signatureB);
        if (recoveredB != action.agentB) {
            emit CrossActionRejected(
                action.relationshipId, action.actionHash,
                RejectionReason.InvalidSignatureB
            );
            revert("CPP: bad sig B");
        }

        consumedActionHashes[action.actionHash] = true;
        emit CrossActionAuthorized(
            action.relationshipId, action.actionHash,
            action.category, action.agentA, action.agentB
        );
        return true;
    }

    // ── Read-only ─────────────────────────────────────────────────────

    function getRelationship(bytes32 relationshipId) external view returns (
        bytes32 principalA,
        bytes32 principalB,
        address operatorA,
        address operatorB,
        address[] memory agentsA,
        address[] memory agentsB,
        uint8[] memory allowedCategories,
        bool revoked
    ) {
        Relationship storage rel = relationships[relationshipId];
        require(rel.exists, "CPP: unknown relationship");
        return (
            rel.principalA, rel.principalB,
            rel.operatorA, rel.operatorB,
            rel.agentsA, rel.agentsB,
            rel.allowedCategories,
            rel.revoked
        );
    }

    function isActionConsumed(bytes32 actionHash) external view returns (bool) {
        return consumedActionHashes[actionHash];
    }

    // ── Internal helpers ──────────────────────────────────────────────

    function _validateAgentList(address[] calldata agents) internal pure {
        for (uint256 i = 0; i < agents.length; i++) {
            require(agents[i] != address(0), "CPP: zero agent");
            for (uint256 j = i + 1; j < agents.length; j++) {
                require(agents[i] != agents[j], "CPP: dup agent");
            }
        }
    }

    function _isCategoryAllowed(uint8 category, uint8[] storage allowed)
        internal view returns (bool)
    {
        for (uint256 i = 0; i < allowed.length; i++) {
            if (allowed[i] == category) return true;
        }
        return false;
    }

    function _isAgentIn(address agent, address[] storage list)
        internal view returns (bool)
    {
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == agent) return true;
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
