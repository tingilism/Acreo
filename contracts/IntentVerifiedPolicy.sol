// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title IntentVerifiedPolicy
 * @notice Extension to AgentVerifier that requires each action to declare a
 *         structured intent matching one of the agent's pre-registered
 *         strategy intent categories.
 *
 * @dev Implements OWASP ASI01 (Agent Goal Hijack) defense.
 *
 *      The attack: prompt injection or compromised tool output steers the
 *      agent's reasoning toward unintended actions. A vanilla policy that
 *      only checks numerical bounds (e.g., "trades up to $1000") cannot
 *      catch hijacks where the malicious action stays inside those bounds.
 *
 *      The defense: each action carries a signed `IntentStatement` declaring
 *      its category and parameter hash. The contract verifies the category
 *      is in the agent's strategy's allowed-intent list. A goal-hijack that
 *      produces an action outside the declared strategy class — e.g., a
 *      withdraw when the strategy is "market-make BTC perp" — is refused
 *      at the policy layer before the principal signs.
 *
 *      Scope honestly stated:
 *        - Catches hijacks that produce out-of-category actions
 *        - Does NOT catch hijacks that stay within declared intent categories
 *          (those are addressed by ASI04 oracle confirmation and ASI10
 *          bounded action space, which compose with this)
 *
 *      Architecture choice: in-contract verification. Intent statements
 *      are public so there's no privacy benefit from ZK. The contract
 *      checks category membership and signature; cheap and auditable.
 */
contract IntentVerifiedPolicy {

    // ── Events ────────────────────────────────────────────────────────

    event StrategyRegistered(
        bytes32 indexed strategyId,
        address indexed operator,
        uint8[] allowedIntentCategories,
        bytes32 assetUniverseHash,
        uint16 maxPositionPctBps
    );

    event IntentVerified(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        uint8 intentCategory,
        address agent
    );

    event IntentRejected(
        bytes32 indexed strategyId,
        bytes32 indexed actionHash,
        RejectionReason reason,
        uint8 attemptedCategory
    );

    // ── Types ─────────────────────────────────────────────────────────

    enum RejectionReason {
        UnknownStrategy,
        CategoryNotAllowed,
        InvalidSignature,
        AgentNotAuthorized,
        Replay,
        ActionHashMismatch
    }

    /**
     * @notice An agent's declared strategy.
     * @dev `allowedIntentCategories` is the load-bearing field. An action's
     *      intentCategory must appear in this list to be authorized.
     */
    struct Strategy {
        address operator;                    // who registered the strategy
        uint8[] allowedIntentCategories;     // e.g. [PLACE_ORDER, CANCEL_ORDER, UPDATE_LEVERAGE]
        bytes32 assetUniverseHash;           // hash of allowed assets (off-chain expandable)
        uint16 maxPositionPctBps;            // max single position as bps of account
        address[] authorizedAgents;          // agents allowed to sign for this strategy
        bool exists;
    }

    /**
     * @notice A signed declaration of intent attached to each action.
     * @dev The agent (or the LLM scaffolding) signs this and includes it with
     *      the action submission. The contract verifies the agent is in the
     *      strategy's authorized list and the category is allowed.
     */
    struct IntentStatement {
        bytes32 strategyId;       // which strategy this action belongs to
        bytes32 actionHash;       // hash of the action this intent justifies
        uint8 intentCategory;     // category id (must be in strategy.allowedIntentCategories)
        bytes32 parametersHash;   // keccak256 of natural-language intent string
        address agent;            // agent address that signed this
        bytes signature;          // signature over the above fields
    }

    /**
     * @notice Canonical intent categories. Strategies declare which they allow.
     * @dev Reserved range 0-31; bots can extend with custom categories 32-255
     *      by registering them off-chain in the strategy's documentation.
     */
    uint8 public constant CATEGORY_PLACE_ORDER = 1;
    uint8 public constant CATEGORY_CANCEL_ORDER = 2;
    uint8 public constant CATEGORY_UPDATE_LEVERAGE = 3;
    uint8 public constant CATEGORY_TRANSFER = 4;
    uint8 public constant CATEGORY_WITHDRAW = 5;
    uint8 public constant CATEGORY_APPROVE_AGENT = 6;
    uint8 public constant CATEGORY_REBALANCE = 7;
    uint8 public constant CATEGORY_CLOSE_POSITION = 8;

    // ── Storage ───────────────────────────────────────────────────────

    mapping(bytes32 => Strategy) public strategies;
    mapping(bytes32 => bool) public consumedActionHashes;

    // ── Strategy registration ─────────────────────────────────────────

    /**
     * @notice Register a new strategy with its allowed intent categories.
     * @param strategyId                 Unique identifier
     * @param allowedIntentCategories   Categories the agent is allowed to take
     * @param assetUniverseHash         Off-chain hash of allowed asset list
     * @param maxPositionPctBps         Max single position as bps of account
     * @param authorizedAgents          Agent addresses allowed to act under this strategy
     */
    function registerStrategy(
        bytes32 strategyId,
        uint8[] calldata allowedIntentCategories,
        bytes32 assetUniverseHash,
        uint16 maxPositionPctBps,
        address[] calldata authorizedAgents
    ) external {
        require(!strategies[strategyId].exists, "IVP: strategy exists");
        require(allowedIntentCategories.length > 0, "IVP: no categories");
        require(allowedIntentCategories.length <= 32, "IVP: too many categories");
        require(maxPositionPctBps <= 10000, "IVP: bad position bps");
        require(authorizedAgents.length > 0, "IVP: no agents");

        // Reject duplicates in category list
        for (uint256 i = 0; i < allowedIntentCategories.length; i++) {
            require(allowedIntentCategories[i] > 0, "IVP: zero category");
            for (uint256 j = i + 1; j < allowedIntentCategories.length; j++) {
                require(
                    allowedIntentCategories[i] != allowedIntentCategories[j],
                    "IVP: dup category"
                );
            }
        }

        // Reject duplicates in agent list
        for (uint256 i = 0; i < authorizedAgents.length; i++) {
            require(authorizedAgents[i] != address(0), "IVP: zero agent");
            for (uint256 j = i + 1; j < authorizedAgents.length; j++) {
                require(
                    authorizedAgents[i] != authorizedAgents[j],
                    "IVP: dup agent"
                );
            }
        }

        strategies[strategyId] = Strategy({
            operator: msg.sender,
            allowedIntentCategories: allowedIntentCategories,
            assetUniverseHash: assetUniverseHash,
            maxPositionPctBps: maxPositionPctBps,
            authorizedAgents: authorizedAgents,
            exists: true
        });

        emit StrategyRegistered(
            strategyId, msg.sender, allowedIntentCategories,
            assetUniverseHash, maxPositionPctBps
        );
    }

    // ── Intent verification ───────────────────────────────────────────

    /**
     * @notice Verify an action's intent matches the agent's declared strategy.
     * @param intent  The signed intent statement attached to the action
     * @return verified  True if the action is authorized
     */
    function verifyIntent(IntentStatement calldata intent)
        external
        returns (bool verified)
    {
        Strategy storage strat = strategies[intent.strategyId];
        if (!strat.exists) {
            emit IntentRejected(
                intent.strategyId, intent.actionHash,
                RejectionReason.UnknownStrategy, intent.intentCategory
            );
            revert("IVP: unknown strategy");
        }

        // Replay protection at the action level
        if (consumedActionHashes[intent.actionHash]) {
            emit IntentRejected(
                intent.strategyId, intent.actionHash,
                RejectionReason.Replay, intent.intentCategory
            );
            revert("IVP: replay");
        }

        // Check agent is authorized for this strategy
        if (!_isAgentAuthorized(intent.agent, strat.authorizedAgents)) {
            emit IntentRejected(
                intent.strategyId, intent.actionHash,
                RejectionReason.AgentNotAuthorized, intent.intentCategory
            );
            revert("IVP: agent not authorized");
        }

        // The load-bearing check: is this intent category in the allowed set?
        if (!_isCategoryAllowed(intent.intentCategory, strat.allowedIntentCategories)) {
            emit IntentRejected(
                intent.strategyId, intent.actionHash,
                RejectionReason.CategoryNotAllowed, intent.intentCategory
            );
            revert("IVP: category not allowed");
        }

        // Verify the signature matches the claimed agent
        bytes32 messageHash = keccak256(abi.encodePacked(
            intent.strategyId,
            intent.actionHash,
            intent.intentCategory,
            intent.parametersHash,
            intent.agent
        ));
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", messageHash
        ));
        address recovered = _recoverSigner(ethSignedHash, intent.signature);
        if (recovered != intent.agent) {
            emit IntentRejected(
                intent.strategyId, intent.actionHash,
                RejectionReason.InvalidSignature, intent.intentCategory
            );
            revert("IVP: bad sig");
        }

        // All checks passed
        consumedActionHashes[intent.actionHash] = true;
        emit IntentVerified(
            intent.strategyId, intent.actionHash,
            intent.intentCategory, intent.agent
        );
        return true;
    }

    // ── Read-only helpers ─────────────────────────────────────────────

    function getStrategy(bytes32 strategyId) external view returns (
        address operator,
        uint8[] memory allowedIntentCategories,
        bytes32 assetUniverseHash,
        uint16 maxPositionPctBps,
        address[] memory authorizedAgents
    ) {
        Strategy storage strat = strategies[strategyId];
        require(strat.exists, "IVP: unknown strategy");
        return (
            strat.operator,
            strat.allowedIntentCategories,
            strat.assetUniverseHash,
            strat.maxPositionPctBps,
            strat.authorizedAgents
        );
    }

    function isActionConsumed(bytes32 actionHash) external view returns (bool) {
        return consumedActionHashes[actionHash];
    }

    function isCategoryAllowed(bytes32 strategyId, uint8 category)
        external
        view
        returns (bool)
    {
        Strategy storage strat = strategies[strategyId];
        if (!strat.exists) return false;
        return _isCategoryAllowed(category, strat.allowedIntentCategories);
    }

    // ── Internal helpers ──────────────────────────────────────────────

    function _isCategoryAllowed(uint8 category, uint8[] storage allowed)
        internal
        view
        returns (bool)
    {
        for (uint256 i = 0; i < allowed.length; i++) {
            if (allowed[i] == category) return true;
        }
        return false;
    }

    function _isAgentAuthorized(address agent, address[] storage authorized)
        internal
        view
        returns (bool)
    {
        for (uint256 i = 0; i < authorized.length; i++) {
            if (authorized[i] == agent) return true;
        }
        return false;
    }

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
