// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AgentVerifier
 * @author Acreo Protocol
 * @notice On-chain ZK proof verifier for AI agent authorization.
 *
 * Every AI agent must present a valid Acreo ZK proof before acting.
 * Deployed on Polygon — 0.001 MATIC per verification.
 *
 * Security notes:
 *  - Replay protection is keyed on keccak256(agentKey, nonce) so the
 *    same nonce is reusable across distinct agents without collision.
 *  - Fee is forwarded to treasury with .call{value:}() so contract
 *    treasuries (Safes, multisigs) work without running out of gas.
 *  - Timestamps are plain seconds (matches block.timestamp) — the
 *    off-chain client sends seconds, not milliseconds.
 */
contract AgentVerifier {

    event ProofVerified(address indexed agentKey, bytes32 indexed action, bytes32 proofId, uint256 feePaid);
    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event TreasuryUpdated(address oldTreasury, address newTreasury);
    event OwnershipTransferred(address oldOwner, address newOwner);

    uint256 public constant PROOF_TTL_SECONDS = 300;       // 5 minutes
    uint256 public constant MAX_FUTURE_SKEW   = 60;        // 1 minute clock drift allowance
    uint256 public constant MAX_FEE           = 0.01 ether;
    string  public constant VERSION           = "1.0.0";
    string  public constant PROTOCOL          = "acreo-v1";

    address public owner;
    address public treasury;
    uint256 public verifyFee;

    uint256 public totalVerifications;
    uint256 public totalFeesCollected;

    mapping(bytes32 => bool) private _usedNonces;

    constructor(address _treasury, uint256 _verifyFee) {
        require(_treasury != address(0), "Zero treasury");
        require(_verifyFee <= MAX_FEE, "Fee too high");
        owner     = msg.sender;
        treasury  = _treasury;
        verifyFee = _verifyFee;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    /**
     * @notice Verify a ZK proof and charge the verify fee.
     * @dev timestamp is in seconds (Unix epoch). The off-chain client must
     *      produce seconds, not milliseconds.
     */
    function verifyAndCharge(
        bytes32 proof,
        address agentKey,
        bytes32 action,
        bytes32 resource,
        uint256 timestamp,
        bytes32 nonce,
        bytes calldata signature
    ) external payable returns (bool) {
        require(msg.value >= verifyFee, "Insufficient fee");
        _checkFreshness(timestamp);
        _checkReplay(agentKey, nonce);
        _checkChallenge(proof, agentKey, action, resource, timestamp, nonce);
        _checkSignature(proof, agentKey, signature);

        // Mark nonce used BEFORE external call — CEI pattern.
        bytes32 nonceKey = keccak256(abi.encodePacked(agentKey, nonce));
        _usedNonces[nonceKey] = true;
        totalVerifications++;
        totalFeesCollected += msg.value;

        emit ProofVerified(agentKey, action, proof, msg.value);

        // Forward fee to treasury. Use .call so contract treasuries
        // (Gnosis Safe, DAO multisigs) do not revert due to 2300-gas stipend.
        (bool sent, ) = payable(treasury).call{value: msg.value}("");
        require(sent, "Treasury transfer failed");

        return true;
    }

    function _checkFreshness(uint256 timestamp) internal view {
        require(timestamp + PROOF_TTL_SECONDS >= block.timestamp, "Proof expired");
        require(timestamp <= block.timestamp + MAX_FUTURE_SKEW, "Future timestamp");
    }

    function _checkReplay(address agentKey, bytes32 nonce) internal view {
        bytes32 nonceKey = keccak256(abi.encodePacked(agentKey, nonce));
        require(!_usedNonces[nonceKey], "Replay attack");
    }

    function _checkChallenge(
        bytes32 proof,
        address agentKey,
        bytes32 action,
        bytes32 resource,
        uint256 timestamp,
        bytes32 nonce
    ) internal pure {
        bytes32 expected = keccak256(abi.encodePacked(
            agentKey, action, resource, timestamp, nonce, "acreo-v1"
        ));
        require(expected == proof, "Challenge mismatch");
    }

    function _checkSignature(
        bytes32 proof,
        address agentKey,
        bytes calldata signature
    ) internal pure {
        bytes32 ethHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", proof
        ));
        address recovered = _recover(ethHash, signature);
        require(recovered != address(0) && recovered == agentKey, "Invalid signature");
    }

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        // EIP-2 low-s check — prevents signature malleability
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(hash, v, r, s);
    }

    /**
     * @notice Check whether a (agentKey, nonce) pair has been consumed.
     * @dev Prior versions took only `nonce` and would silently return false
     *      because the storage key is keccak256(agentKey, nonce). Fixed.
     */
    function isNonceUsed(address agentKey, bytes32 nonce) external view returns (bool) {
        return _usedNonces[keccak256(abi.encodePacked(agentKey, nonce))];
    }

    /**
     * @notice Free read-only verification for simulations / static calls.
     *         Does not mark the nonce as used.
     */
    function verifyFree(
        bytes32 proof,
        address agentKey,
        bytes32 action,
        bytes32 resource,
        uint256 timestamp,
        bytes32 nonce,
        bytes calldata signature
    ) external view returns (bool, string memory) {
        if (timestamp + PROOF_TTL_SECONDS < block.timestamp) return (false, "proof_expired");
        if (timestamp > block.timestamp + MAX_FUTURE_SKEW)   return (false, "future_timestamp");
        bytes32 nonceKey = keccak256(abi.encodePacked(agentKey, nonce));
        if (_usedNonces[nonceKey]) return (false, "replay_attack");
        bytes32 expected = keccak256(abi.encodePacked(agentKey, action, resource, timestamp, nonce, PROTOCOL));
        if (expected != proof) return (false, "challenge_mismatch");
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", proof));
        address recovered = _recover(ethHash, signature);
        if (recovered == address(0) || recovered != agentKey) return (false, "signature_invalid");
        return (true, "");
    }

    function getStats() external view returns (uint256, uint256) {
        return (totalVerifications, totalFeesCollected);
    }

    function setFee(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE, "Fee too high");
        emit FeeUpdated(verifyFee, newFee);
        verifyFee = newFee;
    }

    function setTreasury(address newTreasury) external onlyOwner {
        require(newTreasury != address(0), "Zero address");
        emit TreasuryUpdated(treasury, newTreasury);
        treasury = newTreasury;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    receive() external payable {}
}
