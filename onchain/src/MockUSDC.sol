// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title MockUSDC — a faithful, self-contained EIP-3009 token for local testing.
/// @notice Verifies the EIP-712 `TransferWithAuthorization` signature ON-CHAIN and
///         tracks per-authorizer nonces, exactly like USDC (FiatTokenV2). This is
///         what makes settlement faithful and unlocks nonce-reuse / replay tests.
///
/// No external imports → deploys with a single `forge create`, no `forge install`.
/// Domain: name="USDC", version="2", chainId=block.chainid, verifyingContract=this.
/// Run Anvil with `--chain-id 84532` so the on-chain domain matches the suite's
/// off-chain signing (eip155:84532).
contract MockUSDC {
    string public constant name = "USDC";
    string public constant version = "2";
    string public constant symbol = "USDC";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    // authorizer => nonce => used
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    event Transfer(address indexed from, address indexed to, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /// @notice Open mint for testing — fund any account with test USDC.
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice EIP-3009 gasless transfer (packed `bytes` signature overload).
    ///         The facilitator submits this; the payer pays nothing on-chain (only
    ///         signs). Reverts on bad sig, used nonce, out-of-window, or insufficient
    ///         balance — mirroring real USDC (FiatTokenV2_2).
    /// @dev Real USDC exposes BOTH this `bytes` overload and the `(v, r, s)` overload
    ///      below. x402 facilitators pick between them by how they classify the
    ///      signature (EOA → v/r/s; EIP-1271/6492 → bytes), so a faithful mock must
    ///      implement both selectors — otherwise a facilitator that chose the missing
    ///      overload hits the fallback and reverts with empty data ("0x").
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        bytes32 digest = _authorize(from, to, value, validAfter, validBefore, nonce);
        require(_recover(digest, signature) == from, "auth: invalid signature");
        _finalize(from, to, value, nonce);
    }

    /// @notice EIP-3009 gasless transfer (`(v, r, s)` overload). Same semantics as the
    ///         `bytes` overload above; provided for parity with real USDC's ABI.
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = _authorize(from, to, value, validAfter, validBefore, nonce);
        if (v < 27) {
            v += 27; // tolerate 0/1 recovery id
        }
        require(ecrecover(digest, v, r, s) == from, "auth: invalid signature");
        _finalize(from, to, value, nonce);
    }

    /// @dev Shared pre-checks (time window, nonce unused) + EIP-712 digest construction.
    function _authorize(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (bytes32) {
        require(block.timestamp > validAfter, "auth: not yet valid");
        require(block.timestamp < validBefore, "auth: expired");
        require(!authorizationState[from][nonce], "auth: nonce already used");

        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    /// @dev Shared settlement: mark the nonce used (replay safety) before moving funds.
    function _finalize(address from, address to, uint256 value, bytes32 nonce) internal {
        authorizationState[from][nonce] = true; // mark before transfer (replay safety)
        require(balanceOf[from] >= value, "insufficient balance");
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit AuthorizationUsed(from, nonce);
        emit Transfer(from, to, value);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) {
            v += 27; // tolerate 0/1 recovery id
        }
        return ecrecover(digest, v, r, s);
    }
}
