// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {MockUSDC} from "../src/MockUSDC.sol";

/// @dev Dependency-free Foundry tests: the harness intentionally has no forge-std
/// dependency so the release gate does not fetch mutable Solidity packages.
contract MockUSDCTest {
    function testMetadataAndMintAccounting() public {
        MockUSDC token = new MockUSDC();

        require(keccak256(bytes(token.name())) == keccak256("USDC"), "wrong name");
        require(token.decimals() == 6, "wrong decimals");
        require(token.DOMAIN_SEPARATOR() != bytes32(0), "empty domain separator");

        token.mint(address(this), 1_000_000);
        require(token.totalSupply() == 1_000_000, "wrong supply");
        require(token.balanceOf(address(this)) == 1_000_000, "wrong balance");
    }

    function testInvalidAuthorizationDoesNotConsumeNonce() public {
        MockUSDC token = new MockUSDC();
        bytes32 nonce = keccak256("invalid-signature");
        bytes memory invalidSignature = new bytes(65);

        try token.transferWithAuthorization(
            address(this), address(0xBEEF), 1, 0, block.timestamp + 1 hours, nonce, invalidSignature
        ) {
            revert("invalid authorization accepted");
        } catch {}

        require(!token.authorizationState(address(this), nonce), "nonce consumed on rejection");
        require(token.balanceOf(address(0xBEEF)) == 0, "value moved on rejection");
    }

    function testExpiredAuthorizationIsRejectedBeforeSignatureRecovery() public {
        MockUSDC token = new MockUSDC();
        bytes32 nonce = keccak256("expired");
        bytes memory invalidSignature = new bytes(65);

        try token.transferWithAuthorization(
            address(this), address(0xBEEF), 1, 0, block.timestamp, nonce, invalidSignature
        ) {
            revert("expired authorization accepted");
        } catch {}

        require(!token.authorizationState(address(this), nonce), "expired nonce consumed");
    }
}
