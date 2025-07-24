// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SignerBase} from "../sdk/moduleBase/SignerBase.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants.sol";

// Interface for Gnosis Safe's ERC-1271 implementation
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

contract SafeSignerBypass is SignerBase {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address wallet => address)) public signer;

    event ParentSafeRegisteredForSigner(address indexed kernel, bytes32 indexed id, address indexed parentSafe);

    error NoParentSafeRegistered(address kernel, bytes32 id);
    error ParentSafeCannotBeAddressZero();

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return SIG_VALIDATION_SUCCESS_UINT;
        /* address parentSafe = parentSafes[id][msg.sender];
        if (parentSafe == address(0)) {
            revert NoParentSafeRegistered(msg.sender, id);
        }

        bytes calldata sig = userOp.signature;

        // Try calling the Safe's isValidSignature function with original hash
        try IERC1271(parentSafe).isValidSignature(userOpHash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {
                return SIG_VALIDATION_SUCCESS_UINT;
            }
        } catch {
            // If the first call fails, continue to try with EIP-191 prefix
        }

        // Try with EIP-191 prefixed hash
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);
        try IERC1271(parentSafe).isValidSignature(ethHash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {
                return SIG_VALIDATION_SUCCESS_UINT;
            }
        } catch {
            // If both calls fail, return validation failed
        }

        return SIG_VALIDATION_FAILED_UINT; */
    }

    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        return ERC1271_MAGICVALUE;
        /* address parentSafe = parentSafes[id][msg.sender];
        if (parentSafe == address(0)) {
            // In the context of isValidSignature (ERC1271 query), if the signer isn't set up for this ID/wallet,
            // it should return the invalid magic value rather than reverting.
            return ERC1271_INVALID;
        }

        // Try calling the Safe's isValidSignature function with original hash
        try IERC1271(parentSafe).isValidSignature(hash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {
                return ERC1271_MAGICVALUE;
            }
        } catch {
            // If the first call fails, continue to try with EIP-191 prefix
        }

        // Try with EIP-191 prefixed hash
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        try IERC1271(parentSafe).isValidSignature(ethHash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {
                return ERC1271_MAGICVALUE;
            }
        } catch {
            // If both calls fail, return invalid
        }

        return ERC1271_INVALID; */
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        address parentSafeAddress = address(bytes20(_data[0:20]));
        if (parentSafeAddress == address(0)) {
            revert ParentSafeCannotBeAddressZero();
        }
        if (signer[id][msg.sender] == address(0)) {
             usedIds[msg.sender]++;
        }
        signer[id][msg.sender] = parentSafeAddress;
        emit ParentSafeRegisteredForSigner(msg.sender, id, parentSafeAddress);
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        if (signer[id][msg.sender] == address(0)) {
            revert NoParentSafeRegistered(msg.sender, id);
        }
        delete signer[id][msg.sender];
        usedIds[msg.sender]--;
    }
}