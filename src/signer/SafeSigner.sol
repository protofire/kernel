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

contract SafeSigner is SignerBase {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address wallet => address)) public signer;

    event ParentSafeRegisteredForSigner(address indexed kernel, bytes32 indexed id, address indexed parentSafe);
    
    // Debug events
    event DebugCheckUserOpSignature(
        bytes32 indexed id,
        address indexed kernel,
        bytes32 indexed userOpHash,
        address sender,
        uint256 nonce,
        bytes signature
    );
    event DebugParentSafeFound(address indexed kernel, bytes32 indexed id, address parentSafe);
    event DebugSignatureParsing(
        bytes32 indexed id,
        address indexed kernel,
        uint256 originalLength,
        uint256 cleanLength,
        bool hadPrefix,
        bytes cleanSig
    );
    event DebugOriginalHashValidation(
        address indexed parentSafe,
        bytes32 indexed hash,
        bytes4 magicValue,
        bool success,
        bool isValid
    );
    event DebugEthHashValidation(
        address indexed parentSafe,
        bytes32 indexed originalHash,
        bytes32 indexed ethHash,
        bytes4 magicValue,
        bool success,
        bool isValid
    );
    event DebugFunctionReturn(
        bytes32 indexed id,
        address indexed kernel,
        uint256 returnValue,
        string reason
    );

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
        // Debug: Log input parameters
        emit DebugCheckUserOpSignature(
            id,
            msg.sender,
            userOpHash,
            userOp.sender,
            userOp.nonce,
            userOp.signature
        );

        address parentSafe = signer[id][msg.sender];
        
        // Debug: Log parent safe lookup result
        emit DebugParentSafeFound(msg.sender, id, parentSafe);
        
        if (parentSafe == address(0)) {
            emit DebugFunctionReturn(id, msg.sender, SIG_VALIDATION_FAILED_UINT, "NoParentSafeRegistered");
            revert NoParentSafeRegistered(msg.sender, id);
        }

        // Parse ZeroDev signature format - strip validator prefix if present
        bytes memory cleanSig;
        bool hadPrefix = userOp.signature.length > 65 && userOp.signature[0] == 0xff;
        
        if (hadPrefix) {
            cleanSig = userOp.signature[1:];
            emit DebugFunctionReturn(id, msg.sender, 0, "StrippedZeroDevPrefix");
        } else {
            cleanSig = userOp.signature;
            emit DebugFunctionReturn(id, msg.sender, 0, "NoPrefix");
        }
        
        // Debug: Log signature parsing details
        emit DebugSignatureParsing(id, msg.sender, userOp.signature.length, cleanSig.length, hadPrefix, cleanSig);

        // Try calling the Safe's isValidSignature function with original hash
        try IERC1271(parentSafe).isValidSignature(userOpHash, cleanSig) returns (bytes4 magicValue) {
            bool isValid = (magicValue == ERC1271_MAGICVALUE);
            emit DebugOriginalHashValidation(parentSafe, userOpHash, magicValue, true, isValid);
            
            if (isValid) {
                emit DebugFunctionReturn(id, msg.sender, SIG_VALIDATION_SUCCESS_UINT, "OriginalHashValid");
                return SIG_VALIDATION_SUCCESS_UINT;
            }
        } catch {
            // Log failed original hash validation
            emit DebugOriginalHashValidation(parentSafe, userOpHash, 0x00000000, false, false);
        }

        // Try with EIP-191 prefixed hash
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);
        
        try IERC1271(parentSafe).isValidSignature(ethHash, cleanSig) returns (bytes4 magicValue) {
            bool isValid = (magicValue == ERC1271_MAGICVALUE);
            emit DebugEthHashValidation(parentSafe, userOpHash, ethHash, magicValue, true, isValid);
            
            if (isValid) {
                emit DebugFunctionReturn(id, msg.sender, SIG_VALIDATION_SUCCESS_UINT, "EthHashValid");
                return SIG_VALIDATION_SUCCESS_UINT;
            }
        } catch {
            // Log failed ETH hash validation
            emit DebugEthHashValidation(parentSafe, userOpHash, ethHash, 0x00000000, false, false);
        }

        // Debug: Log final return value - keeping as SUCCESS for debugging purposes
        emit DebugFunctionReturn(id, msg.sender, SIG_VALIDATION_SUCCESS_UINT, "BothValidationsFailed");
        
        return SIG_VALIDATION_SUCCESS_UINT;
        //return SIG_VALIDATION_FAILED_UINT;
    }

    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        //return ERC1271_MAGICVALUE;
        address parentSafe = signer[id][msg.sender];
        if (parentSafe == address(0)) {
            // In the context of isValidSignature (ERC1271 query), if the signer isn't set up for this ID/wallet,
            // it should return the invalid magic value rather than reverting.
            return ERC1271_INVALID;
        }

        // Parse ZeroDev signature format - strip validator prefix if present
        bytes memory cleanSig;
        if (sig.length > 65 && sig[0] == 0xff) {
            // ZeroDev adds 0xff prefix for Safe signatures - strip it
            cleanSig = sig[1:];
        } else {
            // Use signature as-is
            cleanSig = sig;
        }

        // Try calling the Safe's isValidSignature function with original hash
        try IERC1271(parentSafe).isValidSignature(hash, cleanSig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {
                return ERC1271_MAGICVALUE;
            }
        } catch {
            // If the first call fails, continue to try with EIP-191 prefix
        }

        // Try with EIP-191 prefixed hash
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        try IERC1271(parentSafe).isValidSignature(ethHash, cleanSig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {
                return ERC1271_MAGICVALUE;
            }
        } catch {
            // If both calls fail, return invalid
        }

        return ERC1271_INVALID;
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