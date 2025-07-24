// SPDX-License-Identifier: MIT  
  
pragma solidity ^0.8.0;  
  
import {ECDSA} from "solady/utils/ECDSA.sol";  
import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";  
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";  
import {  
    SIG_VALIDATION_SUCCESS_UINT,  
    SIG_VALIDATION_FAILED_UINT,  
    MODULE_TYPE_VALIDATOR,  
    MODULE_TYPE_HOOK,  
    ERC1271_MAGICVALUE,  
    ERC1271_INVALID  
} from "../types/Constants.sol";  
  
// Interface for Gnosis Safe's ERC-1271 implementation  
interface IERC1271 {  
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);  
}  
  
struct SafeValidatorStorage {  
    address parentSafe;  
}  
  
/**
 * @title SafeValidatorBypass
 * @dev Testing validator that bypasses actual Safe signature validation
 * WARNING: This validator always returns valid for ANY signature - USE ONLY FOR TESTING
 */
contract SafeValidatorBypass is IValidator, IHook {  
    event ParentSafeRegistered(address indexed kernel, address indexed parentSafe);  
  
    mapping(address => SafeValidatorStorage) public safeValidatorStorage;  
  
    function onInstall(bytes calldata _data) external payable override {  
        address parentSafe = address(bytes20(_data[0:20]));  
        safeValidatorStorage[msg.sender].parentSafe = parentSafe;  
        emit ParentSafeRegistered(msg.sender, parentSafe);  
    }  
  
    function onUninstall(bytes calldata) external payable override {  
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);  
        delete safeValidatorStorage[msg.sender];  
    }  
  
    function isModuleType(uint256 typeID) external pure override returns (bool) {  
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;  
    }  
  
    function isInitialized(address smartAccount) external view override returns (bool) {  
        return _isInitialized(smartAccount);  
    }  
  
    function _isInitialized(address smartAccount) internal view returns (bool) {  
        return safeValidatorStorage[smartAccount].parentSafe != address(0);  
    }  
  
    /**
     * @dev TESTING FUNCTION - Always returns valid for any user operation
     * WARNING: This bypasses all security checks - USE ONLY FOR TESTING
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)  
        external  
        payable  
        override  
        returns (uint256)  
    {  
        // Check that this validator is properly initialized for this account
        /* address parentSafe = safeValidatorStorage[msg.sender].parentSafe;  
        if (parentSafe == address(0)) {  
            return SIG_VALIDATION_FAILED_UINT;  
        }   */
        
        // For testing purposes, always return success without checking actual signature
        // In a real implementation, this would validate against the Safe's signature
        return SIG_VALIDATION_SUCCESS_UINT;  
    }  
  
    /**
     * @dev TESTING FUNCTION - Always returns valid for any signature
     * WARNING: This bypasses all security checks - USE ONLY FOR TESTING
     */
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)  
        external  
        view  
        override  
        returns (bytes4)  
    {  
        // Check that this validator is properly initialized for this account
        //address parentSafe = safeValidatorStorage[msg.sender].parentSafe;  
        //if (parentSafe == address(0)) {  
          //  return ERC1271_INVALID;  
        //}  
        
        // For testing purposes, always return valid magic value without checking actual signature
        // In a real implementation, this would validate against the Safe's signature
        return ERC1271_MAGICVALUE;  
    }  
  
    // Hook implementation (required for IHook interface)  
    function preCheck(address, uint256, bytes calldata)  
        external  
        payable  
        override  
        returns (bytes memory)  
    {  
        // No pre-check logic needed for this validator  
        return "";  
    }  
  
    function postCheck(bytes calldata) external payable override {  
        // No post-check logic needed for this validator  
    }  
}