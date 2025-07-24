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
  
contract SafeValidator is IValidator, IHook {  
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
  
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)  
        external  
        payable  
        override  
        returns (uint256)  
    {  
        address parentSafe = safeValidatorStorage[msg.sender].parentSafe;  
        bytes calldata sig = userOp.signature;  
          
        // Try calling the Safe's isValidSignature function with original hash
        try IERC1271(parentSafe).isValidSignature(userOpHash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {  
                return SIG_VALIDATION_SUCCESS_UINT;  
            }  
        } catch {
            // If the first call fails, continue to try with EIP-191 prefix
        }
          
        // Try with EIP-191 prefixed hash as well (0x19 + 0x01 + domainSeparator + hash)  
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);  
        try IERC1271(parentSafe).isValidSignature(ethHash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {  
                return SIG_VALIDATION_SUCCESS_UINT;  
            }  
        } catch {
            // If both calls fail, return validation failed
        }
          
        return SIG_VALIDATION_FAILED_UINT;  
    }  
  
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)  
        external  
        view  
        override  
        returns (bytes4)  
    {  
        address parentSafe = safeValidatorStorage[msg.sender].parentSafe;  
          
        // Try calling the Safe's isValidSignature function with original hash
        try IERC1271(parentSafe).isValidSignature(hash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {  
                return ERC1271_MAGICVALUE;  
            }  
        } catch {
            // If the first call fails, continue to try with EIP-191 prefix
        }
          
        // Try with EIP-191 prefixed hash as well  
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);  
        try IERC1271(parentSafe).isValidSignature(ethHash, sig) returns (bytes4 magicValue) {
            if (magicValue == ERC1271_MAGICVALUE) {  
                return ERC1271_MAGICVALUE;  
            }  
        } catch {
            // If both calls fail, return invalid
        }
          
        return ERC1271_INVALID;  
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