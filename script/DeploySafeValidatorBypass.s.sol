// SPDX-License-Identifier: MIT  
pragma solidity ^0.8.0;  
  
import "forge-std/Script.sol";  
import "../src/validator/SafeValidatorBypass.sol";  
  
contract DeploySafeValidatorBypass is Script {  
    function run() external {  
        vm.startBroadcast();  
          
        // Deploy SafeValidator using CREATE2 for deterministic address  
        SafeValidatorBypass safeValidatorBypass = new SafeValidatorBypass{salt: bytes32(0)}();  
          
        console.log("SafeValidatorBypass deployed at:", address(safeValidatorBypass));  
          
        vm.stopBroadcast();  
    }  
}