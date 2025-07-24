// SPDX-License-Identifier: MIT  
pragma solidity ^0.8.0;  
  
import "forge-std/Script.sol";  
import "../src/validator/SafeValidator.sol";  
  
contract DeploySafeValidator is Script {  
    function run() external {  
        vm.startBroadcast();  
          
        // Deploy SafeValidator using CREATE2 for deterministic address  
        SafeValidator safeValidator = new SafeValidator{salt: bytes32(0)}();  
          
        console.log("SafeValidator deployed at:", address(safeValidator));  
          
        vm.stopBroadcast();  
    }  
}