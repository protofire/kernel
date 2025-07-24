// SPDX-License-Identifier: MIT  
pragma solidity ^0.8.0;  
  
import "forge-std/Script.sol";  
import "../src/signer/SafeSignerBypass.sol";  
  
contract DeploySafeSignerBypass is Script {  
    function run() external {  
        vm.startBroadcast();  
          
        // Deploy SafeValidator using CREATE2 for deterministic address  
        SafeSignerBypass safeSignerBypass = new SafeSignerBypass{salt: bytes32(0)}();  
          
        console.log("SafeSignerBypass deployed at:", address(safeSignerBypass));  
          
        vm.stopBroadcast();  
    }  
}