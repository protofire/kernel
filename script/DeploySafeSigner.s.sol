// SPDX-License-Identifier: MIT  
pragma solidity ^0.8.0;  
  
import "forge-std/Script.sol";  
import "../src/signer/SafeSigner.sol";  
  
contract DeploySafeSigner is Script {  
    function run() external {  
        vm.startBroadcast();  
          
        // Deploy SafeValidator using CREATE2 for deterministic address  
        SafeSigner safeSigner = new SafeSigner{salt: bytes32(0)}();  
          
        console.log("SafeSigner deployed at:", address(safeSigner));  
          
        vm.stopBroadcast();  
    }  
}