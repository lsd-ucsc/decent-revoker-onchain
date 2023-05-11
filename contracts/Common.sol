// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

library Common {
    function RecoverSigners(
        bytes32 message, 
        bytes32 r, 
        bytes32 s
    ) 
    public pure
    returns (address[] memory)
    {
        address[] memory signers = new address[](2);
        uint i = 0;
        for (uint8 v = 27; v <= 28; v++) {
            signers[i++] = ecrecover(message, v, r, s);            
        }

        return signers;
    }
}