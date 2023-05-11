// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {RLPReader} from "libs/DecentRA/contracts/rlp/RLPReader.sol";

contract Revoker {  
    using RLPReader for RLPReader.RLPItem;

    mapping(bytes32 => bool) m_enclaveIds;
    mapping(address => bool) m_stakeHolders;



    constructor(
        bytes32[] memory enclaveIds,
        address[] memory stakeHolders
    )
    {
        for (uint i = 0; i < enclaveIds.length; i++) {
            m_enclaveIds[enclaveIds[i]] = true;
        }

        for (uint i = 0; i < stakeHolders.length; i++) {
            m_stakeHolders[stakeHolders[i]] = true;
        }
    }    
}
