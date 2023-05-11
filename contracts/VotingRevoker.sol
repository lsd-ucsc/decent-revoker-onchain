// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Common} from "./Common.sol";
import {Revoker} from "./Revoker.sol";
import {RLPReader} from "libs/DecentRA/contracts/rlp/RLPReader.sol";

contract VotingRevoker is Revoker {  
    struct VoteStruct {
        uint numVotes;
        mapping (address => bool) stakeholder;
    }


    // map enclaves to vote struct {numvotes, voters(map)}
    mapping (bytes32 => VoteStruct) m_votes;

    // revocation llist
    mapping (bytes32 => bool) m_revoked;
    
    constructor(
        bytes32[] memory enclaves,
        address[] memory stakeholders
    )
    Revoker(enclaves, stakeholders) {
        for (uint i = 0; i < enclaves.length; i++) {
            m_votes[enclaves[i]].numVotes = 0;
        }
    }

    function Vote(
        address contractAddr,
        bytes32 enclaveId,
        bytes32 sigR, 
        bytes32 sigS) 
    public view
    {
        // contract must be this contract
        // require (contractAddr == address(this), "invalid contract address");
        
        // enclave must exist
        require (m_enclaveIds[enclaveId] == true, "enclave not found");

        // enclave has not been revoked yet
        require (m_revoked[enclaveId] == false, "enclave already recoked");

        bytes memory concatenated = bytes.concat(bytes20(contractAddr), enclaveId);      
        bytes32 message = sha256(concatenated);

        address[] memory signers = Common.RecoverSigners(message, sigR, sigS);

        bool validStakeholder = false;
        address stakeholder;
        for (uint i = 0; i < signers.length; i++) {
            if (m_stakeHolders[signers[i]]) {
                validStakeholder = true;
                stakeholder = signers[i];
            }
        }

        // must be a valid stakeholder to vote
        require (validStakeholder == true, "invalid stakeholder");

        // // stakeholder only vote once
        // if (!m_votes[enclaveId].stakeholder[stakeholder]) {
        //     m_votes[enclaveId].stakeholder[stakeholder] = true;
        //     m_votes[enclaveId].numVotes++;

        //     // if number of votes more than threshold, revoke
        //     m_revoked[enclaveId] = true;
        // }
    }

    function numVotes(bytes32 enclaveId) external view returns (uint) {
        return m_votes[enclaveId].numVotes;
    }

    function isRevoked(bytes32 enclaveId) external view returns (bool) {
        return m_revoked[enclaveId];
    }

    function getFirstEnclave(bytes32 enclaveId) external view returns (bool) {
        return m_enclaveIds[enclaveId];
    }

    function getStakeHolder(address addr) external view returns (bool) {
        return m_stakeHolders[addr];
    }


}
