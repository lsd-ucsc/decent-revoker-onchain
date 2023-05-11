// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Common} from "./Common.sol";
import {Revoker} from "./Revoker.sol";
import {RLPReader} from "libs/DecentRA/contracts/rlp/RLPReader.sol";

contract VotingRevoker is Revoker {  

    //===== structs =====

    struct VoteStruct {
        uint numVotes;
        mapping (address => bool) stakeholder;
    }

    //===== member variables =====

    uint m_vote_threshold;

    mapping (bytes32 => bool) m_revoked;

    // map enclaves to vote struct {numvotes, voters(map)}
    mapping (bytes32 => VoteStruct) m_votes;
    
    //===== Constructor =====

    constructor(
        bytes32[] memory enclaves,
        address[] memory stakeholders
    )
    Revoker(enclaves, stakeholders) {
        // we need at least 3 stakeholders to enforce a vote threshold of 2/3
        require(stakeholders.length >= 3, "must have at least three stakeholders");
        m_vote_threshold = (stakeholders.length / 3) * 2;

        for (uint i = 0; i < enclaves.length; i++) {
            m_votes[enclaves[i]].numVotes = 0;
        }    

    }
    
    //===== functions =====

    function Vote(
        address contractAddr,
        bytes32 enclaveId,
        bytes32 sigR, 
        bytes32 sigS) 
    public
    {
        // contract must be this contract
        // require (contractAddr == address(this), "invalid contract address");
        
        // enclave must exist
        require (m_enclaveIds[enclaveId] == true, "enclave not found");
        
        // enclave has not been revoked yet
        require (m_revoked[enclaveId] == false, "enclave already revoked");

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

        // stakeholder can only vote once
        require (!m_votes[enclaveId].stakeholder[stakeholder], "stakeholder already voted");

        m_votes[enclaveId].stakeholder[stakeholder] = true;
        m_votes[enclaveId].numVotes++;

        // if number of votes more than threshold, revoke
        if (m_votes[enclaveId].numVotes == m_vote_threshold) {            
            m_revoked[enclaveId] = true;
        }        
    } // end Vote()
}
