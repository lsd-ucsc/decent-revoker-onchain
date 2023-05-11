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

    address[] signers1;
    address[] signers2;
    bytes32 m_message1;
    bytes32 m_message2;
    bytes concatenated1;
    bytes concatenated2;
    bool validStakeholder;
    bool isequal;

    function Vote(
        address contractAddr,
        bytes32 enclaveId,
        // bytes memory unhashed,
        bytes32 message,
        bytes32 sigR, 
        bytes32 sigS) 
    public 
    {
        // contract must be this contract
        require (contractAddr == address(this), "invalid contract address");
        
        // enclave must exist
        require (m_enclaveIds[enclaveId] == true, "enclave not found");

        // enclave has not been revoked yet
        require (m_revoked[enclaveId] == false, "enclave already recoked");

        // m_message1 = message;
        // concatenated1 = unhashed;
        // concatenated2 = bytes.concat(bytes20(contractAddr), enclaveId);
        // m_message2 = sha256(concatenated2);

        // isequal = keccak256(concatenated1) == keccak256(concatenated2);

        bytes memory concatenated = bytes.concat(bytes20(contractAddr), enclaveId);
        m_message1 = message;
        m_message2 = sha256(concatenated);
        // bytes32 message = sha256(concatenated);
        
        // signers1 = Common.RecoverSigners(m_message1, sigR, sigS);
        signers2 = Common.RecoverSigners(m_message2, sigR, sigS);

        validStakeholder = false;
        address stakeholder;
        for (uint i = 0; i < signers2.length; i++) {
            if (m_stakeHolders[signers2[i]]) {
                validStakeholder = true;
                stakeholder = signers2[i];
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
    function getConcatenated1() external view returns (bytes memory) {
        return concatenated1;
    }

    function getConcatenated2() external view returns (bytes memory) {
        return concatenated2;
    }

    function isEqual() external view returns (bool) {
        return isequal;
    }


    function isValidStakeholder() external view returns (bool) {
        return validStakeholder;
    }

    function getMessage1() external view returns (bytes32) {
        return m_message1;
    }

    function getMessage2() external view returns (bytes32) {
        return m_message2;
    }

    function getSigners() external view returns (address[] memory) {
        return signers1;
    }

    function getSigners2() external view returns (address[] memory) {
        return signers2;
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
