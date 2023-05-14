// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract VotingRevoker {

    //===== structs =====

    struct VoteStruct {
        uint numVotes;
        mapping (address => bool) stakeholder;
    }

    //===== member variables =====

    uint m_vote_threshold;

    mapping(bytes32 => bool) m_enclaveIds;
    mapping(address => bool) m_stakeHolders;
    mapping (bytes32 => bool) m_revoked;

    // map enclaves to vote struct {numvotes, voters(map)}
    mapping (bytes32 => VoteStruct) m_votes;

    //===== Constructor =====

    constructor(
        bytes32[] memory enclaveIds,
        address[] memory stakeholders
    )
    {
        // we need at least 3 stakeholders to enforce a vote threshold of 2/3
        require(
            stakeholders.length >= 3,
            "must have at least three stakeholders"
        );

        m_vote_threshold = (stakeholders.length / 3) * 2;

        for (uint i = 0; i < enclaveIds.length; i++) {
            m_votes[enclaveIds[i]].numVotes = 0;
        }

        for (uint i = 0; i < enclaveIds.length; i++) {
            m_enclaveIds[enclaveIds[i]] = true;
        }

        for (uint i = 0; i < stakeholders.length; i++) {
            m_stakeHolders[stakeholders[i]] = true;
        }

    }

    //===== functions =====

    function Vote(
        address contractAddr,
        bytes32 enclaveId,
        bytes32 sigR,
        bytes32 sigS
    )
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

        bool validStakeholder = false;
        address stakeholder;

        for (uint8 recoverId = 27; recoverId <= 28; recoverId++) {
            address signer = ecrecover(message, recoverId, sigR, sigS);

            if (m_stakeHolders[signer]) {
                validStakeholder = true;
                stakeholder = signer;
                break;
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
