// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import {
    Interface_EventManager
} from "../libs/DecentPubSub/PubSub/Interface_EventManager.sol";
import {
    Interface_PubSubService
} from "../libs/DecentPubSub/PubSub/Interface_PubSubService.sol";


contract VotingRevoker {

    //===== structs =====

    struct VoteStruct {
        uint numVotes;
        mapping(address => bool) stakeholder;
    }

    //===== member variables =====

    uint public m_voteThreshold;
    address m_eventMgrAddr;

    mapping(address => bool) m_stakeHolders;
    mapping(bytes32 => bool) m_revoked;

    // map enclaves to vote struct {numvotes, voters(map)}
    mapping(bytes32 => VoteStruct) m_votes;

    //===== Constructor =====

    constructor(
        address pubSubServiceAddr,
        address[] memory stakeholders
    )
    {
        // we need at least 3 stakeholders to enforce a vote threshold of 2/3
        require(
            stakeholders.length >= 3,
            "must have at least 3 stakeholders"
        );

        // make sure all stakeholders are unique
        for (uint i = 0; i < stakeholders.length; i++) {
            for (uint j = i + 1; j < stakeholders.length; j++) {
                require(
                    stakeholders[i] != stakeholders[j],
                    "stakeholders must be unique"
                );
            }
        }

        m_voteThreshold = (stakeholders.length * 2) / 3;
        // multiply first to increase precision
        if (stakeholders.length % 2 == 0) {
            // if we have an even number of stakeholders, we need to increase
            // the threshold by 1 to ensure we have a majority
            m_voteThreshold++;
        }

        for (uint i = 0; i < stakeholders.length; i++) {
            m_stakeHolders[stakeholders[i]] = true;
        }

        m_eventMgrAddr = Interface_PubSubService(pubSubServiceAddr).register();
    }

    //===== functions =====

    function revokeVote(bytes32 enclaveId) external {
        // must be a valid stakeholder to vote
        require(m_stakeHolders[msg.sender], "invalid stakeholder");

        VoteStruct storage vote = m_votes[enclaveId];

        // stakeholder can only vote once
        require (!vote.stakeholder[msg.sender], "stakeholder already voted");

        // record vote
        vote.stakeholder[msg.sender] = true;
        vote.numVotes++;

        // if it's not revoked and we have enough votes, revoke it
        if (!m_revoked[enclaveId] && vote.numVotes >= m_voteThreshold) {
            m_revoked[enclaveId] = true;

            Interface_EventManager(m_eventMgrAddr).notifySubscribers(
                abi.encodePacked(enclaveId)
            );
        }
    } // end revokeVote()

    function isRevoked(bytes32 enclaveId) external view returns (bool) {
        return m_revoked[enclaveId];
    } // end isRevoked()

}
