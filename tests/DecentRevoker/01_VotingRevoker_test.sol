// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {VotingRevoker} from "../../DecentRevoker/VotingRevoker.sol";

import {RevokeSubscriber} from "../RevokeSubscriber.sol";
import {VotingContract} from "./01_VotingContract.sol";


contract VotingRevokerTest {

    address[] m_stakeHolders;
    address m_pubSubSvcAddr;
    address m_revokerAddr;

    function beforeAll() public {
        address[] memory stakeHolders = new address[](3);
        stakeHolders[0] = address(new VotingContract());
        stakeHolders[1] = address(new VotingContract());
        stakeHolders[2] = address(new VotingContract());
        m_stakeHolders = stakeHolders;

        m_pubSubSvcAddr = 0x80922Db6752eCe1C2DeFA54Beb8FB984E649308B;
        m_revokerAddr =
            address(new VotingRevoker(m_pubSubSvcAddr, m_stakeHolders));
    }

    function notEnoughStakeholders() public {
        address[] memory stakeHolders = new address[](2);
        stakeHolders[0] = TestsAccounts.getAccount(0);
        stakeHolders[1] = TestsAccounts.getAccount(1);

        try new VotingRevoker(m_pubSubSvcAddr, stakeHolders) {
            Assert.ok(false, "should not be able to deploy with 2 stakeholders");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "must have at least 3 stakeholders",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function duplicatedStakeholders() public {
        address[] memory stakeHolders = new address[](3);
        stakeHolders[0] = TestsAccounts.getAccount(0);
        stakeHolders[1] = TestsAccounts.getAccount(1);
        stakeHolders[2] = TestsAccounts.getAccount(0);

        try new VotingRevoker(m_pubSubSvcAddr, stakeHolders) {
            Assert.ok(
                false,
                "should not be able to deploy with duplicated stakeholders"
            );
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "stakeholders must be unique",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function oddNumStakeholders() public {
        address[] memory stakeHolders = new address[](3);
        stakeHolders[0] = TestsAccounts.getAccount(0);
        stakeHolders[1] = TestsAccounts.getAccount(1);
        stakeHolders[2] = TestsAccounts.getAccount(2);

        try new VotingRevoker(m_pubSubSvcAddr, stakeHolders)
            returns (VotingRevoker revoker)
        {
            Assert.equal(
                revoker.m_voteThreshold(),
                2,
                "vote threshold should be 2"
            );
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function evenNumStakeholders() public {
        address[] memory stakeHolders = new address[](4);
        stakeHolders[0] = TestsAccounts.getAccount(0);
        stakeHolders[1] = TestsAccounts.getAccount(1);
        stakeHolders[2] = TestsAccounts.getAccount(2);
        stakeHolders[3] = TestsAccounts.getAccount(3);

        try new VotingRevoker(m_pubSubSvcAddr, stakeHolders)
            returns (VotingRevoker revoker)
        {
            Assert.equal(
                revoker.m_voteThreshold(),
                3,
                "vote threshold should be 3"
            );
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function invalidStakeholderTest() public {
        bytes32 enclaveId =
            0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF;

        VotingContract vc = new VotingContract();
        try vc.doRevokeVote(m_revokerAddr, enclaveId) {
            Assert.ok(false, "stakeholder should not be valid");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "invalid stakeholder",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function stakeholderDoubleVoteTest() public {
        bytes32 enclaveId =
            0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF;

        address revokerAddr =
            address(new VotingRevoker(m_pubSubSvcAddr, m_stakeHolders));

        // first vote should succeed
        {
            try VotingContract(m_stakeHolders[0]).doRevokeVote(
                revokerAddr,
                enclaveId
            ) {
                Assert.ok(true, "stakeholder voted successfully");
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory) {
                Assert.ok(false, "Unexpected revert");
            }
        }

        // second vote should not succeed
        {
            try VotingContract(m_stakeHolders[0]).doRevokeVote(
                revokerAddr,
                enclaveId
            ) {
                Assert.ok(false, "stakeholder should not be able to vote twice");
            } catch Error(string memory reason) {
                Assert.equal(
                    reason,
                    "stakeholder already voted",
                    reason
                );
            } catch (bytes memory) {
                Assert.ok(false, "Unexpected revert");
            }
        }
    } // end stakeholderDoubleVoteTest

    /// #value: 1000000000000000000
    function voteTest() public payable {
        bytes32 enclaveId =
            0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF;

        address revokerAddr =
            address(new VotingRevoker(m_pubSubSvcAddr, m_stakeHolders));

        RevokeSubscriber sub = new RevokeSubscriber();
        sub.subscribe{
            value: msg.value
        }(m_pubSubSvcAddr, revokerAddr);

        // first stakeholder vote
        try VotingContract(m_stakeHolders[0]).doRevokeVote(
            revokerAddr,
            enclaveId
        ) {
            Assert.ok(true, "stakeholder voted successfully");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "1st vote Unexpected revert");
        }

        Assert.ok(
            !VotingRevoker(revokerAddr).isRevoked(enclaveId),
            "should not be revoked"
        );

        Assert.greaterThan(
            uint256(gasleft()),
            uint256(90000 + 202000 + 90000),
            "not enough gas left"
        );

        // second stakeholder vote
        try VotingContract(m_stakeHolders[1]).doRevokeVote(
            revokerAddr,
            enclaveId
        ) {
            Assert.ok(true, "stakeholder voted successfully");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "2nd vote Unexpected revert");
        }

        Assert.ok(
            VotingRevoker(revokerAddr).isRevoked(enclaveId),
            "should be revoked"
        );
        Assert.equal(
            sub.m_enclaveId(),
            enclaveId,
            "enclaveId should match"
        );

        // third stakeholder vote
        try VotingContract(m_stakeHolders[2]).doRevokeVote(
            revokerAddr,
            enclaveId
        ) {
            Assert.ok(true, "stakeholder voted successfully");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "3rd vote Unexpected revert");
        }

        Assert.ok(
            VotingRevoker(revokerAddr).isRevoked(enclaveId),
            "should be revoked"
        );
    } // end VoteTest

}
