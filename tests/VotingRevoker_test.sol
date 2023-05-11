// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";

import {VotingRevoker} from "../contracts/VotingRevoker.sol";

contract VotingRevokerTest {
    address m_revokerAddr;
    VotingRevoker m_revoker;
    bytes32[] m_enclaveIds;
    address[] m_stakeHolders;

    function beforeAll() public {        
        m_enclaveIds.push(hex"2b293a7b5cffc0cd9001e423645e280dce6c7350123e57c8de733738d9851b67");
        m_enclaveIds.push(hex"2b293a7b5cffc0cd9001e423645e280dce6c7350123e57c8de733738d9851b68"); 
        m_enclaveIds.push(hex"2b293a7b5cffc0cd9001e423645e280dce6c7350123e57c8de733738d9851b69");

        m_stakeHolders.push(0xc87f9FC3544eAA19BD4e43c55f84318f45094209);
        m_stakeHolders.push(0x33Db9c6743a1A9f0065FC6A6fdFADe58F23Dc056);
        m_stakeHolders.push(0x19abA90DbFFCa8D016040514b6fD64597B171850);
        
        m_revoker = new VotingRevoker(m_enclaveIds, m_stakeHolders);
        m_revokerAddr = address(m_revoker);
    }

    function invalidEnclaveIdTest() public {
        bytes32 sigR = hex"b58dfbf46fbb194a6b27d5c4dfabd35b3ae67d0bea3851b03ce8fbc62857f352";
        bytes32 sigS = hex"a62eecddb8213dc6a06f43cbddc619fbdcc485225557dad467feb612db44a143";
        bytes32 invalidEnclaveId = hex"efe8b57096cb09b4f3a1f80688254b25fa71d76c4da28f00750c0f877bd6aaaa";
        
        try m_revoker.Vote(
            m_revokerAddr,
            invalidEnclaveId,
            sigR,
            sigS
        ) {
            Assert.ok(false, "invalid enclave hash");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "enclave not found",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    /*
        NOTE: checking revoker contract address AND unit testing votes

        Inside the VotingRevoker, the message that is used in signature
        verification is constructed as a concatenation of the revoker address
        and the enclaveId. That is,
            message = concat(revokerAddr, enclaveId)
        
        In unit tests, we need to pass in the parameters to the Vote() method,
        including sigR and sigS which are generated offchain. But these are
        generated using a VotingRevoker address that we have used at the time,
        which will be different than the address that is generated in the unit test.
        Therefore, if we have to exclude the address check.

    */
    function invalidStakeholderTest() public {
        address revoker = 0x70D1419b54d7d657240a04d87dc4121c294d12cb;
        bytes32 sigR = hex"aaa812a0d8426b3da86db031db88e14de415060389f7419f924616c531cf0ed5";
        bytes32 sigS = hex"bbb7040006b0df208c0c112ea9190f8cd92c824d475d94010173741ca52853ac";
        
        try m_revoker.Vote(
            revoker,
            m_enclaveIds[0],
            sigR,
            sigS
        ) {
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
        address revoker = 0x70D1419b54d7d657240a04d87dc4121c294d12cb;
        bytes32 sigR = hex"182812a0d8426b3da86db031db88e14de415060389f7419f924616c531cf0ed5";
        bytes32 sigS = hex"fa47040006b0df208c0c112ea9190f8cd92c824d475d94010173741ca52853ac";

        // first vote should succeed
        {
            try m_revoker.Vote(
                revoker,
                m_enclaveIds[0],
                sigR,
                sigS
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
            try m_revoker.Vote(
                revoker,
                m_enclaveIds[0],
                sigR,
                sigS
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


    function voteTest() public {
        address revoker = 0xAAC129A3e6e9f44147951dDD5655d66c312A4713;

        // first stakeholder vote
        {
            bytes32 sigR = hex"02635b81263df74db06e8175c56f358d5733feaa86318d6843b0fab32f7c849e";
            bytes32 sigS = hex"3cac7d1a1f313403bbae3d45db06827fb4114e900ee81e4f9e188372687169b1";
            
            try m_revoker.Vote(
                revoker,
                m_enclaveIds[1],
                sigR,
                sigS
            ) {
                Assert.ok(true, "stakeholder voted successfully");
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory) {
                Assert.ok(false, "Unexpected revert");
            }
        }

        // second stakeholder vote
        {
            bytes32 sigR = hex"aadec6c90b7ff49bc7847663bf3dbbecf803ce58e45c0f22e1242dbe304ef4b2";
            bytes32 sigS = hex"90a950e46b8e4a6f70877be27bb9d0145f8a93f2acf78fd1dbe92a177eca369b";
            
            try m_revoker.Vote(
                revoker,
                m_enclaveIds[1],
                sigR,
                sigS
            ) {
                Assert.ok(true, "stakeholder voted successfully");
            } catch Error(string memory reason) {
                Assert.ok(false, reason);
            } catch (bytes memory) {
                Assert.ok(false, "Unexpected revert");
            }
        }

        
        // third stakeholder vote, should fail since enclave already revoked
        {
            bytes32 sigR = hex"3886861197b9c80dfcf6323ee666bec855f0f52bc639772d0ec0f3f0c8e056e9";
            bytes32 sigS = hex"0e883bfff1058cb1efd9e98157524ed52d90de9c415a1e4d469fb57fea53bfcc";
            
            try m_revoker.Vote(
                revoker,
                m_enclaveIds[1],
                sigR,
                sigS
            ) {
                Assert.ok(false, "stakeholder should not vote successfully");
            } catch Error(string memory reason) {
                Assert.equal(
                    reason,
                    "enclave already revoked",
                    reason
                );
            } catch (bytes memory) {
                Assert.ok(false, "Unexpected revert");
            }
        }        
    } // end VoteTest
}