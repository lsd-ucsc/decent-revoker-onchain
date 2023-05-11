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

    function invalidVoteAddrTest() public {
        bytes32 message = hex"ba1d1e8d876062218257d1bd9ef05ee2e47c17e9f563a645d17bee1c59323119";
        bytes32 sigR = hex"b58dfbf46fbb194a6b27d5c4dfabd35b3ae67d0bea3851b03ce8fbc62857f352";
        bytes32 sigS = hex"a62eecddb8213dc6a06f43cbddc619fbdcc485225557dad467feb612db44a143";
        address invalidAddr = address(bytes20(bytes("0x19aba90dbffca8d016040514b6fd64597b171850")));
        
        try m_revoker.Vote(
            invalidAddr,
            m_enclaveIds[0],
            message,
            sigR,
            sigS
        ) {
            Assert.ok(false, "should not be right contract address");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "invalid contract address",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function invalidEnclaveIdTest() public {
        bytes32 message = hex"ba1d1e8d876062218257d1bd9ef05ee2e47c17e9f563a645d17bee1c59323119";
        bytes32 sigR = hex"b58dfbf46fbb194a6b27d5c4dfabd35b3ae67d0bea3851b03ce8fbc62857f352";
        bytes32 sigS = hex"a62eecddb8213dc6a06f43cbddc619fbdcc485225557dad467feb612db44a143";
        bytes32 invalidEnclaveId = hex"efe8b57096cb09b4f3a1f80688254b25fa71d76c4da28f00750c0f877bd6aaaa";
        
        try m_revoker.Vote(
            m_revokerAddr,
            invalidEnclaveId,
            message,
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

    function voteTest() public {
        address revoker = 0x70D1419b54d7d657240a04d87dc4121c294d12cb;
        bytes32 message = hex"e639e126ab5b96aa71ef2d8354d2fc47d6c4abf80b2b0c9628776cd130f9fb04";
        bytes32 sigR = hex"7f1e3256f4e98bc2aa705593cf08ffb1a8fa61a946959a5dba238e66a2a99dbd";
        bytes32 sigS = hex"88f0e92f77ca20aea23f1bba366bc45e66d334b5586e9a36ee412b844e8556c1";
        
        try m_revoker.Vote(
            revoker,
            m_enclaveIds[0],
            message,
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

}