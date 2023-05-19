// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {RevokerByConflictMsg} from "../../DecentRevoker/RevokerByConflictMsg.sol";

import {DecentRevokeSubscriber} from "../DecentRevokeSubscriber.sol";
import {TestInputs} from "../TestInputs.sol";
import {PredeployC_DecentSvr_Addr} from "./00_PredeployC_DecentSvr_Addr.sol";
import {PredeployD_PubSub_Addr} from "./00_PredeployD_PubSub_Addr.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract RevokerByConflictMsg_testSuite {

    //===== member variables =====

    address m_decentCertMgrAddr;
    address m_pubSubSvcAddr;
    address m_revokerAddr;
    address m_subsAddr;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    /// #value: 1000000000000000000
    function beforeAll() public payable {
        m_decentCertMgrAddr = PredeployC_DecentSvr_Addr.ADDR1;
        m_pubSubSvcAddr = PredeployD_PubSub_Addr.ADDR;
        m_revokerAddr =
            address(new RevokerByConflictMsg(
                m_pubSubSvcAddr,
                m_decentCertMgrAddr
            ));

        DecentRevokeSubscriber subs = new DecentRevokeSubscriber();
        subs.subscribe{
            value: msg.value
        }(m_pubSubSvcAddr, m_revokerAddr);
        m_subsAddr = address(subs);
    }

    function sameContentTest() public {
        try RevokerByConflictMsg(m_revokerAddr).reportConflicts(
            TestInputs.DECENT_APP_01_EVENT_01_ID_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_S,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_S,
            TestInputs.DECENT_SVR_CERT_DER,
            TestInputs.DECENT_APP_01_CERT_DER
        ) {
            Assert.ok(false, "should not be able to report conflicts with same content");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "contents must be different",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function msg1InvalidSign() public {
        try RevokerByConflictMsg(m_revokerAddr).reportConflicts(
            TestInputs.DECENT_APP_01_EVENT_01_ID_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_HASH,
            TestInputs.DECENT_APP_01_EVENT_02_MSG1_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_02_MSG1_SIGN_S,
            TestInputs.DECENT_APP_01_EVENT_01_MSG2_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG2_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_01_MSG2_SIGN_S,
            TestInputs.DECENT_SVR_CERT_DER,
            TestInputs.DECENT_APP_01_CERT_DER
        ) {
            Assert.ok(false, "should not be able to report conflicts with invalid sign");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "message1 signature invalid",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function msg2InvalidSign() public {
        try RevokerByConflictMsg(m_revokerAddr).reportConflicts(
            TestInputs.DECENT_APP_01_EVENT_01_ID_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_S,
            TestInputs.DECENT_APP_01_EVENT_01_MSG2_HASH,
            TestInputs.DECENT_APP_01_EVENT_02_MSG2_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_02_MSG2_SIGN_S,
            TestInputs.DECENT_SVR_CERT_DER,
            TestInputs.DECENT_APP_01_CERT_DER
        ) {
            Assert.ok(false, "should not be able to report conflicts with invalid sign");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "message2 signature invalid",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function okReportTest1() public {
        DecentRevokeSubscriber(m_subsAddr).reset();
        Assert.equal(
            DecentRevokeSubscriber(m_subsAddr).m_enclaveId(),
            bytes32(0),
            "should be reset"
        );

        try RevokerByConflictMsg(m_revokerAddr).reportConflicts(
            TestInputs.DECENT_APP_01_EVENT_01_ID_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_01_MSG1_SIGN_S,
            TestInputs.DECENT_APP_01_EVENT_01_MSG2_HASH,
            TestInputs.DECENT_APP_01_EVENT_01_MSG2_SIGN_R,
            TestInputs.DECENT_APP_01_EVENT_01_MSG2_SIGN_S,
            TestInputs.DECENT_SVR_CERT_DER,
            TestInputs.DECENT_APP_01_CERT_DER
        ) {
            Assert.ok(true, "should be able to report conflicts");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }

        Assert.ok(
            RevokerByConflictMsg(m_revokerAddr).isRevoked(
                TestInputs.DECENT_APP_01_ENCLAVE_HASH
            ),
            "should be revoked"
        );
        Assert.equal(
            DecentRevokeSubscriber(m_subsAddr).m_enclaveId(),
            TestInputs.DECENT_APP_01_ENCLAVE_HASH,
            "subscriber should be notified"
        );
    }

    function okReportTest2() public {
        DecentRevokeSubscriber(m_subsAddr).reset();
        Assert.equal(
            DecentRevokeSubscriber(m_subsAddr).m_enclaveId(),
            bytes32(0),
            "should be reset"
        );

        try RevokerByConflictMsg(m_revokerAddr).reportConflicts(
            TestInputs.DECENT_APP_02_EVENT_01_ID_HASH,
            TestInputs.DECENT_APP_02_EVENT_01_MSG1_HASH,
            TestInputs.DECENT_APP_02_EVENT_01_MSG1_SIGN_R,
            TestInputs.DECENT_APP_02_EVENT_01_MSG1_SIGN_S,
            TestInputs.DECENT_APP_02_EVENT_01_MSG2_HASH,
            TestInputs.DECENT_APP_02_EVENT_01_MSG2_SIGN_R,
            TestInputs.DECENT_APP_02_EVENT_01_MSG2_SIGN_S,
            TestInputs.DECENT_SVR_CERT_DER,
            TestInputs.DECENT_APP_02_CERT_DER
        ) {
            Assert.ok(true, "should be able to report conflicts");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }

        Assert.ok(
            RevokerByConflictMsg(m_revokerAddr).isRevoked(
                TestInputs.DECENT_APP_02_ENCLAVE_HASH
            ),
            "should be revoked"
        );
        Assert.equal(
            DecentRevokeSubscriber(m_subsAddr).m_enclaveId(),
            TestInputs.DECENT_APP_02_ENCLAVE_HASH,
            "subscriber should be notified"
        );
    }

}
