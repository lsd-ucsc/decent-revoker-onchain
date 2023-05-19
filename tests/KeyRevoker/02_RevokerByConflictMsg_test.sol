// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {
    KeyRevokerByConflictMsg
} from "../../KeyRevoker/KeyRevokerByConflictMsg.sol";

import {KeyRevokeSubscriber} from "../KeyRevokeSubscriber.sol";
import {PredeployA_PubSub_Addr} from "./00_PredeployA_PubSub_Addr.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract KeyRevokerByConflictMsg_testSuite {

    //===== member variables =====

    address m_pubSubSvcAddr;
    address m_revokerAddr;
    address m_subsAddr;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    /// #value: 1000000000000000000
    function beforeAll() public payable {
        m_pubSubSvcAddr = PredeployA_PubSub_Addr.ADDR;
        m_revokerAddr =
            address(new KeyRevokerByConflictMsg(
                m_pubSubSvcAddr
            ));

        KeyRevokeSubscriber subs = new KeyRevokeSubscriber();
        subs.subscribe{
            value: msg.value
        }(m_pubSubSvcAddr, m_revokerAddr);
        m_subsAddr = address(subs);
    }

    function sameContentTest() public {
        try KeyRevokerByConflictMsg(m_revokerAddr).reportConflicts(
            // event ID hash
            0x564049e273a08ddcf23d175320562306a1092532e78289f1ed443eb25d803956,
            // msg 1 content hash
            0xbbec6a3060505c92b54702f7e938a2fdc844179cbfdfd505746926c1ed62ab93,
            // msg 1 signature r
            0xea45bc35b9b52649722c6725a47ce0b3357b5708f2fe215a79ba3225c6cbdce3,
            // msg 1 signature s
            0xcb681f78b09181b453d668ecf29ab901ff812f48b075c96601c201cfd263fb9a,
            // msg 2 content hash
            0xbbec6a3060505c92b54702f7e938a2fdc844179cbfdfd505746926c1ed62ab93,
            // msg 2 signature r
            0xea45bc35b9b52649722c6725a47ce0b3357b5708f2fe215a79ba3225c6cbdce3,
            // msg 2 signature s
            0xcb681f78b09181b453d668ecf29ab901ff812f48b075c96601c201cfd263fb9a,
            // msg signer
            0x2699AccBCd33C4519b7d4fcB8fB291D4dDbB9201
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
        try KeyRevokerByConflictMsg(m_revokerAddr).reportConflicts(
            // event ID hash
            0x564049e273a08ddcf23d175320562306a1092532e78289f1ed443eb25d803956,
            // msg 1 content hash
            0xbbec6a3060505c92b54702f7e938a2fdc844179cbfdfd505746926c1ed62ab93,
            // msg 1 signature r
            0x40b3ebd58ad6648b34225eca9a0a11dc1c8c9faba95aa21ba92536442b4c6406,
            // msg 1 signature s
            0x7272c7a2ff482eb8628af418dfc8a4e7c713c963fa2941c659cfe4e6d0720b3b,
            // msg 2 content hash
            0x97e23c13f4f00d4e8bc4dca2cd0ebdeb877061a30cbf37a0c29e5c7ff39aebd8,
            // msg 2 signature r
            0x800f185cc8ae9536aca4fb6e953ef665dd5699598f10d271bed6b1ebe854f228,
            // msg 2 signature s
            0x7dd90b4d833bdd4396ec3a5cd283ed5e6f5b02dd92476b090fb201b6ae25a09c,
            // msg signer
            0x2699AccBCd33C4519b7d4fcB8fB291D4dDbB9201
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
        try KeyRevokerByConflictMsg(m_revokerAddr).reportConflicts(
            // event ID hash
            0x564049e273a08ddcf23d175320562306a1092532e78289f1ed443eb25d803956,
            // msg 1 content hash
            0xbbec6a3060505c92b54702f7e938a2fdc844179cbfdfd505746926c1ed62ab93,
            // msg 1 signature r
            0xea45bc35b9b52649722c6725a47ce0b3357b5708f2fe215a79ba3225c6cbdce3,
            // msg 1 signature s
            0xcb681f78b09181b453d668ecf29ab901ff812f48b075c96601c201cfd263fb9a,
            // msg 2 content hash
            0x97e23c13f4f00d4e8bc4dca2cd0ebdeb877061a30cbf37a0c29e5c7ff39aebd8,
            // msg 2 signature r
            0x94183ca19781a7f94015be6473a39e56618e8126ae16b16067b1ff54fb4c71e9,
            // msg 2 signature s
            0xf6916b296a0a40e0dc15b7c3bd77f824e7820c0c6c148d3da5b8928e208a31bf,
            // msg signer
            0x2699AccBCd33C4519b7d4fcB8fB291D4dDbB9201
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
        KeyRevokeSubscriber(m_subsAddr).reset();
        Assert.equal(
            KeyRevokeSubscriber(m_subsAddr).m_keyAddr(),
            address(0),
            "should be reset"
        );

        try KeyRevokerByConflictMsg(m_revokerAddr).reportConflicts(
            // event ID hash
            0x564049e273a08ddcf23d175320562306a1092532e78289f1ed443eb25d803956,
            // msg 1 content hash
            0xbbec6a3060505c92b54702f7e938a2fdc844179cbfdfd505746926c1ed62ab93,
            // msg 1 signature r
            0xea45bc35b9b52649722c6725a47ce0b3357b5708f2fe215a79ba3225c6cbdce3,
            // msg 1 signature s
            0xcb681f78b09181b453d668ecf29ab901ff812f48b075c96601c201cfd263fb9a,
            // msg 2 content hash
            0x97e23c13f4f00d4e8bc4dca2cd0ebdeb877061a30cbf37a0c29e5c7ff39aebd8,
            // msg 2 signature r
            0x800f185cc8ae9536aca4fb6e953ef665dd5699598f10d271bed6b1ebe854f228,
            // msg 2 signature s
            0x7dd90b4d833bdd4396ec3a5cd283ed5e6f5b02dd92476b090fb201b6ae25a09c,
            // msg signer
            0x2699AccBCd33C4519b7d4fcB8fB291D4dDbB9201
        ) {
            Assert.ok(true, "should be able to report conflicts");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }

        Assert.ok(
            KeyRevokerByConflictMsg(m_revokerAddr).isRevoked(
                0x2699AccBCd33C4519b7d4fcB8fB291D4dDbB9201
            ),
            "should be revoked"
        );
        Assert.equal(
            KeyRevokeSubscriber(m_subsAddr).m_keyAddr(),
            0x2699AccBCd33C4519b7d4fcB8fB291D4dDbB9201,
            "subscriber should be notified"
        );
    }

    function okReportTest2() public {
        KeyRevokeSubscriber(m_subsAddr).reset();
        Assert.equal(
            KeyRevokeSubscriber(m_subsAddr).m_keyAddr(),
            address(0),
            "should be reset"
        );

        try KeyRevokerByConflictMsg(m_revokerAddr).reportConflicts(
            // event ID hash
            0xd51f87044f4df302378bfcb8d7ba1fb824c5ce325b3999ed3716d07724c2ce6b,
            // msg 1 content hash
            0x1da3a594f77062a4d9b9f9db20d96cf4b82d7c615adeeb758ac0248c2604adfb,
            // msg 1 signature r
            0x40b3ebd58ad6648b34225eca9a0a11dc1c8c9faba95aa21ba92536442b4c6406,
            // msg 1 signature s
            0x7272c7a2ff482eb8628af418dfc8a4e7c713c963fa2941c659cfe4e6d0720b3b,
            // msg 2 content hash
            0x85f45b44b439d7ab5ac2b634a0ec4f8592cd32c2ed9bb5c15cb8a07718723a19,
            // msg 2 signature r
            0x94183ca19781a7f94015be6473a39e56618e8126ae16b16067b1ff54fb4c71e9,
            // msg 2 signature s
            0xf6916b296a0a40e0dc15b7c3bd77f824e7820c0c6c148d3da5b8928e208a31bf,
            // msg signer
            0x79287ed0721e1DbFb9AB94856e45d3a8F68a728B
        ) {
            Assert.ok(true, "should be able to report conflicts");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }

        Assert.ok(
            KeyRevokerByConflictMsg(m_revokerAddr).isRevoked(
                0x79287ed0721e1DbFb9AB94856e45d3a8F68a728B
            ),
            "should be revoked"
        );
        Assert.equal(
            KeyRevokeSubscriber(m_subsAddr).m_keyAddr(),
            0x79287ed0721e1DbFb9AB94856e45d3a8F68a728B,
            "subscriber should be notified"
        );
    }

}
