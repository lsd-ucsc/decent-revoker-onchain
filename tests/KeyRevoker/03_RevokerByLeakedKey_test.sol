// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {KeyRevokerByLeakedKey} from "../../KeyRevoker/KeyRevokerByLeakedKey.sol";

import {KeyRevokeSubscriber} from "../KeyRevokeSubscriber.sol";
import {PredeployA_PubSub_Addr} from "./00_PredeployA_PubSub_Addr.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract KeyRevokerByLeakedKey_testSuite {

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
            address(new KeyRevokerByLeakedKey(
                m_pubSubSvcAddr
            ));

        KeyRevokeSubscriber subs = new KeyRevokeSubscriber();
        subs.subscribe{
            value: msg.value
        }(m_pubSubSvcAddr, m_revokerAddr);
        m_subsAddr = address(subs);
    }

    function invalidRevokeSignTest() public {
        try KeyRevokerByLeakedKey(m_revokerAddr).submitRevokeSign(
            // revoke sign r
            0x46d349498c7b205950269c21c35913f4c7f8451d2e618070daa82df6af5309d2,
            // should be
            // 0x9318c05c529b9b6394dc8ad3e85cb876e72df2c017cae1ca6f6503e39a7c9872,
            // revoke sign s
            0x23bdca7f835975b62f0e3111799faf07927a78d8a16427b95c1296cd51f93ffb,
            // should be
            // 0xc4532c17e70c7b13e5c3e54e436613f3496f7e2b35afe70cf09e4e3c6234a351,
            // key address
            0x5eF7E1948b447E0737F9Bfce4c8741FfDAEFC43E
        ) {
            Assert.ok(false, "should not be able to revoke");
        } catch Error(string memory reason) {
            Assert.equal(
                reason,
                "revoke signature invalid",
                reason
            );
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }
    }

    function okRevokeSignTest() public {
        KeyRevokeSubscriber(m_subsAddr).reset();
        Assert.equal(
            KeyRevokeSubscriber(m_subsAddr).m_keyAddr(),
            address(0),
            "should be reset"
        );

        try KeyRevokerByLeakedKey(m_revokerAddr).submitRevokeSign(
            // revoke sign r
            0x46d349498c7b205950269c21c35913f4c7f8451d2e618070daa82df6af5309d2,
            // revoke sign s
            0x23bdca7f835975b62f0e3111799faf07927a78d8a16427b95c1296cd51f93ffb,
            // key address
            0xed02Eb0f195cdee260b0Ec6b3cEA3ad6a0d207D7
        ) {
            Assert.ok(true, "should be able to revoke");
        } catch Error(string memory reason) {
            Assert.ok(false, reason);
        } catch (bytes memory) {
            Assert.ok(false, "Unexpected revert");
        }

        Assert.ok(
            KeyRevokerByLeakedKey(m_revokerAddr).isRevoked(
                0xed02Eb0f195cdee260b0Ec6b3cEA3ad6a0d207D7
            ),
            "should be revoked"
        );
        Assert.equal(
            KeyRevokeSubscriber(m_subsAddr).m_keyAddr(),
            0xed02Eb0f195cdee260b0Ec6b3cEA3ad6a0d207D7,
            "subscriber should be notified"
        );
    }

}
