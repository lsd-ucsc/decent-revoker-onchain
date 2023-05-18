// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import {DecentAppCert} from "libs/DecentRA/contracts/DecentAppCert.sol";
import {DecentCertChain} from "libs/DecentRA/contracts/DecentCertChain.sol";
import {LibSecp256k1Sha256} from "libs/DecentRA/contracts/LibSecp256k1Sha256.sol";

import {
    Interface_EventManager
} from "../libs/DecentPubSub/PubSub/Interface_EventManager.sol";
import {
    Interface_PubSubService
} from "../libs/DecentPubSub/PubSub/Interface_PubSubService.sol";


contract LeakedKeyRevoker {
    using DecentAppCert for DecentAppCert.DecentApp;

    //===== constants =====

    bytes32 constant REVOKING_HASH = "REVOKE THIS PRIVATE KEY         ";

    //===== member variables =====

    mapping(bytes32 => bool) m_revoked;

    address m_eventMgrAddr;
    address m_decentSvrCertMgrAddr;

    //===== Constructor =====

    constructor(address pubSubServiceAddr, address decentSvrCertMgr) {
        m_decentSvrCertMgrAddr = decentSvrCertMgr;

        m_eventMgrAddr = Interface_PubSubService(pubSubServiceAddr).register();
    }

    //===== functions =====

    function submitRevokeSign(
        bytes32 sigR,
        bytes32 sigS,
        bytes memory svrCertDer,
        bytes memory appCertDer
    )
        external
    {
        // verify the Decent certificate chain
        DecentAppCert.DecentApp memory appCert;
        DecentCertChain.verifyCertChain(
            appCert,
            m_decentSvrCertMgrAddr,
            svrCertDer,
            appCertDer
        );

        if (m_revoked[appCert.appEnclaveHash]) {
            // if the enclave has already been revoked, we don't need to do
            // anything
            return;
        }

        // require that the key was used to sign the message above
        require(
            LibSecp256k1Sha256.verifySignHash(
                appCert.appKeyAddr,
                REVOKING_HASH,
                sigR,
                sigS
            ),
            "revoke signature invalid"
        );

        m_revoked[appCert.appEnclaveHash] = true;

        Interface_EventManager(m_eventMgrAddr).notifySubscribers(
            abi.encodePacked(appCert.appEnclaveHash)
        );
    } // end submitRevokeSign()

    function isRevoked(bytes32 enclaveId) external view returns (bool) {
        return m_revoked[enclaveId];
    } // end isRevoked()

}
