// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Common} from "./Common.sol";
import {DecentAppCert} from "libs/DecentRA/contracts/DecentAppCert.sol";
import {DecentCertChain} from "libs/DecentRA/contracts/DecentCertChain.sol";
import {Interface_DecentServerCertMgr} from "libs/DecentRA/contracts/Interface_DecentServerCertMgr.sol";
import {LibSecp256k1Sha256} from "libs/DecentRA/contracts/LibSecp256k1Sha256.sol";

contract ConflictingMessageRevoker {
    using DecentAppCert for DecentAppCert.DecentApp;

    //===== member variables =====

    mapping(bytes32 => bool) m_enclaveIds;
    mapping(bytes32 => bool) m_revoked;

    address m_decentSvrMgr;
    DecentAppCert.DecentApp m_appCert;

    //===== Constructor =====

    constructor(bytes32[] memory enclaveIds, address decentSvrMgr) {
        for (uint i = 0; i < enclaveIds.length; i++) {
            m_enclaveIds[enclaveIds[i]] = true;
        }

        m_decentSvrMgr = decentSvrMgr;
    }

    //===== functions =====

    function Vote(
        bytes32 event1,
        bytes32 content1,
        bytes32 message1SigR,
        bytes32 message1SigS,
        bytes32 event2,
        bytes32 content2,
        bytes32 message2SigR,
        bytes32 message2SigS,
        bytes memory appCertDer
    )
    public
    {
        // must be the same event
        require(event1 == event2, "events must be the same");

        // must be different content
        require(content1 != content2, "contents must be different");

        // load the DecentApp cert
        DecentAppCert.DecentApp memory appCert;
        appCert.loadCert(appCertDer, m_decentSvrMgr, m_decentSvrMgr);
        m_appCert = appCert;

        bytes memory message1 = bytes.concat(event1, content1);
        bytes memory message2 = bytes.concat(event2, content2);

        // require that they are signed by the same App
        require(
            LibSecp256k1Sha256.verifySignMsg(
                m_appCert.appKeyAddr,
                message1,
                message1SigR,
                message1SigS
            ),
            "message1 signature invalid"
        );

        require(
            LibSecp256k1Sha256.verifySignMsg(
                m_appCert.appKeyAddr,
                message2,
                message2SigR,
                message2SigS
            ),
            "message2 signature invalid"
        );

        m_revoked[m_appCert.appEnclaveHash] = true;
    } // end Vote()
}
