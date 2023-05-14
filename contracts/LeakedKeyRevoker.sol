// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Common} from "./Common.sol";
import {DecentAppCert} from "libs/DecentRA/contracts/DecentAppCert.sol";
import {DecentCertChain} from "libs/DecentRA/contracts/DecentCertChain.sol";
import {
    Interface_DecentServerCertMgr
} from "libs/DecentRA/contracts/Interface_DecentServerCertMgr.sol";
import {LibSecp256k1Sha256} from "libs/DecentRA/contracts/LibSecp256k1Sha256.sol";



contract LeakedKeyRevoker{

    using DecentAppCert for DecentAppCert.DecentApp;

    //===== member variables =====

	mapping(bytes32 => bool) m_enclaveIds;
    mapping(bytes32 => bool) m_revoked;

    address m_decentSvrMgr;
    DecentAppCert.DecentApp m_appCert;


    //===== Constructor =====

    constructor(
        bytes32[] memory enclaveIds,
		address decentSvrMgr
    )
	{
		for (uint i = 0; i < enclaveIds.length; i++) {
            m_enclaveIds[enclaveIds[i]] = true;
        }

        m_decentSvrMgr = decentSvrMgr;
	}

    //===== functions =====

    function Vote(
		bytes32 sigR,
		bytes32 sigS,
		bytes memory appCertDer
	)
    public
    {
		bytes memory message = bytes("REVOKE THIS PRIVATE KEY");

		// load the DecentApp cert
		DecentAppCert.DecentApp memory appCert;
        appCert.loadCert(appCertDer, m_decentSvrMgr, m_decentSvrMgr);
        m_appCert = appCert;

		// require that the key was used to sign the message above
		require(
			LibSecp256k1Sha256.verifySignMsg(
				m_appCert.appKeyAddr,
				message,
				sigR,
				sigS
			),
			"message1 signature invalid"
		);

		m_revoked[m_appCert.appEnclaveHash] = true;

    } // end Vote()
}
