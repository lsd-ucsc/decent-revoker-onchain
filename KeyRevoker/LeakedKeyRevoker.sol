// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import {LibSecp256k1Sha256} from "../libs/DecentRA/contracts/LibSecp256k1Sha256.sol";

import {
    Interface_EventManager
} from "../libs/DecentPubSub/PubSub/Interface_EventManager.sol";
import {
    Interface_PubSubService
} from "../libs/DecentPubSub/PubSub/Interface_PubSubService.sol";


contract LeakedKeyRevoker {

    //===== constants =====

    bytes32 constant REVOKING_HASH = "REVOKE THIS PRIVATE KEY         ";

    //===== member variables =====

    mapping(address => bool) m_revoked;

    address m_eventMgrAddr;

    //===== Constructor =====

    constructor(address pubSubServiceAddr) {
        m_eventMgrAddr = Interface_PubSubService(pubSubServiceAddr).register();
    }

    //===== functions =====

    function submitRevokeSign(
        bytes32 sigR,
        bytes32 sigS,
        address signerKeyAddr
    )
        external
    {
        if (m_revoked[signerKeyAddr]) {
            // if the enclave has already been revoked, we don't need to do
            // anything
            return;
        }

        // require that the key was used to sign the message above
        require(
            LibSecp256k1Sha256.verifySignHash(
                signerKeyAddr,
                REVOKING_HASH,
                sigR,
                sigS
            ),
            "revoke signature invalid"
        );

        m_revoked[signerKeyAddr] = true;

        Interface_EventManager(m_eventMgrAddr).notifySubscribers(
            abi.encodePacked(signerKeyAddr)
        );
    } // end submitRevokeSign()

    function isRevoked(address keyAddr) external view returns (bool) {
        return m_revoked[keyAddr];
    } // end isRevoked()

}
