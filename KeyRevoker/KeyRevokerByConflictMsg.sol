// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import {LibSecp256k1Sha256} from "../libs/DecentRA/contracts/LibSecp256k1Sha256.sol";

import {
    Interface_EventManager
} from "../libs/DecentPubSub/PubSub/Interface_EventManager.sol";
import {
    Interface_PubSubService
} from "../libs/DecentPubSub/PubSub/Interface_PubSubService.sol";


contract KeyRevokerByConflictMsg {

    //===== member variables =====

    mapping(address => bool) m_revoked;

    address m_eventMgrAddr;

    //===== Constructor =====

    constructor(address pubSubServiceAddr) {
        m_eventMgrAddr = Interface_PubSubService(pubSubServiceAddr).register();
    }

    //===== functions =====

    function reportConflicts(
        bytes32 eventId,
        bytes32 content1,
        bytes32 message1SigR,
        bytes32 message1SigS,
        bytes32 content2,
        bytes32 message2SigR,
        bytes32 message2SigS,
        address signerKeyAddr
    )
        external
    {
        // must be different content
        require(content1 != content2, "contents must be different");

        if (m_revoked[signerKeyAddr]) {
            // if the enclave has already been revoked, we don't need to do
            // anything
            return;
        }

        bytes memory message1 = bytes.concat(eventId, content1);
        bytes memory message2 = bytes.concat(eventId, content2);

        // require that they are signed by the same App
        require(
            LibSecp256k1Sha256.verifySignMsg(
                signerKeyAddr,
                message1,
                message1SigR,
                message1SigS
            ),
            "message1 signature invalid"
        );

        require(
            LibSecp256k1Sha256.verifySignMsg(
                signerKeyAddr,
                message2,
                message2SigR,
                message2SigS
            ),
            "message2 signature invalid"
        );

        m_revoked[signerKeyAddr] = true;

        Interface_EventManager(m_eventMgrAddr).notifySubscribers(
            abi.encodePacked(signerKeyAddr)
        );
    } // end reportConflicts()

    function isRevoked(address keyAddr) external view returns (bool) {
        return m_revoked[keyAddr];
    } // end isRevoked()

}
