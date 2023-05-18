// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


import {
    Interface_PubSubService
} from "../libs/DecentPubSub/PubSub/Interface_PubSubService.sol";


contract RevokeSubscriber {

    bytes32 public m_enclaveId;

    constructor() {
    }

    function onNotify(bytes memory data) external {
        bytes32 enclaveId;
        assembly {
            enclaveId := mload(add(data, 32))
        }
        m_enclaveId = enclaveId;
    }

    function subscribe(address pubSubSvcAddr, address pubAddr)
        external
        payable
    {
        Interface_PubSubService(pubSubSvcAddr).subscribe{
            value: msg.value
        }(pubAddr);
    }

    function reset() external {
        m_enclaveId = bytes32(0);
    }

}
