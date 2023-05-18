// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


import {
    Interface_PubSubService
} from "../libs/DecentPubSub/PubSub/Interface_PubSubService.sol";


contract KeyRevokeSubscriber {

    address public m_keyAddr;

    constructor() {
    }

    function onNotify(bytes memory data) external {
        bytes20 keyAddr;
        require(data.length == 20, "invalid key addr length");
        assembly {
            keyAddr := and(
                mload(add(data, 32)),
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000
            )
        }
        m_keyAddr = address(keyAddr);
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
        m_keyAddr = address(0);
    }

}
