// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


import {VotingRevoker} from "../../KeyRevoker/VotingRevoker.sol";


contract VotingContract {
    constructor() {
    }

    function doRevokeVote(
        address vRevokerAddr,
        address proposedKeyAddr
    )
        public
    {
        VotingRevoker(vRevokerAddr).revokeVote(proposedKeyAddr);
    }
}
