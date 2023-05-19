// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


import {KeyRevokerByVoting} from "../../KeyRevoker/KeyRevokerByVoting.sol";


contract VotingContract {
    constructor() {
    }

    function doRevokeVote(
        address vRevokerAddr,
        address proposedKeyAddr
    )
        public
    {
        KeyRevokerByVoting(vRevokerAddr).revokeVote(proposedKeyAddr);
    }
}
