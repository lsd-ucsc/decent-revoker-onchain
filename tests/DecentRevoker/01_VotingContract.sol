// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


import {VotingRevoker} from "../../DecentRevoker/VotingRevoker.sol";


contract VotingContract {
    constructor() {
    }

    function doRevokeVote(
        address vRevokerAddr,
        bytes32 enclaveId
    )
        public
    {
        VotingRevoker(vRevokerAddr).revokeVote(enclaveId);
    }
}
