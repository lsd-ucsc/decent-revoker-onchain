// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


import {RevokerByVoting} from "../../DecentRevoker/RevokerByVoting.sol";


contract VotingContract {
    constructor() {
    }

    function doRevokeVote(
        address vRevokerAddr,
        bytes32 enclaveId
    )
        public
    {
        RevokerByVoting(vRevokerAddr).revokeVote(enclaveId);
    }
}
