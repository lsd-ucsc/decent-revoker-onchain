// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;


import {VotingRevoker} from "../../contracts/VotingRevoker.sol";


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
