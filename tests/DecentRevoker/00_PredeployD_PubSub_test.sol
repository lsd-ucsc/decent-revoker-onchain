// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {PubSubService} from "../../libs/DecentPubSub/PubSub/PubSubService.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract PredeployD_PubSub_testSuit {

    //===== member variables =====

    address m_addr;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        m_addr = address(new PubSubService());
        Assert.equal(
            m_addr,
            0x80922Db6752eCe1C2DeFA54Beb8FB984E649308B,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );
    }

}
