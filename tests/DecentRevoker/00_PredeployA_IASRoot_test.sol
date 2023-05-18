// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {IASRootCertMgr} from "../../libs/DecentRA/contracts/IASRootCertMgr.sol";

import {TestInputs} from "../TestInputs.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract PredeployA_IASRoot_testSuit {

    //===== member variables =====

    address m_addr;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        m_addr = address(new IASRootCertMgr(TestInputs.IAS_ROOT_CERT_DER));
        Assert.equal(
            m_addr,
            0x93Ff8fe9BF40051E8763C864B15A0E87f2f96468,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );
    }

}
