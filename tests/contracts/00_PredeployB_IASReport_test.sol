// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {IASReportCertMgr} from "../../libs/DecentRA/contracts/IASReportCertMgr.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract PredeployB_IASReport_testSuit {

    //===== member variables =====

    address m_addr1;
    address m_addr2;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        address iasRootAddr = 0x93Ff8fe9BF40051E8763C864B15A0E87f2f96468;
        m_addr1 = address(new IASReportCertMgr(iasRootAddr));
        Assert.equal(
            m_addr1,
            0xd840735F4B6a0d1AF8Fa48EcE560f4778c007397,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );

        m_addr2 = address(new IASReportCertMgr(iasRootAddr));
        Assert.equal(
            m_addr2,
            0x3903c0ac720556c950cc9C5e5037265b156c8849,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );
    }

}
