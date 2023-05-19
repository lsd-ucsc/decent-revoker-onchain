// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {IASReportCertMgr} from "../../libs/DecentRA/contracts/IASReportCertMgr.sol";

import {PredeployA_IASRoot_Addr} from "./00_PredeployA_IASRoot_Addr.sol";
import {PredeployB_IASReport_Addr} from "./00_PredeployB_IASReport_Addr.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract PredeployB_IASReport_testSuit {

    //===== member variables =====

    address m_addr1;
    address m_addr2;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        address iasRootAddr = PredeployA_IASRoot_Addr.ADDR;
        m_addr1 = address(new IASReportCertMgr(iasRootAddr));
        Assert.equal(
            m_addr1,
            PredeployB_IASReport_Addr.ADDR1,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );

        m_addr2 = address(new IASReportCertMgr(iasRootAddr));
        Assert.equal(
            m_addr2,
            PredeployB_IASReport_Addr.ADDR2,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );
    }

}
