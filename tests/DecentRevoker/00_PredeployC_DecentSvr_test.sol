// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {DecentServerCertMgr} from "../../libs/DecentRA/contracts/DecentServerCertMgr.sol";

import {PredeployB_IASReport_Addr} from "./00_PredeployB_IASReport_Addr.sol";
import {PredeployC_DecentSvr_Addr} from "./00_PredeployC_DecentSvr_Addr.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract PredeployC_DecentSvr_testSuit {

    //===== member variables =====

    address m_addr1;
    address m_addr2;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        address iasRepAddr1 = PredeployB_IASReport_Addr.ADDR1;
        m_addr1 = address(new DecentServerCertMgr(iasRepAddr1));
        Assert.equal(
            m_addr1,
            PredeployC_DecentSvr_Addr.ADDR1,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );

        address iasRepAddr2 = PredeployB_IASReport_Addr.ADDR2;
        m_addr2 = address(new DecentServerCertMgr(iasRepAddr2));
        Assert.equal(
            m_addr2,
            PredeployC_DecentSvr_Addr.ADDR2,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );
    }

}
