// SPDX-License-Identifier: MIT
pragma solidity >=0.4.17 <0.9.0;

// This import is automatically injected by Remix
import "remix_tests.sol";

// This import is required to use custom transaction context
// Although it may fail compilation in 'Solidity Compiler' plugin
// But it will work fine in 'Solidity Unit Testing' plugin
import "remix_accounts.sol";


import {DecentServerCertMgr} from "../../libs/DecentRA/contracts/DecentServerCertMgr.sol";


// File name has to end with '_test.sol', this file can contain more than one testSuite contracts
contract PredeployC_DecentSvr_testSuit {

    //===== member variables =====

    address m_addr1;
    address m_addr2;

    //===== functions =====

    /// 'beforeAll' runs before all other tests
    /// More special functions are: 'beforeEach', 'beforeAll', 'afterEach' & 'afterAll'
    function beforeAll() public {
        address iasRepAddr1 = 0xd840735F4B6a0d1AF8Fa48EcE560f4778c007397;
        m_addr1 = address(new DecentServerCertMgr(iasRepAddr1));
        Assert.equal(
            m_addr1,
            0xD9eC9E840Bb5Df076DBbb488d01485058f421e58,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );

        address iasRepAddr2 = 0x3903c0ac720556c950cc9C5e5037265b156c8849;
        m_addr2 = address(new DecentServerCertMgr(iasRepAddr2));
        Assert.equal(
            m_addr2,
            0xaa96CB8107828e584C4FbC37a41754333DfFD206,
            "The address of predeployed contract is changed;"
            " please update it accordingly in all test cases"
        );
    }

}
