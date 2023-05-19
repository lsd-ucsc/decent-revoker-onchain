#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


import base64
import json
import logging
import os
import signal
import subprocess
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from typing import Tuple
from web3 import Web3


ROOT_DIR     = os.path.join(os.path.dirname(__file__), '..')
UTILS_DIR    = os.path.join(ROOT_DIR, 'utils')
BUILD_DIR    = os.path.join(ROOT_DIR, 'build')
TESTS_DIR    = os.path.join(ROOT_DIR, 'tests')
INPUTS_DIR   = os.path.join(TESTS_DIR, 'inputs')
PYHELPER_DIR = os.path.join(UTILS_DIR, 'PyEthHelper')
PROJECT_CONFIG_PATH = os.path.join(UTILS_DIR, 'project_conf.json')
CHECKSUM_KEYS_PATH  = os.path.join(BUILD_DIR, 'ganache_keys_checksum.json')
GANACHE_KEYS_PATH   = os.path.join(BUILD_DIR, 'ganache_keys.json')
GANACHE_PORT     = 7545
GANACHE_NUM_KEYS = 20
GANACHE_NET_ID   = 1337

REVOKE_MSG_HASH = b'REVOKE THIS PRIVATE KEY         '
assert len(REVOKE_MSG_HASH) == 32, 'REVOKE_MSG_HASH must be 32 bytes long'


sys.path.append(PYHELPER_DIR)
from PyEthHelper import EthContractHelper
from PyEthHelper import GanacheAccounts


def StartGanache() -> subprocess.Popen:
	cmd = [
		'ganache-cli',
		'-p', str(GANACHE_PORT),
		'-d',
		'-a', str(GANACHE_NUM_KEYS),
		'--network-id', str(GANACHE_NET_ID),
		'--chain.hardfork', 'shanghai',
		'--wallet.accountKeysPath', str(GANACHE_KEYS_PATH),
	]
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	return proc


def CheckEnclaveIdInReceipt(receipt: dict, enclaveId: str) -> bool:
	if 'logs' not in receipt:
		return False

	if enclaveId.startswith('0x'):
		enclaveId = enclaveId[2:]
	enclaveIdBytes = bytes.fromhex(enclaveId)

	for log in receipt['logs']:
		if 'data' not in log:
			continue
		if len(log['data']) < (3 * 32):
			continue
		if log['data'][2 * 32:] == enclaveIdBytes:
			return True

	return False


def GenerateRevokeSign(credentials: dict) -> Tuple[str, str]:

	privKey: ec.EllipticCurvePrivateKey = serialization.load_der_private_key(
		bytes.fromhex(credentials['privKeyDer']),
		password=None
	)

	sign = privKey.sign(
		REVOKE_MSG_HASH,
		ec.ECDSA(utils.Prehashed(hashes.SHA256()))
	)
	r, s = utils.decode_dss_signature(sign)
	rHex = r.to_bytes(32, 'big').hex()
	sHex = s.to_bytes(32, 'big').hex()

	print('Revoke sign R: {}'.format(rHex))
	print('Revoke sign S: {}'.format(sHex))

	return rHex, sHex


def _PemToDerCert(certPem: str) -> bytes:
	# PEM to DER
	certPem = certPem.strip()
	certPem = certPem.removeprefix('-----BEGIN CERTIFICATE-----')
	certPem = certPem.removesuffix('-----END CERTIFICATE-----')

	certPem = certPem.replace('\n', '')
	certPem = certPem.replace('\r', '')
	der = base64.b64decode(certPem)

	return der


def LoadIASRootCertDer() -> bytes:
	with open(os.path.join(INPUTS_DIR, 'CertIASRoot.pem'), 'r') as f:
		certPem = f.read()

	return _PemToDerCert(certPem)


def LoadDecentSvrCertDer(idx: int) -> bytes:
	filename = 'CertDecentServer_{:02}.pem'.format(idx)
	with open(os.path.join(INPUTS_DIR, filename), 'r') as f:
		certPem = f.read()

	return _PemToDerCert(certPem)


def LoadDecentAppCertDer(sIdx: int, aIdx: int) -> bytes:
	filename = 'CertDecentApp_S{:02}_{:02}.pem'.format(sIdx, aIdx)
	with open(os.path.join(INPUTS_DIR, filename), 'r') as f:
		certPem = f.read()

	return _PemToDerCert(certPem)


def LoadProblemCredential(sIdx: int, aIdx: int, mIdx: int) -> dict:
	filename = 'CredProbApp_S{:02}_{:02}_{:02}.json'.format(sIdx, aIdx, mIdx)
	with open(os.path.join(INPUTS_DIR, filename), 'r') as f:
		msg = json.load(f)

	return msg


def RunRevokerByVotingTests(
	w3: Web3,
	pubSubAddr: str,
) -> None:
	# setup sending account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)

	# select three stakeholders
	with open(CHECKSUM_KEYS_PATH, 'r') as f:
		keys = json.load(f)
		stakeholders = [ x for x in keys['addresses'].keys() ]
	stakeholders = stakeholders[:3]
	print('Stakeholders are: {}'.format(stakeholders))

	# deploy RevokerByVoting contract
	print('Deploying RevokerByVoting contract...')
	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByVoting',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	votingReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=votingContract,
		arguments=[ pubSubAddr, stakeholders ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	votingAddr = votingReceipt.contractAddress
	print('RevokerByVoting contract deployed at {}'.format(votingAddr))
	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByVoting',
		release=None, # use locally built contract
		address=votingAddr
	)
	print()

	# revoke an enclave
	enclaveId = '0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF'
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)
	print('{} votes to revoke enclave {}'.format(stakeholders[0], enclaveId))
	voteReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='revokeVote',
		arguments=[ enclaveId ],
		privKey=privKey,
		confirmPrompt=False # don't prompt for confirmation
	)
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='isRevoked',
		arguments=[ enclaveId ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == False, 'Enclave should not be revoked with only 1 vote'
	# stakeholder 1
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=1, # use account 1
		keyJson=CHECKSUM_KEYS_PATH
	)
	print('{} votes to revoke enclave {}'.format(stakeholders[1], enclaveId))
	voteReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='revokeVote',
		arguments=[ enclaveId ],
		privKey=privKey,
		gas=9999999,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert CheckEnclaveIdInReceipt(voteReceipt, enclaveId), 'Enclave ID not in receipt'
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='isRevoked',
		arguments=[ enclaveId ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'Enclave should be revoked after 2 votes'
	print()


def RunRevokerByConflictMsgTests(
	w3: Web3,
	pubSubAddr: str,
	decentSvrCertMgrAddr: str,
) -> None:
	# setup sending account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)

	# deploy RevokerByConflictMsg contract
	print('Deploying RevokerByConflictMsg contract...')
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByConflictMsg',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	revokerReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=revokerContract,
		arguments=[ pubSubAddr, decentSvrCertMgrAddr ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	revokerAddr = revokerReceipt.contractAddress
	print('RevokerByConflictMsg contract deployed at {}'.format(revokerAddr))
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByConflictMsg',
		release=None, # use locally built contract
		address=revokerAddr
	)
	print()

	credentials = LoadProblemCredential(0, 0, 1)
	print('report conflict msg to revoke enclave {}'.format(
		credentials['enclaveHash']
	))
	reportReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='reportConflicts',
		arguments=[
			'0x' + credentials['msgIdHash'],
			'0x' + credentials['msgContent1Hash'],
			'0x' + credentials['msg1SignR'],
			'0x' + credentials['msg1SignS'],
			'0x' + credentials['msgContent2Hash'],
			'0x' + credentials['msg2SignR'],
			'0x' + credentials['msg2SignS'],
			LoadDecentSvrCertDer(0),
			LoadDecentAppCertDer(0, 0),
		 ],
		privKey=privKey,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert CheckEnclaveIdInReceipt(reportReceipt, credentials['enclaveHash']), \
		'Enclave ID not in receipt'
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ '0x' + credentials['enclaveHash'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'Enclave should be revoked'
	print()


def RunRevokerByLeakedKeyTests(
	w3: Web3,
	pubSubAddr: str,
	decentSvrCertMgrAddr: str,
) -> None:
	# setup sending account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)

	credentials = LoadProblemCredential(0, 0, 1)

	# generate revoke signature
	rHex, sHex = GenerateRevokeSign(credentials)

	# deploy RevokerByLeakedKey contract
	print('Deploying RevokerByLeakedKey contract...')
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByLeakedKey',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	revokerReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=revokerContract,
		arguments=[ pubSubAddr, decentSvrCertMgrAddr ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	revokerAddr = revokerReceipt.contractAddress
	print('RevokerByLeakedKey contract deployed at {}'.format(revokerAddr))
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByLeakedKey',
		release=None, # use locally built contract
		address=revokerAddr
	)
	print()

	print('report leaked key to revoke enclave {}'.format(
		credentials['enclaveHash']
	))
	reportReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='submitRevokeSign',
		arguments=[
			'0x' + rHex,
			'0x' + sHex,
			LoadDecentSvrCertDer(0),
			LoadDecentAppCertDer(0, 0),
		 ],
		privKey=privKey,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert CheckEnclaveIdInReceipt(reportReceipt, credentials['enclaveHash']), \
		'Enclave ID not in receipt'
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ '0x' + credentials['enclaveHash'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'Enclave should be revoked'
	print()


def RunTests() -> None:
	# connect to ganache
	ganacheUrl = 'http://localhost:{}'.format(GANACHE_PORT)
	w3 = Web3(Web3.HTTPProvider(ganacheUrl))
	while not w3.is_connected():
		print('Attempting to connect to ganache...')
		time.sleep(1)
	print('Connected to ganache')

	# checksum keys
	GanacheAccounts.ChecksumGanacheKeysFile(
		CHECKSUM_KEYS_PATH,
		GANACHE_KEYS_PATH
	)

	# setup account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)

	# deploy PubSubService contract
	print('Deploying PubSubService contract...')
	pubSubContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='PubSubService',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	pubSubReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=pubSubContract,
		arguments=[],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	pubSubAddr = pubSubReceipt.contractAddress
	print('PubSubService contract deployed at {}'.format(pubSubAddr))
	print()

	# deploy IASRootCertMgr contract
	print('Deploying IASRootCertMgr contract...')
	iasRootContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='IASRootCertMgr',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	iasRootReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=iasRootContract,
		arguments=[ LoadIASRootCertDer() ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	iasRootAddr = iasRootReceipt.contractAddress
	print('IASRootCertMgr contract deployed at {}'.format(iasRootAddr))
	print()

	# deploy IASReportCertMgr contract
	print('Deploying IASReportCertMgr contract...')
	iasReportContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='IASReportCertMgr',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	iasReportReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=iasReportContract,
		arguments=[ iasRootAddr ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	iasReportAddr = iasReportReceipt.contractAddress
	print('IASReportCertMgr contract deployed at {}'.format(iasReportAddr))
	print()

	# deploy DecentServerCertMgr contract
	print('Deploying DecentServerCertMgr contract...')
	decentSvrContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='DecentServerCertMgr',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	decentSvrReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=decentSvrContract,
		arguments=[ iasReportAddr ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	decentSvrAddr = decentSvrReceipt.contractAddress
	print('DecentServerCertMgr contract deployed at {}'.format(decentSvrAddr))
	print()

	# Run RevokerByVoting tests
	RunRevokerByVotingTests(w3, pubSubAddr)

	# Run RevokerByConflictMsg tests
	RunRevokerByConflictMsgTests(w3, pubSubAddr, decentSvrAddr)

	# Run RevokerByLeakedKey tests
	RunRevokerByLeakedKeyTests(w3, pubSubAddr, decentSvrAddr)


def StopGanache(ganacheProc: subprocess.Popen) -> None:
	print('Shutting down ganache (it may take ~15 seconds)...')
	waitEnd = time.time() + 20
	ganacheProc.terminate()
	while ganacheProc.poll() is None:
		try:
			if time.time() > waitEnd:
				print('Force to shut down ganache')
				ganacheProc.kill()
			else:
				print('Still waiting for ganache to shut down...')
				ganacheProc.send_signal(signal.SIGINT)
			ganacheProc.wait(timeout=2)
		except subprocess.TimeoutExpired:
			continue
	print('Ganache has been shut down')


def main():

	# logging configuration
	loggingFormat = '%(asctime)s %(levelname)s %(message)s'
	logging.basicConfig(level=logging.INFO, format=loggingFormat)
	# logger = logging.getLogger(__name__ + main.__name__)

	ganacheProc = StartGanache()

	try:
		RunTests()
	finally:
		# finish and exit
		StopGanache(ganacheProc)


if __name__ == '__main__':
	main()
