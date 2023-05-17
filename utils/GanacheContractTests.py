#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


import json
import logging
import os
import signal
import subprocess
import sys
import time

from web3 import Web3


ROOT_DIR     = os.path.join(os.path.dirname(__file__), '..')
UTILS_DIR    = os.path.join(ROOT_DIR, 'utils')
BUILD_DIR    = os.path.join(ROOT_DIR, 'build')
TESTS_DIR    = os.path.join(ROOT_DIR, 'tests')
CERTS_DIR    = os.path.join(TESTS_DIR, 'certs')
PYHELPER_DIR = os.path.join(UTILS_DIR, 'PyEthHelper')
PROJECT_CONFIG_PATH = os.path.join(UTILS_DIR, 'project_conf.json')
CHECKSUM_KEYS_PATH  = os.path.join(BUILD_DIR, 'ganache_keys_checksum.json')
GANACHE_KEYS_PATH   = os.path.join(BUILD_DIR, 'ganache_keys.json')
GANACHE_PORT     = 7545
GANACHE_NUM_KEYS = 20
GANACHE_NET_ID   = 1337


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
		'--wallet.accountKeysPath', str(GANACHE_KEYS_PATH),
	]
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	return proc


def CheckEnclaveIdInReceipt(receipt: dict, enclaveId: str) -> bool:
	if 'logs' not in receipt:
		return False

	enclaveIdBytes = bytes.fromhex(enclaveId[2:])

	for log in receipt['logs']:
		if 'data' not in log:
			continue
		if len(log['data']) < (3 * 32):
			continue
		if log['data'][2 * 32:] == enclaveIdBytes:
			return True

	return False


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

	# select three stakeholders
	with open(CHECKSUM_KEYS_PATH, 'r') as f:
		keys = json.load(f)
		stakeholders = [ x for x in keys['addresses'].keys() ]
	stakeholders = stakeholders[:3]
	print('Stakeholders are: {}'.format(stakeholders))

	# deploy VotingRevoker contract
	print('Deploying VotingRevoker contract...')
	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='VotingRevoker',
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
	print('VotingRevoker contract deployed at {}'.format(votingAddr))
	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='VotingRevoker',
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
