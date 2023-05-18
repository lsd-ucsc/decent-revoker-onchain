#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


import hashlib
import json
import logging
import os
import signal
import subprocess
import random
import sys
import time
from typing import Dict

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes

from web3 import Web3


ROOT_DIR     = os.path.join(os.path.dirname(__file__), '..')
UTILS_DIR    = os.path.join(ROOT_DIR, 'utils')
BUILD_DIR    = os.path.join(ROOT_DIR, 'build')
TESTS_DIR    = os.path.join(ROOT_DIR, 'tests')
INPUTS_DIR   = os.path.join(TESTS_DIR, 'inputs')
PYHELPER_DIR = os.path.join(UTILS_DIR, 'PyEthHelper')
PROJECT_CONFIG_PATH = os.path.join(UTILS_DIR, 'key_revoker_conf.json')
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


def CheckKeyAddrInReceipt(receipt: dict, keyAddr: str) -> bool:
	if 'logs' not in receipt:
		return False

	if keyAddr.startswith('0x'):
		keyAddr = keyAddr[2:]
	keyAddr = bytes.fromhex(keyAddr)

	for log in receipt['logs']:
		if 'data' not in log:
			continue
		if len(log['data']) < (3 * 32):
			continue
		if log['data'][2 * 32:][:20] == keyAddr:
			return True

	return False


def GenConflictMsg() -> dict:
	privKey = ec.generate_private_key(ec.SECP256K1())
	pubKey = privKey.public_key()

	pubKeyX = pubKey.public_numbers().x
	pubKeyY = pubKey.public_numbers().y
	pubKeyBytes = pubKeyX.to_bytes(32, 'big') + pubKeyY.to_bytes(32, 'big')
	pubKeyAddr = Web3.to_checksum_address(
		Web3.keccak(pubKeyBytes)[-20:].hex()
	)

	res = {
		'eventId': random.randbytes(16),
		'msg1': random.randbytes(32),
		'msg2': random.randbytes(32),
		'pubKeyBytes': pubKeyBytes.hex(),
		'pubKeyAddr': pubKeyAddr
	}

	res['eventIdHash'] = hashlib.sha256(res['eventId']).digest()
	res['msg1Hash'] = hashlib.sha256(res['msg1']).digest()
	res['msg2Hash'] = hashlib.sha256(res['msg2']).digest()

	msg1Sign = privKey.sign(
		res['eventIdHash'] + res['msg1Hash'],
		ec.ECDSA(hashes.SHA256())
	)
	r, s = utils.decode_dss_signature(msg1Sign)
	res['msg1SignR'] = '0x' + r.to_bytes(32, 'big').hex()
	res['msg1SignS'] = '0x' + s.to_bytes(32, 'big').hex()

	msg2Sign = privKey.sign(
		res['eventIdHash'] + res['msg2Hash'],
		ec.ECDSA(hashes.SHA256())
	)
	r, s = utils.decode_dss_signature(msg2Sign)
	res['msg2SignR'] = '0x' + r.to_bytes(32, 'big').hex()
	res['msg2SignS'] = '0x' + s.to_bytes(32, 'big').hex()

	res['eventIdHash'] = '0x' + res['eventIdHash'].hex()
	res['msg1Hash'] = '0x' + res['msg1Hash'].hex()
	res['msg2Hash'] = '0x' + res['msg2Hash'].hex()

	print('eventIdHash: ' + res['eventIdHash'])
	print('msg1Hash:    ' + res['msg1Hash'])
	print('msg1SignR:   ' + res['msg1SignR'])
	print('msg1SignS:   ' + res['msg1SignS'])
	print('msg2Hash:    ' + res['msg2Hash'])
	print('msg2SignR:   ' + res['msg2SignR'])
	print('msg2SignS:   ' + res['msg2SignS'])
	print('signerAddr:  ' + res['pubKeyAddr'])

	return res


def GenRevokeSign() -> dict:
	privKey = ec.generate_private_key(ec.SECP256K1())
	pubKey = privKey.public_key()

	pubKeyX = pubKey.public_numbers().x
	pubKeyY = pubKey.public_numbers().y
	pubKeyBytes = pubKeyX.to_bytes(32, 'big') + pubKeyY.to_bytes(32, 'big')
	pubKeyAddr = Web3.to_checksum_address(
		Web3.keccak(pubKeyBytes)[-20:].hex()
	)

	res = {
		'pubKeyBytes': pubKeyBytes.hex(),
		'pubKeyAddr': pubKeyAddr
	}

	sign = privKey.sign(
		REVOKE_MSG_HASH,
		ec.ECDSA(utils.Prehashed(hashes.SHA256()))
	)
	r, s = utils.decode_dss_signature(sign)

	res['revokeSignR'] = '0x' + r.to_bytes(32, 'big').hex()
	res['revokeSignS'] = '0x' + s.to_bytes(32, 'big').hex()

	print('Revoke sign R: {}'.format(res['revokeSignR']))
	print('Revoke sign S: {}'.format(res['revokeSignS']))
	print('Signer addr:   {}'.format(res['pubKeyAddr']))

	return res


def RunVotingRevokerTests(
	w3: Web3,
	pubSubAddr: str,
	gasCosts: Dict[str, int],
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
	gasCosts['deployVotingRevoker'] = votingReceipt.gasUsed
	print('VotingRevoker contract deployed at {}'.format(votingAddr))
	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='VotingRevoker',
		release=None, # use locally built contract
		address=votingAddr
	)
	print()

	# revoke some random key address
	keyAddr = GenRevokeSign()['pubKeyAddr']

	voteCosts = []
	# stakeholder 0
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)
	print('{} votes to revoke key address {}'.format(stakeholders[0], keyAddr))
	voteReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='revokeVote',
		arguments=[ keyAddr ],
		privKey=privKey,
		confirmPrompt=False # don't prompt for confirmation
	)
	voteCosts.append(voteReceipt.gasUsed)
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='isRevoked',
		arguments=[ keyAddr ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == False, 'key should not be revoked with only 1 vote'
	# stakeholder 1
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=1, # use account 1
		keyJson=CHECKSUM_KEYS_PATH
	)
	print('{} votes to revoke key address {}'.format(stakeholders[1], keyAddr))
	voteReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='revokeVote',
		arguments=[ keyAddr ],
		privKey=privKey,
		gas=9999999,
		confirmPrompt=False # don't prompt for confirmation
	)
	voteCosts.append(voteReceipt.gasUsed)
	assert CheckKeyAddrInReceipt(voteReceipt, keyAddr), 'key address not in receipt'
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='isRevoked',
		arguments=[ keyAddr ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'key should be revoked after 2 votes'
	print()

	gasCosts['revokeVoteAvg'] = sum(voteCosts) / len(voteCosts)


def RunConflictMsgRevokerTests(
	w3: Web3,
	pubSubAddr: str,
	gasCosts: Dict[str, int],
) -> None:
	# setup sending account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)

	# deploy ConflictingMessageRevoker contract
	print('Deploying ConflictingMessageRevoker contract...')
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='ConflictingMessageRevoker',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	revokerReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=revokerContract,
		arguments=[ pubSubAddr, ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	revokerAddr = revokerReceipt.contractAddress
	gasCosts['deployConflictingMessageRevoker'] = revokerReceipt.gasUsed
	print('ConflictingMessageRevoker contract deployed at {}'.format(revokerAddr))
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='ConflictingMessageRevoker',
		release=None, # use locally built contract
		address=revokerAddr
	)
	print()

	credentials = GenConflictMsg()
	print('report conflict msg to revoke key address {}'.format(
		credentials['pubKeyAddr']
	))
	reportReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='reportConflicts',
		arguments=[
			credentials['eventIdHash'],
			credentials['msg1Hash'],
			credentials['msg1SignR'],
			credentials['msg1SignS'],
			credentials['msg2Hash'],
			credentials['msg2SignR'],
			credentials['msg2SignS'],
			credentials['pubKeyAddr'],
		 ],
		privKey=privKey,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert CheckKeyAddrInReceipt(reportReceipt, credentials['pubKeyAddr']), \
		'key address not in receipt'
	gasCosts['reportConflicts'] = reportReceipt.gasUsed
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ credentials['pubKeyAddr'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'key address should be revoked'
	print()


def RunLeakedKeyRevokerTests(
	w3: Web3,
	pubSubAddr: str,
	gasCosts: Dict[str, int],
) -> None:
	# setup sending account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=CHECKSUM_KEYS_PATH
	)

	# deploy LeakedKeyRevoker contract
	print('Deploying LeakedKeyRevoker contract...')
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='LeakedKeyRevoker',
		release=None, # use locally built contract
		address=None, # deploy new contract
	)
	revokerReceipt = EthContractHelper.DeployContract(
		w3=w3,
		contract=revokerContract,
		arguments=[ pubSubAddr, ],
		privKey=privKey,
		gas=None, # let web3 estimate
		value=0,
		confirmPrompt=False # don't prompt for confirmation
	)
	revokerAddr = revokerReceipt.contractAddress
	gasCosts['deployLeakedKeyRevoker'] = revokerReceipt.gasUsed
	print('LeakedKeyRevoker contract deployed at {}'.format(revokerAddr))
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='LeakedKeyRevoker',
		release=None, # use locally built contract
		address=revokerAddr
	)
	print()

	credentials = GenRevokeSign()

	print('report leaked key to revoke key address {}'.format(
		credentials['pubKeyAddr']
	))
	reportReceipt = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='submitRevokeSign',
		arguments=[
			credentials['revokeSignR'],
			credentials['revokeSignS'],
			credentials['pubKeyAddr'],
		 ],
		privKey=privKey,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert CheckKeyAddrInReceipt(reportReceipt, credentials['pubKeyAddr']), \
		'key address not in receipt'
	gasCosts['reportLeakedKey'] = reportReceipt.gasUsed
	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ credentials['pubKeyAddr'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'key address should be revoked'
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

	gasCost = {}

	# Run VotingRevoker tests
	RunVotingRevokerTests(w3, pubSubAddr, gasCost)

	# Run ConflictingMessageRevoker tests
	RunConflictMsgRevokerTests(w3, pubSubAddr, gasCost)

	# Run LeakedKeyRevoker tests
	RunLeakedKeyRevokerTests(w3, pubSubAddr, gasCost)

	with open(os.path.join(BUILD_DIR, 'keyRevokeGasCosts.json'), 'w') as f:
		json.dump(gasCost, f, indent='\t')


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

