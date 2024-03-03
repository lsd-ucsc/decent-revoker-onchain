#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2024 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


import argparse
import base64
import hashlib
import json
import logging
import os
import random
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from typing import Dict, List, Tuple
from web3 import Web3
from web3.contract.contract import Contract
from PyEthHelper import EthContractHelper
from PyEthHelper import GanacheAccounts


BASE_DIR_PATH       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR_PATH      = os.path.join(BASE_DIR_PATH, 'build')
UTILS_DIR_PATH      = os.path.join(BASE_DIR_PATH, 'utils')
TESTS_DIR           = os.path.join(BASE_DIR_PATH, 'tests')
INPUTS_DIR          = os.path.join(TESTS_DIR, 'inputs')
PROJECT_CONFIG_PATH = os.path.join(UTILS_DIR_PATH, 'project_conf.json')

REVOKE_MSG_HASH = b'REVOKE THIS PRIVATE KEY         '
assert len(REVOKE_MSG_HASH) == 32, 'REVOKE_MSG_HASH must be 32 bytes long'

LOGGER = logging.getLogger('NetworkCompatibility')


def _PemToDerCert(certPem: str) -> bytes:
	# PEM to DER
	certPem = certPem.strip()
	certPem = certPem.removeprefix('-----BEGIN CERTIFICATE-----')
	certPem = certPem.removesuffix('-----END CERTIFICATE-----')

	certPem = certPem.replace('\n', '')
	certPem = certPem.replace('\r', '')
	der = base64.b64decode(certPem)

	return der


##########
# Decent credential helpers
##########


def GenDecentRevokeSign(credentials: dict) -> Tuple[str, str]:

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

	LOGGER.info('Revoke sign R: {}'.format(rHex))
	LOGGER.info('Revoke sign S: {}'.format(sHex))

	return rHex, sHex


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

	LOGGER.info('Revoke sign R: {}'.format(rHex))
	LOGGER.info('Revoke sign S: {}'.format(sHex))

	return rHex, sHex


##########
# Key credential helpers
##########


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

	LOGGER.info('eventIdHash: ' + res['eventIdHash'])
	LOGGER.info('msg1Hash:    ' + res['msg1Hash'])
	LOGGER.info('msg1SignR:   ' + res['msg1SignR'])
	LOGGER.info('msg1SignS:   ' + res['msg1SignS'])
	LOGGER.info('msg2Hash:    ' + res['msg2Hash'])
	LOGGER.info('msg2SignR:   ' + res['msg2SignR'])
	LOGGER.info('msg2SignS:   ' + res['msg2SignS'])
	LOGGER.info('signerAddr:  ' + res['pubKeyAddr'])

	return res


def GenKeyRevokeSign() -> dict:
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

	LOGGER.info('Revoke sign R: {}'.format(res['revokeSignR']))
	LOGGER.info('Revoke sign S: {}'.format(res['revokeSignS']))
	LOGGER.info('Signer addr:   {}'.format(res['pubKeyAddr']))

	return res


##########
# Tests - Voting
##########


def DeployVoteProxyContract(
	w3: Web3,
	privKey: str,
	numVoters: int = 3,
) -> List[Contract]:
	proxyContracts = []
	for i in range(numVoters):
		# deploy VoteProxy contract
		LOGGER.info('Deploying VoteProxy contract...')
		proxyContract = EthContractHelper.LoadContract(
			w3=w3,
			projConf=PROJECT_CONFIG_PATH,
			contractName='VoteProxy',
			release=None, # use locally built contract
			address=None, # deploy new contract
		)
		deployReceipt = EthContractHelper.DeployContract(
			w3=w3,
			contract=proxyContract,
			arguments=[ ],
			privKey=privKey,
			gas=None, # let web3 estimate
			value=0,
			confirmPrompt=False # don't prompt for confirmation
		)
		proxyContract = EthContractHelper.LoadContract(
			w3=w3,
			projConf=PROJECT_CONFIG_PATH,
			contractName='VoteProxy',
			release=None, # use locally built contract
			address=deployReceipt.contractAddress
		)
		proxyContracts.append(proxyContract)

	return proxyContracts


def RunRevokerByVotingTests(
	w3: Web3,
	privKey: str,
	pubSubAddr: str,
	proxyContracts: List[Contract],
) -> None:

	stakeholders = [ proxyContract.address for proxyContract in proxyContracts ]
	LOGGER.info(f'Stakeholders are: {stakeholders}')

	# deploy RevokerByVoting contract
	LOGGER.info('Deploying RevokerByVoting contract...')
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
	revokerAddr = votingReceipt.contractAddress

	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByVoting',
		release=None, # use locally built contract
		address=revokerAddr
	)


	# revoke an enclave
	enclaveId = '0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF'


	for proxyContract in proxyContracts:
		LOGGER.info(f'{proxyContract.address} casting vote')
		voteReceipt = EthContractHelper.CallContractFunc(
			w3=w3,
			contract=proxyContract,
			funcName='decentRevokeVote',
			arguments=[ revokerAddr, enclaveId ],
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
	assert revokeState == True, 'Enclave should be revoked by now'


def RunKeyRevokerByVotingTests(
	w3: Web3,
	privKey: str,
	pubSubAddr: str,
	proxyContracts: List[Contract],
) -> None:

	stakeholders = [ proxyContract.address for proxyContract in proxyContracts ]
	LOGGER.info(f'Stakeholders are: {stakeholders}')

	# deploy KeyRevokerByVoting contract
	LOGGER.info('Deploying KeyRevokerByVoting contract...')
	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='KeyRevokerByVoting',
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
	revokerAddr = votingReceipt.contractAddress

	votingContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='KeyRevokerByVoting',
		release=None, # use locally built contract
		address=revokerAddr
	)


	# revoke some random key address
	keyAddr = GenKeyRevokeSign()['pubKeyAddr']


	for proxyContract in proxyContracts:
		LOGGER.info(f'{proxyContract.address} casting vote')
		voteReceipt = EthContractHelper.CallContractFunc(
			w3=w3,
			contract=proxyContract,
			funcName='keyRevokeVote',
			arguments=[ revokerAddr, keyAddr ],
			privKey=privKey,
			confirmPrompt=False # don't prompt for confirmation
		)

	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=votingContract,
		funcName='isRevoked',
		arguments=[ keyAddr ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'Key should be revoked by now'


##########
# Tests - Conflicting Messages
##########


def RunRevokerByConflictMsgTests(
	w3: Web3,
	privKey: str,
	pubSubAddr: str,
	decentSvrCertMgrAddr: str,
) -> None:
	# deploy RevokerByConflictMsg contract
	LOGGER.info('Deploying RevokerByConflictMsg contract...')
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
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByConflictMsg',
		release=None, # use locally built contract
		address=revokerAddr
	)

	credentials = LoadProblemCredential(0, 0, 1)
	LOGGER.info('report conflict msg to revoke enclave {}'.format(
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

	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ '0x' + credentials['enclaveHash'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'Enclave should be revoked'


def RunKeyRevokerByConflictMsgTests(
	w3: Web3,
	privKey: str,
	pubSubAddr: str,
) -> None:

	# deploy KeyRevokerByConflictMsg contract
	LOGGER.info('Deploying KeyRevokerByConflictMsg contract...')
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='KeyRevokerByConflictMsg',
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
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='KeyRevokerByConflictMsg',
		release=None, # use locally built contract
		address=revokerAddr
	)

	credentials = GenConflictMsg()
	LOGGER.info('report conflict msg to revoke key address {}'.format(
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

	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ credentials['pubKeyAddr'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'key address should be revoked'


##########
# Tests - Leaked Keys
##########


def RunRevokerByLeakedKeyTests(
	w3: Web3,
	privKey: str,
	pubSubAddr: str,
	decentSvrCertMgrAddr: str,
) -> None:
	# deploy RevokerByLeakedKey contract
	LOGGER.info('Deploying RevokerByLeakedKey contract...')
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

	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='RevokerByLeakedKey',
		release=None, # use locally built contract
		address=revokerAddr
	)


	credentials = LoadProblemCredential(0, 0, 1)


	# generate revoke signature
	rHex, sHex = GenDecentRevokeSign(credentials)

	LOGGER.info('report leaked key to revoke enclave {}'.format(
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

	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ '0x' + credentials['enclaveHash'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'Enclave should be revoked'


def RunKeyRevokerByLeakedKeyTests(
	w3: Web3,
	privKey: str,
	pubSubAddr: str,
) -> None:
	# deploy KeyRevokerByLeakedKey contract
	LOGGER.info('Deploying KeyRevokerByLeakedKey contract...')
	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='KeyRevokerByLeakedKey',
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

	revokerContract = EthContractHelper.LoadContract(
		w3=w3,
		projConf=PROJECT_CONFIG_PATH,
		contractName='KeyRevokerByLeakedKey',
		release=None, # use locally built contract
		address=revokerAddr
	)

	credentials = GenKeyRevokeSign()

	LOGGER.info('report leaked key to revoke key address {}'.format(
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

	revokeState = EthContractHelper.CallContractFunc(
		w3=w3,
		contract=revokerContract,
		funcName='isRevoked',
		arguments=[ credentials['pubKeyAddr'] ],
		privKey=None,
		confirmPrompt=False # don't prompt for confirmation
	)
	assert revokeState == True, 'key address should be revoked'


def RunTests(
	apiUrl: str,
	keyfile: os.PathLike,
	pubSubAddr: str,
	decentSvrCertMgrAddr: str,
) -> dict:
	# connect to endpoint
	w3 = Web3(Web3.HTTPProvider(apiUrl))
	while not w3.is_connected():
		LOGGER.info('Attempting to connect to endpoint...')
		time.sleep(1)
	LOGGER.info('Connected to endpoint')

	# checksum keys
	GanacheAccounts.ChecksumGanacheKeysFile(
		keyfile,
		keyfile
	)

	# setup account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0,
		keyJson=keyfile
	)

	LOGGER.info(f'Using PubSubService at {pubSubAddr}')
	LOGGER.info(f'Using DecentSvrCertMgr at {decentSvrCertMgrAddr}')

	pxyContracts = DeployVoteProxyContract(w3=w3, privKey=privKey, numVoters=3)
	RunRevokerByVotingTests(
		w3=w3,
		privKey=privKey,
		pubSubAddr=pubSubAddr,
		proxyContracts=pxyContracts
	)
	RunKeyRevokerByVotingTests(
		w3=w3,
		privKey=privKey,
		pubSubAddr=pubSubAddr,
		proxyContracts=pxyContracts
	)

	RunRevokerByConflictMsgTests(
		w3=w3,
		privKey=privKey,
		pubSubAddr=pubSubAddr,
		decentSvrCertMgrAddr=decentSvrCertMgrAddr
	)
	RunKeyRevokerByConflictMsgTests(
		w3=w3,
		privKey=privKey,
		pubSubAddr=pubSubAddr
	)

	RunRevokerByLeakedKeyTests(
		w3=w3,
		privKey=privKey,
		pubSubAddr=pubSubAddr,
		decentSvrCertMgrAddr=decentSvrCertMgrAddr
	)
	RunKeyRevokerByLeakedKeyTests(
		w3=w3,
		privKey=privKey,
		pubSubAddr=pubSubAddr
	)


def main():
	argParser = argparse.ArgumentParser(
		description='Run tests to check compatibility with a given network'
	)
	argParser.add_argument(
		'--api-url', '-u',
		type=str, required=True,
		help='URL to the JSON-RPC over HTTP API of the network'
	)
	argParser.add_argument(
		'--key-file', '-k',
		type=str, required=True,
		help='Path to the file containing the private keys for the accounts'
	)
	argParser.add_argument(
		'--log-path', '-l',
		type=str, required=False,
		help='Path to the directory where the log file will be stored'
	)
	argParser.add_argument(
		'--pubsub-addr', '-p',
		type=str, required=True,
		help='Address of the PubSubService contract'
	)
	argParser.add_argument(
		'--ra-addr', '-r',
		type=str, required=True,
		help='Address of the Decent RA server cert contract'
	)
	args = argParser.parse_args()

	logFormatter = logging.Formatter('[%(asctime)s | %(levelname)s] [%(name)s] %(message)s')
	logLevel = logging.INFO
	rootLogger = logging.root

	rootLogger.setLevel(logLevel)

	consoleHandler = logging.StreamHandler()
	consoleHandler.setFormatter(logFormatter)
	consoleHandler.setLevel(logLevel)
	rootLogger.addHandler(consoleHandler)

	if args.log_path is not None:
		fileHandler = logging.FileHandler(args.log_path)
		fileHandler.setFormatter(logFormatter)
		fileHandler.setLevel(logLevel)
		rootLogger.addHandler(fileHandler)


	RunTests(
		apiUrl=args.api_url,
		keyfile=args.key_file,
		pubSubAddr=args.pubsub_addr,
		decentSvrCertMgrAddr=args.ra_addr
	)


if __name__ == '__main__':
	exit(main())

