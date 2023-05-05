#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


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
