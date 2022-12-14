#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# Exercise the wallet keypool, and interaction with wallet encryption/locking

# Add python-bitcoinrpc to module search path:

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class KeyPoolTest(BitcoinTestFramework):

    def run_test(self):
        nodes = self.nodes
        addr_before_encrypting = nodes[0].getnewaddress()
        addr_before_encrypting_data = nodes[0].validateaddress(addr_before_encrypting)
        wallet_info_old = nodes[0].getwalletinfo()
        assert(addr_before_encrypting_data['hdmasterkeyid'] == wallet_info_old['hdmasterkeyid'])
        
        # Encrypt wallet and wait to terminate
        nodes[0].encryptwallet('test')
        bitcoind_processes[0].wait()
        # Restart node 0
        nodes[0] = start_node(0, self.options.tmpdir)
        # Keep creating keys
        addr = nodes[0].getnewaddress()
        addr_data = nodes[0].validateaddress(addr)
        wallet_info = nodes[0].getwalletinfo()
        assert(addr_before_encrypting_data['hdmasterkeyid'] != wallet_info['hdmasterkeyid'])
        assert(addr_data['hdmasterkeyid'] == wallet_info['hdmasterkeyid'])

        try:
            addr = nodes[0].getnewaddress()
            raise AssertionError('Keypool should be exhausted after one address')
        except JSONRPCException as e:
            assert(e.error['code']==-12)

        # top up the keypool and make the size be 4
        nodes[0].walletpassphrase('test', 12000)
        nodes[0].keypoolrefill(4)
        nodes[0].walletlock()

        # drain the keys
        addr = set()
        addr.add(nodes[0].getrawchangeaddress())
        addr.add(nodes[0].getrawchangeaddress())
        addr.add(nodes[0].getrawchangeaddress())
        addr.add(nodes[0].getrawchangeaddress())
        # assert that four unique addresses were returned
        assert(len(addr) == 4)
        # the next one should fail
        try:
            addr = nodes[0].getrawchangeaddress()
            raise AssertionError('Keypool should be exhausted after three addresses')
        except JSONRPCException as e:
            assert(e.error['code']==-12)

        # refill keypool with four new addresses
        nodes[0].walletpassphrase('test', 1)
        nodes[0].keypoolrefill(4)
        # test walletpassphrase timeout
        waitFor(20, lambda: nodes[0].getwalletinfo()["unlocked_until"] == 0)
        assert_equal(nodes[0].getwalletinfo()["unlocked_until"], 0)

        # drain them by mining
        nodes[0].generate(1)
        nodes[0].generate(1)
        nodes[0].generate(1)
        nodes[0].generate(1)
        try:
            nodes[0].generate(1)
            raise AssertionError('Keypool should be exhausted after four addesses')
        except JSONRPCException as e:
            assert(e.error['code']==-12)

    def setup_network(self):
        self.nodes = start_nodes(1, self.options.tmpdir)

if __name__ == '__main__':
    KeyPoolTest().main(None,{"keypool":1})  # add limited keypool here, not across all other tests

def Test():
    flags = standardFlags()
    t = KeyPoolTest()
    t.drop_to_pdb = True
    t.main(flags, {"keypool":1})
    print("completed!")

