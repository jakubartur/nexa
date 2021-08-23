#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class TweakTest (BitcoinTestFramework):
    def __init__(self):
        self.num_nodes = 1

    #def setup_chain(self,bitcoinConfDict=None, wallets=None):
    #    print("Initializing test directory "+self.options.tmpdir)
    #    initialize_chain(self.options.tmpdir)
    #def setup_network(self, split=False):
    #    self.nodes = start_nodes(1, self.options.tmpdir)
    #    self.is_network_split=False

    def run_test (self):
        # note that these tests rely on tweaks that may be changed or removed.

        node = self.nodes[0]

        # check basic set/get access
        node.set("mining.blockSize=100000")
        assert node.get("mining.blockSize")["mining.blockSize"] == 100000

        # check double set and then double get
        node.set("mining.blockSize=200000","mining.comment=slartibartfast dug here")
        data = node.get("mining.blockSize", "mining.comment")
        assert data["mining.blockSize"] == 200000
        assert data["mining.comment"] == "slartibartfast dug here"

        # Check spaces -- note that  spaces in the CLI become separate args
        node.set("mining.blockSize=", "200001")
        data = node.get("mining.blockSize")
        assert data["mining.blockSize"] == 200001
        # Check spaces -- note that  spaces in the CLI become separate args
        node.set("mining.blockSize", "=200002")
        data = node.get("mining.blockSize")
        assert data["mining.blockSize"] == 200002

        # check double set with double spaces and then double get
        node.set("mining.blockSize", "=", "200002","mining.comment", "=", "slartibartfast built fjords not fnords")
        data = node.get("mining.blockSize", "mining.comment")
        assert data["mining.blockSize"] == 200002
        assert data["mining.comment"] == "slartibartfast built fjords not fnords"

        # check incompatible double set
        try:
            node.set("mining.blockSize=300000","net.excessiveBlock=10000")
            assert 0 # the 2nd param is inconsistent with the current state of mining.blockSize
        except JSONRPCException as e:
            # if one set fails, no changes should be made (set is atomic)
            assert node.get("mining.blockSize")["mining.blockSize"] == 200002

        # check wildcard
        netTweaks = node.get("net.*")
        for n,val in netTweaks.items():
            assert n.startswith("net.")

        # check equivalence of no args and *
        data = node.get()
        data1 = node.get("*")
        assert data == data1



if __name__ == '__main__':
    TweakTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = TweakTest()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
