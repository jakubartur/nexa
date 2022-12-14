#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from grapheneblocks import GrapheneBlockTest
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class GrapheneOptimizedTest(GrapheneBlockTest):
    
    def setup_network(self, split=False):
        standard_node_opts = [
            "-rpcservertimeout=0",
            "-debug=graphene",
            "-use-grapheneblocks=1",
            "-use-thinblocks=0",
            "-use-compactblocks=0",
            "-net.grapheneFastFilterCompatibility=2"]

        optimized_node_opts = [
            "-rpcservertimeout=0",
            "-debug=graphene",
            "-use-grapheneblocks=1",
            "-use-thinblocks=0",
            "-use-compactblocks=0",
            "-net.grapheneFastFilterCompatibility=0"]

        self.nodes = [
            start_node(0, self.options.tmpdir, optimized_node_opts),
            start_node(1, self.options.tmpdir, standard_node_opts),
            start_node(2, self.options.tmpdir, optimized_node_opts)
        ]

        interconnect_nodes(self.nodes)
        self.is_network_split = False
        self.sync_all()


if __name__ == '__main__':
    GrapheneOptimizedTest().main()
