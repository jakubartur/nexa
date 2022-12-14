#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test RPC calls related to blockchain state. Tests correspond to code in
# rpc/blockchain.cpp.
#

from decimal import Decimal

import test_framework.loginit
from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import *
from test_framework.loginit import logging


class BlockchainTest(BitcoinTestFramework):
    """
    Test blockchain-related RPC calls:

        - gettxoutsetinfo
        - getblockheader
        - getblock
        - rollbackchain
        - reconsidermostworkchain
        - gettxpoolinfo
        - getorphanpoolinfo
        - getraworphanpool

    """

    def setup_chain(self):
        logging.info ("Initializing test directory " + self.options.tmpdir)
        self.node_opts = ["-debug=all,-event"]
        initialize_chain(self.options.tmpdir)

    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=net"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug=net"]))
        self.nodes.append(start_node(2, self.options.tmpdir, ["-debug=net", "-prune=1550"]))
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        self._test_getblockchaininfo()
        self._test_gettxoutsetinfo()
        self._test_getblockheader()
        self._test_getblock()
        self._forking_test()
        self._test_rollbackchain_and_reconsidermostworkchain()
        self._test_transaction_pools()
        self.nodes[0].verifychain(4, 0)
        self._test_getblock_outside_active()


    def _forking_test(self):
        LONGER = 5
        if True:
            self.nodes[1].generate(10*LONGER)
            nblocks = self.nodes[1].getblockcount()
            node2 = start_node(2, self.options.tmpdir, self.node_opts)
            self.nodes.append(node2)
            node2 = self.nodes[2]
            connect_nodes(node2, 0)
            node3 = start_node(3, self.options.tmpdir, self.node_opts)
            self.nodes.append(node3)
            connect_nodes(node3, 2)  # Connect node 3 only to the new node
            connect_nodes(node3, 1)  # Connect node 3 only to the new node
            logging.info("syncing nodes 0, 2 and 3 to node 1")
            waitFor(30, lambda: node2.getblockcount() == nblocks, 2.0)
            waitFor(30, lambda: node3.getblockcount() == nblocks, 2.0)
            waitFor(30, lambda: self.nodes[0].getblockcount() == nblocks, 2.0)

        # sort of simultaneously create blocks (we'd need to have an async generate to really do so,
        # but this is likely to generate on another node before it has a chance to sync
        for i in range(0,5):
            for n in self.nodes:
                n.generate(1)

        besthashes = [x.getbestblockhash() for x in self.nodes]
        print("Node tips: ", besthashes)
        # now force convergence
        self.nodes[1].generate(6)
        count = self.nodes[1].getblockcount()
        bestblockhash = self.nodes[1].getbestblockhash()
        waitFor(30, lambda: self.nodes[0].getblockcount() == count)
        waitFor(30, lambda: self.nodes[2].getblockcount() == count)
        waitFor(30, lambda: self.nodes[3].getblockcount() == count)
        waitFor(30, lambda: self.nodes[0].getbestblockhash() == bestblockhash)
        waitFor(30, lambda: self.nodes[2].getbestblockhash() == bestblockhash)

        logging.info("Forced fork")
        # create a fork by partitioning the network
        # node2 and 3 are only connected to 0 and 1 via a bidirectional connection to 0
        disconnect_nodes(node2, 0)
        disconnect_nodes(node3, 1)

        winningHashes = self.nodes[0].generate(5)
        losingHashes = self.nodes[3].generate(4)

        assert self.nodes[0].getbestblockhash() != self.nodes[3].getbestblockhash()
        assert self.nodes[0].getblockcount() == 1 + self.nodes[3].getblockcount()

        # reconnect
        connect_nodes(node2, 0)

        # now nodes 2 and 3 should reorganize to the longer (more work) side
        waitFor(30, lambda: self.nodes[2].getbestblockhash() == winningHashes[-1])
        waitFor(30, lambda: self.nodes[3].getbestblockhash() == winningHashes[-1])

    def _test_getblockchaininfo(self):
        logging.info("Test getblockchaininfo")

        keys = [
            'bestblockhash',
            'bip135_forks',
            'bip9_softforks',
            'blocks',
            'chain',
            'chainwork',
            'difficulty',
            'headers',
            'initialblockdownload',
            'mediantime',
            'pruned',
            'softforks',
            'size_on_disk',
            'verificationprogress',
        ]

        res = self.nodes[2].getblockchaininfo()
        # result should have pruneheight and default keys if pruning is enabled
        assert_equal(sorted(res.keys()), sorted(keys + ['pruneheight', 'prune_target_size']))
        # pruneheight should be greater or equal to 0
        assert res['pruneheight'] >= 0

        # size_on_disk should be > 0
        assert res['size_on_disk'] > 0

        # check other pruning fields given that prune=1
        assert res['pruned']

        assert_equal(res['prune_target_size'], 1625292800)

        stop_node(self.nodes[2], 2)
        del(self.nodes[-1])
        res = self.nodes[0].getblockchaininfo()
        assert_equal(sorted(res.keys()), sorted(keys))

    def _test_gettxoutsetinfo(self):
        node = self.nodes[0]
        res = node.gettxoutsetinfo()

        assert_equal(res['total_amount'], COINBASE_REWARD*150 + COINBASE_REWARD/2*49)
        assert_equal(res['height'], 200)
        assert_equal(res['txouts'], 200)
        size = res["disk_size"]
        assert (size > 6400)
        assert (size < 64000)
        assert_equal(res['bestblock'], node.getblockhash(200))
        assert_equal(len(res['bestblock']), 64)
        assert_equal(len(res['hash_serialized']), 64)

        logging.info ("Test that gettxoutsetinfo() works for blockchain with just the genesis block")
        b1hash = node.getblockhash(1)
        node.invalidateblock(b1hash)

        res2 = node.gettxoutsetinfo()
        assert_equal(res2['total_amount'], Decimal('0'))
        assert_equal(res2['height'], 0)
        assert_equal(res2['txouts'], 0)
        assert_equal(res2['bestblock'], node.getblockhash(0))
        assert_equal(len(res2['hash_serialized']), 64)

        logging.info ("Test that gettxoutsetinfo() returns the same result after invalidate/reconsider block")
        node.reconsiderblock(b1hash)

        res3 = node.gettxoutsetinfo()
        assert_equal(res['total_amount'], res3['total_amount'])
        assert_equal(res['height'], res3['height'])
        assert_equal(res['txouts'], res3['txouts'])
        assert_equal(res['bestblock'], res3['bestblock'])
        assert_equal(res['hash_serialized'], res3['hash_serialized'])

    def _test_getblockheader(self):
        node = self.nodes[0]

        assert_raises(
            JSONRPCException, lambda: node.getblockheader('nonsense'))

        besthash = node.getbestblockhash()
        secondbesthash = node.getblockhash(199)
        header = node.getblockheader(besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], 200)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chainwork'])
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['ancestorhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['mediantime'], int)
        assert isinstance(header['size'], int)
        assert isinstance(header['feePoolAmt'], int)
        assert isinstance(header['nonce'], str)
        assert isinstance(header['difficulty'], Decimal)
        assert isinstance(header["chainwork"], str)
        assert int(header["chainwork"], 16) > 0, "chainwork not updated"  # this is also checking that the string is a number.

        header_by_height = node.getblockheader(header['height'])
        assert_equal (header_by_height, header)

        header_by_height = node.getblockheader("200")
        assert_equal (header_by_height, header)

    def _test_getblock(self):
        node = self.nodes[0]

        assert_raises(
            JSONRPCException, lambda: node.getblock('nonsense'))

        besthash = node.getbestblockhash()

        block_by_hash = node.getblock(besthash)
        block_by_height = node.getblock(200)

        assert_equal (block_by_height, block_by_hash)

    def _test_getblock_outside_active(self):
        """
        If we have it, it should be possible to fetch a block that is no
        longer in the active chain.
        """
        blockhash = self.nodes[0].generate(1)[0]
        self.nodes[0].invalidateblock(blockhash)
        b = self.nodes[0].getblock(blockhash)
        assert_equal(blockhash, b['hash'])

    def _test_rollbackchain_and_reconsidermostworkchain(self):
        # Save the hash of the current chaintip and then mine 10 blocks
        blockcount = self.nodes[0].getblockcount()

        self.nodes[0].generate(10)
        self.sync_all()
        assert_equal(blockcount + 10, self.nodes[0].getblockcount())
        assert_equal(blockcount + 10, self.nodes[1].getblockcount())

        # Now Rollback the chain on Node 0 by 5 blocks
        logging.info ("Test that rollbackchain() works")
        blockcount = self.nodes[0].getblockcount()
        self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - 5)
        assert_equal(blockcount - 5, self.nodes[0].getblockcount())
        assert_equal(blockcount, self.nodes[1].getblockcount())

        # Invalidate the chaintip on Node 0 and then mine more blocks on Node 1
        # - Node1 should advance in chain length but Node 0 shoudd not follow.
        self.nodes[1].generate(5)
        time.sleep(2) # give node0 a chance to sync (it shouldn't)

        assert_equal(self.nodes[0].getblockcount() + 10, self.nodes[1].getblockcount())
        assert_not_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())

        # Now mine blocks on node0 which will extend the chain beyond node1.
        self.nodes[0].generate(12)

        # Reconnect nodes since they will have been disconnected when nod0's chain was previously invalidated.
        # -  Node1 should re-org and follow node0's chain.
        connect_nodes_bi(self.nodes, 0, 1)
        self.sync_all()
        assert_equal(self.nodes[0].getblockcount(), self.nodes[1].getblockcount())
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())


        # Test that we can only rollback the chain by max 100 blocks
        self.nodes[0].generate(100)
        self.sync_all()

        # Roll back by 101 blocks, this should fail
        blockcount = self.nodes[0].getblockcount()
        try:
            self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - 101)
        except JSONRPCException as e:
            logging.info (e.error['message'])
            assert("You are attempting to rollback the chain by 101 blocks, however the limit is 100 blocks." in e.error['message'])
        assert_equal(blockcount, self.nodes[0].getblockcount())
        assert_equal(blockcount, self.nodes[1].getblockcount())

        # Now rollback by 100 blocks
        bestblockhash = self.nodes[0].getbestblockhash() #save for later
        blockcount = self.nodes[0].getblockcount()
        self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - 100)
        assert_equal(blockcount - 100, self.nodes[0].getblockcount())
        assert_equal(blockcount, self.nodes[1].getblockcount())

        # Now reconsider the now invalid chaintip on node0 which will reconnect the blocks
        self.nodes[0].reconsiderblock(bestblockhash)
        self.sync_all()

        # Now rollback by 101 blocks by using the override
        bestblockhash = self.nodes[0].getbestblockhash() #save for later
        blockcount = self.nodes[0].getblockcount()
        self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - 101, True)
        assert_equal(blockcount - 101, self.nodes[0].getblockcount())
        assert_equal(blockcount, self.nodes[1].getblockcount())

        # Now reconsider the now invalid chaintip on node0 which will reconnect the blocks
        self.nodes[0].reconsiderblock(bestblockhash)
        self.sync_all()

        ### Test that we can rollback the chain beyond a forkpoint and then reconnect
        #   the blocks on either chain

        # Mine a few blocks
        self.nodes[0].generate(50)

        # Invalidate the chaintip and then mine another chain
        bestblockhash1 = self.nodes[0].getbestblockhash() #save for later
        self.nodes[0].invalidateblock(bestblockhash1)
        self.nodes[0].generate(5)

        # Reconsider the previous chain so both chains are either valid or fork-active.
        self.nodes[0].reconsiderblock(bestblockhash1)

        # Invalidate the current longer fork2 and mine 10 blocks on fork1
        # which now makes it the longer fork
        bestblockhashfork2 = self.nodes[0].getbestblockhash() #save for later
        self.nodes[0].invalidateblock(bestblockhashfork2)
        self.nodes[0].generate(10)

        # Reconsider fork2 so both chains are active.
        # fork1 should be 10 blocks long and fork 2 should be 5 blocks long with fork1 being active
        # and fork2 being fork-valid.
        self.nodes[0].reconsiderblock(bestblockhashfork2)

        # Now we're ready to test the rollback. Rollback beyond the fork point (more than 10 blocks).
        self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - 20)

        # Reconsider the fork1. Blocks should now be fully reconnected on fork1.
        self.nodes[0].reconsiderblock(bestblockhash1)
        assert_equal(self.nodes[0].getbestblockhash(), bestblockhash1);

        # Rollback again beyond the fork point (more than 10 blocks).
        self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - 20)

        # Reconsider the fork2. Blocks should now be fully reconnected on fork2.
        self.nodes[0].reconsiderblock(bestblockhashfork2)
        assert_equal(self.nodes[0].getbestblockhash(), bestblockhashfork2);


        #### Start testing reconsidermostworkchain
        # Create an additional fork 3 which is the longest fork. Then make the shortest
        # fork2 the active chain.  Then do a reconsidermostworkchain which should make
        # fork3 the active chain, and disregarding fork1 which is longer than fork2 but
        # shorter than fork3.
        logging.info ("Test that reconsidermostworkchain() works")

        # rollback to before fork 1 and 2, and then mine another longer fork 3
        self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - 120, True)
        fork3blocks = 140;
        self.nodes[0].generate(fork3blocks)
        bestblockhashfork3 = self.nodes[0].getbestblockhash() #save for later

        # now rollback again and make the shortest fork2 the active chain
        self.nodes[0].rollbackchain(self.nodes[0].getblockcount() - fork3blocks, True)
        self.nodes[0].reconsiderblock(bestblockhashfork2)
        assert_equal(self.nodes[0].getbestblockhash(), bestblockhashfork2);

        # do a reconsidermostworkchain but without the override flag
        try:
            self.nodes[0].reconsidermostworkchain()
        except JSONRPCException as e:
            logging.info (e.error['message'])
            assert("You are attempting to rollback the chain by 120 blocks, however the limit is 100 blocks." in e.error['message'])
        # check that nothing happened and we're still on the same chaintip
        assert_equal(self.nodes[0].getbestblockhash(), bestblockhashfork2);

        # now do a reconsidermostworkchain with the override. We should now be on fork3 best block hash
        self.nodes[0].reconsidermostworkchain(True)
        assert_equal(self.nodes[0].getbestblockhash(), bestblockhashfork3);

        # check that we are already on the correct chain by issuing another reconsider
        try:
            self.nodes[0].reconsidermostworkchain()
        except JSONRPCException as e:
            logging.info (e.error['message'])
            assert("Nothing to do. Already on the correct chain." in e.error['message'])

        # check that we can run reconsidermostworkchain when we're already on the correct chain
        try:
            self.nodes[0].reconsidermostworkchain()
        except JSONRPCException as e:
            logging.info (e.error['message'])
            assert("Nothing to do. Already on the correct chain." in e.error['message'])
        # check that nothing happened and we're still on the same chaintip
        assert_equal(self.nodes[0].getbestblockhash(), bestblockhashfork3);

    def _test_transaction_pools(self):
        node = self.nodes[0]

        # main txn pool
        res = node.gettxpoolinfo()
        assert_equal(res['size'], 0)
        assert_equal(res['bytes'], 0)
        assert_equal(res['usage'], 0)
        assert_equal(res['bytes'], 0)
        assert_equal(res['maxtxpool'], 300000000)
        assert_equal(res['txpoolminfee'], Decimal('0E-8'))

        # orphan pool
        res2 = node.getorphanpoolinfo()
        assert_equal(res2['size'], 0)
        assert_equal(res2['bytes'], 0)

        res3 = node.getraworphanpool()
        assert_equal(len(res3), 0)


if __name__ == '__main__':
    BlockchainTest().main()

def TestOnce():
    t = BlockchainTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)

def Test():
    for i in range(100):
        print("\n\nTest iteration: ", i)
        TestOnce()
