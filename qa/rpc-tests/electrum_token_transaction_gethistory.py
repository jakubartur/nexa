#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Unlimited developers
import asyncio
from test_framework.util import assert_equal
from test_framework.loginit import logging
from test_framework.electrumutil import (
        ElectrumConnection,
        ElectrumTestFramework,
        get_txid_from_idem,
)

"""
Test the `token.transaction.get_history` RPC call
"""
class ElectrumTokenTransactionGetHistory(ElectrumTestFramework):

    def run_test(self):
        # This test users nexad wallet to create and send tokens.
        # Mine and mature some coins.
        self.n = self.nodes[0]
        self.n.generate(101)
        self.sync_height()

        async def async_tests():
            self.cli = ElectrumConnection()
            await self.cli.connect()
            try:
                await self.test_history()
            finally:
                self.cli.disconnect()
        asyncio.run(async_tests())


    async def test_history(self):
        n = self.n
        mint_addr = n.getnewaddress()

        # This creates two transaction, creating tx + mint tx
        [token_id, _] = await self.create_token(
                to_addr = n.getnewaddress(),
                mint_amount = 42)

        # 8 more transactions for sending
        send_txids = []
        for _ in range(0, 8):
            txidem = n.token("send", token_id, n.getnewaddress(), 1)
            send_txids.append(get_txid_from_idem(n, txidem))

        self.sync_mempool_count()
        res = await self.cli.call("token.transaction.get_history", token_id)
        assert_equal(None, res['cursor'])
        assert_equal(10, len(res['history']))

        for txid in send_txids:
            assert(txid in map(lambda x: x['tx_hash'], res['history']))

        for item in res['history']:
            assert_equal(0, item['height'])

        n.generate(1)
        self.sync_height()
        self.sync_mempool_count()

        res = await self.cli.call("token.transaction.get_history", token_id)
        assert_equal(10, len(res['history']))
        for item in res['history']:
            assert_equal(n.getblockcount(), item['height'])

        # Create a tx confirmed in a later block, + 1 in mempool
        n.token("send", token_id, n.getnewaddress(), 1)
        n.generate(1)
        n.token("send", token_id, n.getnewaddress(), 1)
        self.sync_height()
        self.sync_mempool_count()
        assert_equal(10, len(res['history']))

        # The order returned should be:
        # [mempool, blockheight, blockheight - 1]
        h = (await self.cli.call(
            "token.transaction.get_history", token_id))['history']
        assert_equal(0, h[0]['height'])
        assert_equal(n.getblockcount(), h[1]['height'])
        assert_equal(n.getblockcount() - 1, h[2]['height'])


if __name__ == '__main__':
    ElectrumTokenTransactionGetHistory().main()
