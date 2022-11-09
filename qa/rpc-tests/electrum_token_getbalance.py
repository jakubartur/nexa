#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Unlimited developers
import asyncio
from test_framework.util import assert_equal, waitForAsync
from test_framework.loginit import logging
from test_framework.electrumutil import (
        ElectrumConnection,
        ElectrumTestFramework,
        get_txid_from_idem,
)

class ElectrumTokenGetBalanceTests(ElectrumTestFramework):
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
                await self.test_balance()
            finally:
                self.cli.disconnect()
        asyncio.run(async_tests())


    # Basic test
    async def test_balance(self):
        n = self.n
        addr = n.getnewaddress()
        addr_scripthash = await self.cli.call("blockchain.address.get_scripthash", addr)
        addr2 = n.getnewaddress()

        token1_id_enc, token1_id_hex = await self.create_token(
                to_addr = addr, mint_amount = 100)

        token2_id_enc, token2_id_hex = await self.create_token(
                to_addr = addr, mint_amount = 200)


        self.sync_mempool_count()
        b = await self.cli.call("token.address.get_balance", addr)
        assert len(b['confirmed']) == 0
        assert_equal(100, b['unconfirmed'][token1_id_hex])
        assert_equal(200, b['unconfirmed'][token2_id_hex])
        assert_equal(b, await self.cli.call("token.scripthash.get_balance", addr_scripthash))

        n.generate(1)
        self.sync_height()
        b = await self.cli.call("token.address.get_balance", addr)
        assert len(b['unconfirmed']) == 0
        assert_equal(100, b['confirmed'][token1_id_hex])
        assert_equal(200, b['confirmed'][token2_id_hex])

        # Special case. Sending and receiving the same
        # amount in mempool, results in unconfirmed balance of 0.
        n.token("send", token1_id_enc, addr2, 100)
        n.token("send", token2_id_enc, addr2, 200)
        n.token("send", token1_id_enc, addr, 100)
        n.token("send", token2_id_enc, addr, 200)
        self.sync_mempool_count()
        b = await self.cli.call("token.address.get_balance", addr)
        assert_equal(0, b['unconfirmed'][token1_id_hex])
        assert_equal(0, b['unconfirmed'][token2_id_hex])

        # Spending confirmed tokens results in negative mempool
        # balance.
        n.generate(1)
        self.sync_height()
        n.token("send", token1_id_enc, addr2, 100)
        n.token("send", token2_id_enc, addr2, 200)
        self.sync_mempool_count()
        b = await self.cli.call("token.address.get_balance", addr)
        assert_equal(-100, b['unconfirmed'][token1_id_hex])
        assert_equal(-200, b['unconfirmed'][token2_id_hex])


if __name__ == '__main__':
    ElectrumTokenGetBalanceTests().main()
