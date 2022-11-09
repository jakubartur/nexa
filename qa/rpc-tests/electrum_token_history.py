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

class ElectrumTokenHistoryTests(ElectrumTestFramework):

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
                await self.test_token_only()
                await self.test_token_filter()
            finally:
                self.cli.disconnect()
        asyncio.run(async_tests())

    async def test_token_only(self):
        """
        Check that transactions that only transaction that transfer tokens are
        in the history.
        """
        n = self.n
        mint_to_addr = n.getnewaddress()
        token_id_enc, _ = await self.create_token(to_addr = mint_to_addr, mint_amount = 100)
        addr = n.getnewaddress()
        addr_scripthash = await self.cli.call("blockchain.address.get_scripthash", addr)
        txidem_send = n.token("send", token_id_enc, addr, 42)

        # This tx should not show up in history
        n.sendtoaddress(addr, 21)

        self.sync_mempool_count()

        assert_equal(2, len(await self.cli.call("blockchain.address.get_history", addr)))
        token_history = await self.cli.call("token.address.get_history", addr)
        assert_equal(1, len(token_history["transactions"]))

        # These calls should provide same result
        assert_equal(token_history, await self.cli.call(
            "token.address.get_mempool", addr))
        assert_equal(token_history, await self.cli.call(
            "token.scripthash.get_history", addr_scripthash))
        assert_equal(token_history, await self.cli.call(
            "token.scripthash.get_mempool", addr_scripthash))

        txid_send = get_txid_from_idem(n, txidem_send)
        assert_equal(token_history["transactions"][0]["tx_hash"], txid_send)

        # Mine transactions
        n.generate(1)
        self.sync_height()
        self.sync_mempool_count()
        assert_equal(0, len((await self.cli.call(
            "token.address.get_mempool", addr))["transactions"]))

        assert_equal(1, len((await self.cli.call(
            "token.address.get_history", addr))["transactions"]))

    async def test_token_filter(self):
        """
        Check that we can filter on tokenID's
        """
        n = self.n
        mint_to_addr = n.getnewaddress()
        token1_id_enc, token1_id_hex = await self.create_token(to_addr = mint_to_addr, mint_amount = 100)
        token2_id_enc, token2_id_hex = await self.create_token(to_addr = mint_to_addr, mint_amount = 100)

        addr = n.getnewaddress()
        addr_scripthash = await self.cli.call("blockchain.address.get_scripthash", addr)

        txidem_send = n.token("send", token1_id_enc, addr, 42)
        txidem_send2 = n.token("send", token2_id_enc, addr, 24)

        self.sync_mempool_count()
        # 2 transactions with 2 different tokens
        token_history = await self.cli.call("token.address.get_history", addr)
        assert_equal(2, len(token_history["transactions"]))

        # Filtering on one of the tokens should give 1 transaction
        token_history = await self.cli.call("token.address.get_history", addr, None, token1_id_hex)
        assert_equal(1, len(token_history["transactions"]))

if __name__ == '__main__':
    ElectrumTokenHistoryTests().main()
