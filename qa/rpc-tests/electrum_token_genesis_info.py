#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Unlimited developers
import asyncio
from test_framework.util import assert_equal
from test_framework.loginit import logging
from test_framework.electrumutil import (
        ElectrumConnection,
        ElectrumTestFramework,
)

class ElectrumTokenGenesisInfo(ElectrumTestFramework):
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
                await self.test_basic()
                await self.test_with_token_history()
            finally:
                self.cli.disconnect()
        asyncio.run(async_tests())

    async def test_basic(self):
        n = self.n
        cli = self.cli
        addr = n.getnewaddress()

        ticker = "TICKER"
        name = "Some Name"
        url = "https://example.org"
        doc_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

        token_id, token_id_hex = await self.create_token(
            ticker, name, url, doc_hash,
            to_addr = addr, mint_amount = 100)

        # Get token info from mempool NYI
        n.generate(1)
        self.sync_height()

        info = await cli.call("token.genesis.info", token_id)
        assert 'txid' in info
        assert 'txidem' in info
        assert_equal(token_id_hex, info['token_id_hex'])
        assert_equal(doc_hash, info['document_hash'])
        assert_equal(ticker, info['ticker'])
        assert_equal(name, info['name'])


    async def test_with_token_history(self):
        """
        Check that electrum is able to find genesis also when there are
        other token transactions within the same block as genesis transaction
        """
        n = self.n
        cli = self.cli
        addr = n.getnewaddress()

        n = self.n
        cli = self.cli
        addr = n.getnewaddress()

        token_id, _ = await self.create_token(
            "DUMMY", "dummy token",
            to_addr = addr, mint_amount = 20)

        for _ in range(1, 20):
            n.token("send", token_id, addr, 10)

        n.generate(1)
        self.sync_height()
        info = await cli.call("token.genesis.info", token_id)
        assert_equal("DUMMY", info['ticker'])
if __name__ == '__main__':
    ElectrumTokenGenesisInfo().main()
