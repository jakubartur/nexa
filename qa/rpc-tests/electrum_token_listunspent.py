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

DUST = 546

class ElectrumTokenListUnspentTests(ElectrumTestFramework):
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
                await self.test_listunspent()
            finally:
                self.cli.disconnect()
        asyncio.run(async_tests())

    async def test_listunspent(self):
        n = self.n
        cli = self.cli
        addr = n.getnewaddress()
        addr_mint = n.getnewaddress()
        addr_scripthash = await cli.call(
                "blockchain.address.get_scripthash", addr)
        utxo = (await cli.call("token.address.listunspent", addr))['unspent']
        assert_equal(0, len(utxo))
        assert_equal(
                utxo,
                (await cli.call("token.scripthash.listunspent", addr_scripthash))['unspent'])

        token1_id_enc, token1_id_hex = await self.create_token(
                to_addr = addr_mint, mint_amount = 100)

        txidem = n.token("send", token1_id_enc, addr, 42)
        txid = get_txid_from_idem(n, txidem)
        async def fetch_utxo():
            utxo = (await cli.call("token.address.listunspent", addr))['unspent']
            if len(utxo) > 0:
                return utxo
            return None

        utxo = await waitForAsync(10, fetch_utxo)
        assert_equal(1, len(utxo))

        assert_equal(0, utxo[0]['height'])
        assert_equal(txid, utxo[0]['tx_hash'])
        assert_equal(DUST, utxo[0]['value'])
        assert_equal(token1_id_hex, utxo[0]['token_id_hex'])
        assert_equal(42, utxo[0]['token_amount'])
        assert(utxo[0]['tx_pos'] in [0, 1])

        assert_equal(
                utxo,
                (await cli.call("token.scripthash.listunspent", addr_scripthash))['unspent'])

        n.generate(1)
        async def wait_for_confheight():
            utxo = (await cli.call("token.address.listunspent", addr))['unspent']
            return len(utxo) == 1 and utxo[0]['height'] == n.getblockcount()
        await waitForAsync(10, wait_for_confheight)


if __name__ == '__main__':
    ElectrumTokenListUnspentTests().main()
