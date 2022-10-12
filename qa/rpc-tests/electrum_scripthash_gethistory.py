#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Unlimited developers
"""
Tests specific for the electrum call 'blockchain.scripthash.get_history'
"""
import asyncio
from test_framework.util import assert_equal
from test_framework.electrumutil import (
        ElectrumTestFramework,
        ElectrumConnection,
        script_to_scripthash,
        sync_electrum_height,
        get_txid_from_idem)
from test_framework.blocktools import create_transaction, pad_tx
from test_framework.script import CScript, OP_TRUE, OP_DROP, OP_NOP

GET_HISTORY = "blockchain.scripthash.get_history"
ADDRESS_GET_HISTORY = "blockchain.address.get_history"

class ElectrumScripthashGetHistory(ElectrumTestFramework):

    def run_test(self):
        n = self.nodes[0]
        self.bootstrap_p2p()
        coinbases = self.mine_blocks(n, 100)

        async def async_tests():
            cli = ElectrumConnection()
            await cli.connect()
            await self.test_blockheight_confirmed(n, cli, coinbases.pop(0))
            await self.test_tokens_in_history(n, cli)

        asyncio.run(async_tests())

    async def test_blockheight_confirmed(self, n, cli, unspent):
        # Just a unique anyone-can-spend scriptpubkey
        scriptpubkey = CScript([OP_TRUE, OP_DROP, OP_NOP])
        scripthash = script_to_scripthash(scriptpubkey)

        # There should exist any history for scripthash
        assert_equal(0, len(await cli.call(GET_HISTORY, scripthash)))

        # Send tx to scripthash and confirm it
        tx = create_transaction(unspent,
                n = 0, value = unspent.vout[0].nValue,
                sig = CScript([OP_TRUE]), out = scriptpubkey)

        self.mine_blocks(n, 1, txns = [tx])
        sync_electrum_height(n)

        # History should now have 1 entry at current tip height
        res = await cli.call(GET_HISTORY, scripthash)
        assert_equal(1, len(res))
        assert_equal(n.getblockcount(), res[0]['height'])
        assert_equal(tx.GetRpcHexId(), res[0]['tx_hash'])

    async def test_tokens_in_history(self, n, cli):
        """
        Even though token amounts are added to outputs
        scriptpubkey (and would change the script hash),
        they should still be found by address query.
        """
        # Node needs coins for fees
        n.generate(101)

        # Create and send tokens

        addr1 = n.getnewaddress()
        addr2 = n.getnewaddress()

        token = n.token("new")
        group_id = token["groupIdentifier"]
        txidem_mint = n.token("mint", group_id, addr1, 42)
        txidem_send = n.token("send", group_id, addr1, 42)
        txidem_send2 = n.token("send", group_id, addr2, 42)

        mempool = n.getrawtxpool()
        self.wait_for_mempool_count(count = len(mempool))

        def has_tx(res, txhash):
            for tx in res:
                if tx['tx_hash'] == txhash:
                    return True
            return False

        # addr1 should have all 3 transactions in its history.
        res = await cli.call(ADDRESS_GET_HISTORY, addr1)
        assert_equal(3, len(res))
        assert(has_tx(res, get_txid_from_idem(n, txidem_mint)))
        assert(has_tx(res, get_txid_from_idem(n, txidem_send)))
        assert(has_tx(res, get_txid_from_idem(n, txidem_send2)))

        # addr2 should have the last send in its history
        res = await cli.call(ADDRESS_GET_HISTORY, addr2)
        assert_equal(1, len(res))
        assert(has_tx(res, get_txid_from_idem(n, txidem_send2)))

if __name__ == '__main__':
    ElectrumScripthashGetHistory().main()
