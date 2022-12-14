#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

import pdb
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.nodemessages import *
from test_framework.script import *
# Create one-input, one-output, no-fee transaction:
class RawTransactionsTest(BitcoinTestFramework):

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        print(("Initializing test directory "+self.options.tmpdir))
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.extra_args = [["-relay.minRelayTxFee=1000"], ["-relay.minRelayTxFee=1000"],["-relay.minRelayTxFee=1000"],["-relay.minRelayTxFee=1000"]]
        self.nodes = start_nodes(4, self.options.tmpdir, self.extra_args)

        connect_nodes_full(self.nodes[:3])
        connect_nodes_bi(self.nodes,0,3)

        self.is_network_split=False
        self.sync_blocks()

    def checkBal(self, n):
        bal = n.getbalance()
        bal2 = n.getbalance("*")
        unspent = n.listunspent()
        amt = sum([ x["amount"] for x in unspent])
        assert amt == bal
        assert bal == bal2


    def run_test(self):
        print("Mining blocks...")

        min_relay_tx_fee = self.nodes[0].getnetworkinfo()['relayfee']
        # This test is not meant to test fee estimation and we'd like
        # to be sure all txs are sent at a consistent desired feerate
        for node in self.nodes:
            node.set("wallet.payTxFee=" + str(min_relay_tx_fee))

        # if the fee's positive delta is higher than this value tests will fail,
        # neg. delta always fail the tests.
        # The size of the signature of every input may be at most 2 bytes larger
        # than a minimum sized signature.

        # feeTolerance is the difference between the wallet's single-shot tx construction and the
        # stepwise (fundrawtransaction) construction.  Since these 2 constructions can legitimately include additional
        # inputs or outputs this tolerance needs to be pretty high
        feeTolerance = Decimal("2.00") # 200 bytes at 1 sat/byte

        self.nodes[2].generate(1)
        self.sync_blocks()
        self.nodes[0].generate(121)
        self.sync_blocks()

        assert self.nodes[3].getbalance() == Decimal("0")

        watchonly_address = self.nodes[0].getnewaddress()
        watchonly_pubkey = self.nodes[0].validateaddress(watchonly_address)["pubkey"]
        watchonly_amount = Decimal(200000000/50)
        self.nodes[3].importpubkey(watchonly_pubkey, "", True)

        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1000.5)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1000.0)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 5000.0)

        self.nodes[0].sendtoaddress(self.nodes[3].getnewaddress(), watchonly_amount/2)
        watchonly_txid = self.nodes[0].sendtoaddress(watchonly_address, watchonly_amount)

        self.nodes[0].generate(1)
        self.sync_blocks()
        self.checkBal(self.nodes[1])

        # Node 3 sees what we sent it
        assert self.nodes[3].getbalance("*") == watchonly_amount/2
        # Node 3 sees the watch only amount and what we sent it
        assert self.nodes[3].getbalance("*",1,True) == watchonly_amount + watchonly_amount/2

        ###############
        # simple test #
        ###############
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 1000.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert(len(dec_tx['vin']) > 0) #test if we have enought inputs

        #############################
        # test preserving nLockTime #
        #############################
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 1000.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs,1234)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert(dec_tx["locktime"] == 1234)

        ################################
        # test using default nLockTime #
        ################################
        blockcount =  self.nodes[0].getblockcount()
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 1000.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        # there's a random chance of an earlier locktime so iterate a few times
        for i in range(0,20):
            rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
            fee = rawtxfund['fee']
            dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
            if dec_tx["locktime"] == blockcount:
                break
            assert(dec_tx["locktime"] > 0)
            assert(i<18)  # incrediably unlikely to never produce the current blockcount

        ##############################
        # simple test with two coins #
        ##############################
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2000.2 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert(len(dec_tx['vin']) > 0) #test if we have enough inputs

        ##############################
        # simple test with two coins #
        ##############################
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2000.6 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert(len(dec_tx['vin']) > 0)
        assert_equal(dec_tx['vin'][0]['scriptSig']['hex'], '')


        ################################
        # simple test with two outputs #
        ################################
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2000.6, self.nodes[1].getnewaddress() : 2000.5 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        for out in dec_tx['vout']:
            totalOut += out['value']

        assert(len(dec_tx['vin']) > 0)
        assert_equal(dec_tx['vin'][0]['scriptSig']['hex'], '')


        #########################################################################
        # test a fundrawtransaction with a VIN greater than the required amount #
        #########################################################################
        utx = False
        listunspent = self.nodes[2].listunspent()
        for aUtx in listunspent:
            if aUtx['amount'] == 5000.0:
                utx = aUtx
                break

        assert(utx!=False)

        inputs  = [ {'outpoint' : utx['outpoint'], 'amount' : utx['amount']}]
        outputs = { self.nodes[0].getnewaddress() : 1000.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['outpoint'], dec_tx['vin'][0]['outpoint'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        for out in dec_tx['vout']:
            totalOut += out['value']

        assert_equal(fee + totalOut, utx['amount']) #compare vin total and totalout+fee


        #####################################################################
        # test a fundrawtransaction with which will not get a change output #
        #####################################################################
        utx = False
        listunspent = self.nodes[2].listunspent()
        for aUtx in listunspent:
            if aUtx['amount'] == 5000.0:
                utx = aUtx
                break

        assert(utx!=False)

        inputs  = [ {'outpoint' : utx['outpoint'], 'amount' : utx['amount']}]
        outputs = { self.nodes[0].getnewaddress() : Decimal(5000.0) - fee } #  - feeTolerance }  # BU having the fee tolerance in there creates a very small change output
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['outpoint'], dec_tx['vin'][0]['outpoint'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        txfee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        for out in dec_tx['vout']:
            totalOut += out['value']

        assert_equal(rawtxfund['changepos'], -1)
        assert_equal(txfee + totalOut, utx['amount']) #compare vin total and totalout+fee


        #########################################################################
        # test a fundrawtransaction with a VIN smaller than the required amount #
        #########################################################################
        utx = False
        listunspent = self.nodes[2].listunspent()
        for aUtx in listunspent:
            if aUtx['amount'] == 1000.0:
                utx = aUtx
                break

        assert(utx!=False)

        inputs  = [ {'outpoint' : utx['outpoint'], 'amount' : utx['amount']}]
        outputs = { self.nodes[0].getnewaddress() : utx['amount'] - decimal.Decimal("10.0") }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)

        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['outpoint'], dec_tx['vin'][0]['outpoint'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        matchingOuts = 0
        for i, out in enumerate(dec_tx['vout']):
            totalOut += out['value']
            if out['scriptPubKey']['addresses'][0] in outputs:
                matchingOuts+=1
            else:
                assert_equal(i, rawtxfund['changepos'])

        assert_equal(utx['outpoint'], dec_tx['vin'][0]['outpoint'])

        assert_equal(matchingOuts, 1)
        assert_equal(len(dec_tx['vout']), 2)


        ###########################################
        # test a fundrawtransaction with two VINs #
        ###########################################
        utx  = False
        utx2 = False
        listunspent = self.nodes[2].listunspent()
        for aUtx in listunspent:
            if aUtx['amount'] == 1000.0:
                utx = aUtx
            if aUtx['amount'] == 5000.0:
                utx2 = aUtx


        assert(utx!=False)

        inputs  = [ {'outpoint' : utx['outpoint'], 'amount' : utx['amount']}, {'outpoint' : utx2['outpoint'], 'amount' : utx2['amount']}]
        outputs = { self.nodes[0].getnewaddress() : 6000.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['outpoint'], dec_tx['vin'][0]['outpoint'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        matchingOuts = 0
        for out in dec_tx['vout']:
            totalOut += out['value']
            if out['scriptPubKey']['addresses'][0] in outputs:
                matchingOuts+=1

        assert_equal(matchingOuts, 1)
        assert_equal(len(dec_tx['vout']), 2)

        matchingIns = 0
        for vinOut in dec_tx['vin']:
            for vinIn in inputs:
                if vinIn['outpoint'] == vinOut['outpoint']:
                    matchingIns+=1

        assert_equal(matchingIns, 2) #we now must see two vins identical to vins given as params

        #########################################################
        # test a fundrawtransaction with two VINs and two vOUTs #
        #########################################################
        utx  = False
        utx2 = False
        listunspent = self.nodes[2].listunspent()
        for aUtx in listunspent:
            if aUtx['amount'] == 1000.0:
                utx = aUtx
            if aUtx['amount'] == 5000.0:
                utx2 = aUtx


        assert(utx!=False)

        inputs  = [ {'outpoint' : utx['outpoint'], 'amount' : utx['amount']}, {'outpoint' : utx2['outpoint'], 'amount' : utx2['amount']}]
        outputs = { self.nodes[0].getnewaddress() : 6000.0, self.nodes[0].getnewaddress() : 1000.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['outpoint'], dec_tx['vin'][0]['outpoint'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        matchingOuts = 0
        for out in dec_tx['vout']:
            totalOut += out['value']
            if out['scriptPubKey']['addresses'][0] in outputs:
                matchingOuts+=1

        assert_equal(matchingOuts, 2)
        assert_equal(len(dec_tx['vout']), 3)

        ##############################################
        # test a fundrawtransaction with invalid vin #
        ##############################################
        listunspent = self.nodes[2].listunspent()
        inputs  = [ {'outpoint' : "1c7f966dab21119bac53213a2bc7532bff1fa844c124fd750a7d0b1332440bd1", 'amount' : 1} ] #invalid vin!
        outputs = { self.nodes[0].getnewaddress() : 1000.0}
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        try:
            rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
            logging.info("Unspent: " + str(len(listunspent)) + "\n" + str(listunspent))  # if we spend more let's see what's unspent
            raise AssertionError("Spent more than available")
        except JSONRPCException as e:
            assert("Insufficient" in e.error['message'])


        ############################################################
        #compare fee of a standard transaction
        inputs = []
        outputs = {self.nodes[1].getnewaddress():1000.1}
        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawTx)
        signedTx = self.nodes[0].signrawtransaction(fundedTx["hex"])
        signedDecoded = self.nodes[0].decoderawtransaction(signedTx['hex'])
        signedFee = signedDecoded['fee']

        # fundrawtransaction should have the proper fee for signed tx, even though its not signed so compare
        # since schnorr sigs are 1 size this should be exact.
        assert fundedTx["fee"] == signedFee

        # create similar transaction over sendtoaddress
        txId = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000.1)
        signedFee2 = self.nodes[0].getrawtxpool(True)[txId]['fee']

        # compare fee to make sure both constructions are reasonable
        feeDelta = abs(Decimal(signedFee) - Decimal(fundedTx['fee']))
        assert feeDelta <= feeTolerance
        ############################################################

        ############################################################
        #compare fee of a standard transaction with multiple outputs
        inputs = []
        outputs = {self.nodes[1].getnewaddress():1000.1,self.nodes[1].getnewaddress():1000.2,self.nodes[1].getnewaddress():1000.1,self.nodes[1].getnewaddress():1000.3,self.nodes[1].getnewaddress():200,self.nodes[1].getnewaddress():300}
        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawTx)
        signedTx = self.nodes[0].signrawtransaction(fundedTx["hex"])
        signedDecoded = self.nodes[0].decoderawtransaction(signedTx['hex'])
        signedFee = signedDecoded['fee']

        # fundrawtransaction should have the proper fee for signed tx, even though its not signed so compare
        # since schnorr sigs are 1 size this should be exact.
        assert fundedTx["fee"] == signedFee

        # create same transaction over sendtoaddress
        txId = self.nodes[0].sendmany("", outputs)
        signedFee = self.nodes[0].getrawtxpool(True)[txId]['fee']

        # compare fee
        feeDelta = abs(Decimal(signedFee) - Decimal(fundedTx['fee']))
        assert feeDelta <= feeTolerance
        ############################################################


        ############################################################
        #compare fee of a 2of2 multisig p2sh transaction

        # create 2of2 addr
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[1].getnewaddress()

        addr1Obj = self.nodes[1].validateaddress(addr1)
        addr2Obj = self.nodes[1].validateaddress(addr2)

        mSigObj = self.nodes[1].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])

        inputs = []
        outputs = {mSigObj:1000.1}
        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawTx)

        #create same transaction over sendtoaddress
        txId = self.nodes[0].sendtoaddress(mSigObj, 1000.1)
        signedFee = self.nodes[0].getrawtxpool(True)[txId]['fee']

        #compare fee
        feeDelta = abs(Decimal(fundedTx['fee']) - Decimal(signedFee))
        assert feeDelta <= feeTolerance
        ############################################################
        self.checkBal(self.nodes[1])


        ############################################################
        #compare fee of a standard pubkeyhash transaction

        # create 4of5 addr
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[1].getnewaddress()
        addr3 = self.nodes[1].getnewaddress()
        addr4 = self.nodes[1].getnewaddress()
        addr5 = self.nodes[1].getnewaddress()

        addr1Obj = self.nodes[1].validateaddress(addr1)
        addr2Obj = self.nodes[1].validateaddress(addr2)
        addr3Obj = self.nodes[1].validateaddress(addr3)
        addr4Obj = self.nodes[1].validateaddress(addr4)
        addr5Obj = self.nodes[1].validateaddress(addr5)

        mSigObj = self.nodes[1].addmultisigaddress(4, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey'], addr4Obj['pubkey'], addr5Obj['pubkey']])

        inputs = []
        outputs = {mSigObj:1000.1}
        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[0].fundrawtransaction(rawTx)

        #create same transaction over sendtoaddress
        txId = self.nodes[0].sendtoaddress(mSigObj, 1000.1)
        signedFee = self.nodes[0].getrawtxpool(True)[txId]['fee']

        #compare fee
        feeDelta = abs(Decimal(fundedTx['fee']) - Decimal(signedFee))
        assert feeDelta <= feeTolerance
        ############################################################


        ############################################################
        # spend a 2of2 multisig transaction over fundraw

        # create 2of2 addr
        addr1 = self.nodes[2].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[2].validateaddress(addr1)
        addr2Obj = self.nodes[2].validateaddress(addr2)

        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])


        # send 1.2 BTC to msig addr
        txId = self.nodes[0].sendtoaddress(mSigObj, 1000.2)
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()
        self.checkBal(self.nodes[1])

        oldBalance = self.nodes[1].getbalance()
        inputs = []
        outputs = {self.nodes[1].getnewaddress():1000.1}
        rawTx = self.nodes[2].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[2].fundrawtransaction(rawTx)

        signedTx = self.nodes[2].signrawtransaction(fundedTx['hex'])
        txId = self.nodes[2].enqueuerawtransaction(signedTx['hex'], "flush")
        waitFor(5, lambda: self.nodes[1].gettxpoolinfo()["size"]>0)
        self.nodes[1].generate(1)
        self.sync_blocks()

        # make sure funds are received at node1
        assert_equal(oldBalance+Decimal('1000.10'), self.nodes[1].getbalance())
        self.checkBal(self.nodes[1])
        unspent = self.nodes[1].listunspent()

        ############################################################
        # locked wallet test
        self.nodes[1].encryptwallet("test")  # Recall the encryptwallet shuts bitcoind down
        self.nodes.pop(1)
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.nodes = start_nodes(4, self.options.tmpdir)
        self.checkBal(self.nodes[1])

        # This test is not meant to test fee estimation and we'd like
        # to be sure all txs are sent at a consistent desired feerate
        for node in self.nodes:
            node.set("wallet.payTxFee=" + str(min_relay_tx_fee))

        connect_nodes_full(self.nodes[:3])
        connect_nodes_bi(self.nodes,0,3)
        self.is_network_split=False
        self.sync_all()
        unspent2 = self.nodes[1].listunspent()
        diff = set([x["outpoint"] for x in unspent2]) ^ set([x["outpoint"] for x in unspent])
        self.checkBal(self.nodes[1])
        # drain the keypool
        self.nodes[1].getnewaddress()
        inputs = []
        outputs = {self.nodes[0].getnewaddress():1000.1}
        rawTx = self.nodes[1].createrawtransaction(inputs, outputs)
        # fund a transaction that requires a new key for the change output
        # creating the key must be impossible because the wallet is locked
        try:
            fundedTx = self.nodes[1].fundrawtransaction(rawTx)
            raise AssertionError("Wallet unlocked without passphrase")
        except JSONRPCException as e:
            assert('Keypool ran out' in e.error['message'])

        #refill the keypool
        self.nodes[1].walletpassphrase("test", 100)
        self.nodes[1].walletlock()

        self.checkBal(self.nodes[1])

        try:
            self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1000.2)
            raise AssertionError("Wallet unlocked without passphrase")
        except JSONRPCException as e:
            assert('walletpassphrase' in e.error['message'])

        oldBalance = self.nodes[0].getbalance()

        inputs = []
        outputs = {self.nodes[0].getnewaddress():1000.1}
        rawTx = self.nodes[1].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[1].fundrawtransaction(rawTx)

        #now we need to unlock
        self.nodes[1].walletpassphrase("test", 100)
        signedTx = self.nodes[1].signrawtransaction(fundedTx['hex'])
        txId = self.nodes[1].enqueuerawtransaction(signedTx['hex'],"flush")
        self.sync_all()
        self.nodes[1].generate(1)
        self.sync_all()

        # make sure funds are received at node1
        assert_equal(oldBalance+COINBASE_REWARD+Decimal('1000.10'), self.nodes[0].getbalance())


        ###############################################
        # multiple (~19) inputs tx test | Compare fee #
        ###############################################

        #empty node1, send some small coins from node0 to node1
        addr = self.nodes[0].getnewaddress()
        bal = self.nodes[1].getbalance()
        unspent = self.nodes[1].listunspent()
        amt = sum([ x["amount"] for x in unspent])
        amt1 = sum([ x["satoshi"] for x in unspent])
        assert amt1 == amt*COIN
        assert amt == bal
        self.nodes[1].sendtoaddress(addr, bal, "", "", True)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        for i in range(0,20):
            self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000.01)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        #fund a tx with ~20 small inputs
        inputs = []
        outputs = {self.nodes[0].getnewaddress():1000.15,self.nodes[0].getnewaddress():1000.04}
        rawTx = self.nodes[1].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[1].fundrawtransaction(rawTx)

        #create same transaction over sendtoaddress
        txId = self.nodes[1].sendmany("", outputs)
        signedFee = self.nodes[1].getrawtxpool(True)[txId]['fee']

        #compare fee
        feeDelta = Decimal(fundedTx['fee']) - Decimal(signedFee)
        assert(feeDelta >= 0 and feeDelta <= feeTolerance*19) #~19 inputs


        #############################################
        # multiple (~19) inputs tx test | sign/send #
        #############################################

        #again, empty node1, send some small coins from node0 to node1
        self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), self.nodes[1].getbalance(), "", "", True)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_blocks()

        for i in range(0,20):
            self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1000.01)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_blocks()

        #fund a tx with ~20 small inputs
        oldBalance = self.nodes[0].getbalance()

        inputs = []
        outputs = {self.nodes[0].getnewaddress():1000.15,self.nodes[0].getnewaddress():1000.04}
        rawTx = self.nodes[1].createrawtransaction(inputs, outputs)
        fundedTx = self.nodes[1].fundrawtransaction(rawTx)
        fundedAndSignedTx = self.nodes[1].signrawtransaction(fundedTx['hex'])
        txId = self.nodes[1].enqueuerawtransaction(fundedAndSignedTx['hex'], "flush")
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(oldBalance+COINBASE_REWARD+Decimal('2000.19'), self.nodes[0].getbalance()) #0.19+block reward

        #####################################################
        # test fundrawtransaction with OP_RETURN and no vin #
        #####################################################

        tx = CTransaction()
        tx.vout.append(TxOut(0, 100, scriptPubKey=CScript([OP_RETURN])))
        rawtx = tx.toHex()
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        assert_equal(len(dec_tx['vin']), 0)
        assert_equal(len(dec_tx['vout']), 1)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])

        assert_greater_than(len(dec_tx['vin']), 0) # at least one vin
        assert_equal(len(dec_tx['vout']), 2) # one change output added

        #####################################################
        # check transaction with invalid input amount       #
        #####################################################

        sigtxresult =  self.nodes[2].signrawtransaction(rawtxfund['hex'])
        tx = CTransaction(sigtxresult['hex'])
        tx.vin[0].amount -= 1
        result = self.nodes[2].validaterawtransaction(tx.toHex())
        assert result["inputs_flags"]['isValid'] == False, "invalid amount but valid tx"
        assert 'mandatory-script-verify-flag-failed' in "\n".join(result['inputs_flags']['inputs'][0]['errors']), ("signature (sighash) will fail because amount changed, but instead got:\n%s" % str(result))
        sigtxresult =  self.nodes[2].signrawtransaction(tx.toHex())
        assert sigtxresult['complete'] == False, "refuse to sign tx if input amount is not correct"

        ##################################################
        # test a fundrawtransaction using only watchonly #
        ##################################################

        # Node 3 sees what we sent it
        node3Bal = self.nodes[3].getbalance("*")
        # Node 3 sees the watch only amount and what we sent it
        node3WatchAndBal = self.nodes[3].getbalance("*",1,True)
        watchOnlyBal = node3WatchAndBal - node3Bal

        if watchOnlyBal < watchonly_amount:
            assert watchOnlyBal == 0  # Because if it was spent it should have been spent to change
            # Ok create a new watchonly tx
            watchonly_txid = self.nodes[0].sendtoaddress(watchonly_address, watchonly_amount)
            self.nodes[0].generate(1)
            self.sync_blocks()


        inputs = []
        outputs = {self.nodes[2].getnewaddress() : watchonly_amount - 1000000 }
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)

        result = self.nodes[3].fundrawtransaction(rawtx, True)
        res_dec = self.nodes[0].decoderawtransaction(result["hex"])
        assert_equal(len(res_dec["vin"]), 1)
        assert_equal(res_dec["vin"][0]["amount"], 4000000)
        watchOutpoint = res_dec["vin"][0]['outpoint']
        # make some guesses at what the outpoint probably is and compare
        assert watchOutpoint == COutPoint().fromIdemAndIdx(watchonly_txid,0).rpcHex() or watchOutpoint == COutPoint().fromIdemAndIdx(watchonly_txid,1).rpcHex() or watchOutpoint == COutPoint().fromIdemAndIdx(watchonly_txid,2).rpcHex()


        assert("fee" in result.keys())
        assert_greater_than(result["changepos"], -1)

        ###############################################################
        # test fundrawtransaction using the entirety of watched funds #
        # and another utxo to supply the fee                          #
        ###############################################################

        inputs = []
        outputs = {self.nodes[2].getnewaddress() : watchonly_amount}
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)

        result = self.nodes[3].fundrawtransaction(rawtx, True)
        res_dec = self.nodes[0].decoderawtransaction(result["hex"])
        assert_equal(len(res_dec["vin"]), 2)
        assert(res_dec["vin"][0]["outpoint"] == watchOutpoint or res_dec["vin"][1]["outpoint"] == watchOutpoint)

        assert_greater_than(result["fee"], 0)
        assert_greater_than(result["changepos"], -1)

        signedtx = self.nodes[3].signrawtransaction(result["hex"])
        assert(not signedtx["complete"])
        signedtx = self.nodes[0].signrawtransaction(signedtx["hex"])
        assert(signedtx["complete"])
        self.nodes[0].enqueuerawtransaction(signedtx["hex"],"flush")

        self.nodes[0].generate(1)
        self.sync_blocks()

        ################################
        # Test no address reuse occurs #
        ################################

        inputs = []
        outputs = {self.nodes[2].getnewaddress() : Decimal("1234.56") }
        rawtx = self.nodes[3].createrawtransaction(inputs, outputs)
        result3 = self.nodes[3].fundrawtransaction(rawtx)
        res_dec = self.nodes[0].decoderawtransaction(result3["hex"])
        changeaddress = ""
        for out in res_dec['vout']:
            if out['value'] != Decimal("1234.56"):
                changeaddress += out['scriptPubKey']['addresses'][0]
        assert(changeaddress != "")
        nextaddr = self.nodes[3].getnewaddress()
        # Now the change address key should be removed from the keypool
        assert(changeaddress != nextaddr)

if __name__ == '__main__':
    # this test sends a 0 value transaction so we need to turn off the fee percent check
    RawTransactionsTest().main(None,{"keypool":1 })

def Test():
    t = RawTransactionsTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc","net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "keypool":1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
