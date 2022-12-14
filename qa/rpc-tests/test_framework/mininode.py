#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# mininode.py - Bitcoin P2P network half-a-node
#
# This python code was modified from ArtForz' public domain  half-a-node, as
# found in the mini-node branch of http://github.com/jgarzik/pynode.
#
# NodeConn: an object which manages p2p connectivity to a bitcoin node
# NodeConnCB: a base class that describes the interface for receiving
#             callbacks with network messages from a NodeConn
# CBlock, CTransaction, CBlockHeader, CTxIn, CTxOut, etc....:
#     data structures that should map to corresponding structures in
#     bitcoin/primitives
# msg_block, msg_tx, msg_headers, etc.:
#     data structures that represent network messages
# ser_*, deser_*: functions that handle serialization/deserialization

import pdb
import struct
import socket
import asyncore
import time
import sys
import random
from binascii import hexlify, unhexlify
from io import BytesIO
from codecs import encode
import hashlib
from threading import RLock
from threading import Thread
import logging
import copy
import traceback

from test_framework.util import waitFor, waitForBlockInChainTips
from .nodemessages import *
from .bumessages import *

import math
from .siphash import siphash256


MAX_INV_SZ = 50000
MAX_BLOCK_SIZE = 1000000

class MiniNodeError(Exception):
    pass

class DisconnectedError(MiniNodeError):
    pass

# Keep our own socket map for asyncore, so that we can track disconnects
# ourselves (to workaround an issue with closing an asyncore socket when
# using select)
mininode_socket_map = dict()

# This is what a callback should look like for NodeConn
# Reimplement the on_* functions to provide handling for events
class NodeConnCB(object):
    def __init__(self, extversion=None):
        """Pass None to not use extversion.  Pass a msg_extversion object to use that.  Pass True to use extversion, but your derived class will issue the message"""
        self.verack_received = False
        self.xverack_received = False
        self.xver = {}
        # deliver_sleep_time is helpful for debugging race conditions in p2p
        # tests; it causes message delivery to sleep for the specified time
        # before acquiring the global lock and delivering the next message.
        self.deliver_sleep_time = None
        self.disconnected = False
        self.extversion = extversion

    def set_deliver_sleep_time(self, value):
        with mininode_lock:
            self.deliver_sleep_time = value

    def get_deliver_sleep_time(self):
        with mininode_lock:
            return self.deliver_sleep_time

    # Spin until verack message is received from the node.
    # Tests may want to use this as a signal that the test can begin.
    # This can be called from the testing thread, so it needs to acquire the
    # global lock.
    def wait_for(self, test_function):
        for i in range(200):
            if self.disconnected:
                raise DisconnectedError()
            with mininode_lock:
                if test_function():
                    return
            time.sleep(0.05)
        raise TimeoutError("Waiting for %s timed out." % repr(test_function))

    def wait_for_verack(self):
        self.wait_for(lambda : self.verack_received)

    def deliver(self, conn, message):
        deliver_sleep = self.get_deliver_sleep_time()
        if deliver_sleep is not None:
            time.sleep(deliver_sleep)
        with mininode_lock:
            fn = 'on_' + message.command.decode('ascii')
            try:
                getattr(self, fn)(conn, message)
            except:
                print("ERROR delivering %s (%s) to %s" % (repr(message), sys.exc_info()[0], fn))
                traceback.print_exc()

    def on_version(self, conn, message):
        # Note, send a verack IF extversion is not being used.  Otherwise send extversion
        if self.extversion == None:
            if message.nVersion >= 209:
                conn.send_message(msg_verack())
        else:
            if type(self.extversion) == msg_extversion:
                conn.send_message(self.extversion)
        conn.ver_send = min(MY_VERSION, message.nVersion)
        if message.nVersion < 209:
            conn.ver_recv = conn.ver_send

    def on_verack(self, conn, message):
        conn.ver_recv = conn.ver_send
        self.verack_received = True

    def on_inv(self, conn, message):
        want = msg_getdata()
        for i in message.inv:
            if i.type != 0:
                want.inv.append(i)
        if len(want.inv):
            conn.send_message(want)

    def on_addr(self, conn, message): pass

    def on_alert(self, conn, message): pass

    def on_getdata(self, conn, message): pass

    def on_getblocks(self, conn, message): pass

    def on_tx(self, conn, message): pass

    def on_block(self, conn, message): pass

    def on_getaddr(self, conn, message): pass

    def on_headers(self, conn, message): pass

    def on_getheaders(self, conn, message): pass

    def on_ping(self, conn, message):
        conn.send_message(msg_pong(message.nonce))

    def on_reject(self, conn, message): pass

    def on_close(self, conn):
        self.disconnected=True
        pass

    def on_mempool(self, conn): pass

    def on_pong(self, conn, message): pass

    def on_sendheaders(self, conn, message): pass

    def on_sendcmpct(self, conn, message): pass

    def on_cmpctblock(self, conn, message): pass

    def on_getblocktxn(self, conn, message): pass

    def on_blocktxn(self, conn, message): pass

    def on_xverack_old(self, conn, message):
        self.xverack_received = True

    def on_extversion(self, conn, message):
        # reply with a verack since we got both the version and extversion messages
        conn.xver = message
        if self.extversion != None:  # already sent otherwise
            conn.send_message(msg_verack())

# More useful callbacks and functions for NodeConnCB's which have a single NodeConn


class SingleNodeConnCB(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.connection = None
        self.ping_counter = 1
        self.last_pong = msg_pong()

    def add_connection(self, conn):
        self.connection = conn

    # Wrapper for the NodeConn's send_message function
    def send_message(self, message, pushbuf = False):
        assert self.connection is not None, 'forgot to .add_connection'
        self.connection.send_message(message, pushbuf)

    def send_and_ping(self, message):
        self.send_message(message)
        self.sync_with_ping()

    def on_pong(self, conn, message):
        self.last_pong = message

    # Sync up with the node
    def sync_with_ping(self, timeout=30):
        def received_pong():
            return (self.last_pong.nonce == self.ping_counter)
        self.send_message(msg_ping(nonce=self.ping_counter))
        success = wait_until(received_pong, timeout)
        self.ping_counter += 1
        return success


def dupdate(x, y):
    x.update(y)
    return x


class MsgAnnotater:
    def __init__(self):
        self.idx = 0

    def annotate(self, msg, conn):
        msg.idx = self.idx
        msg.offset = conn.curIndex
        self.idx += 1
        return msg

# The actual NodeConn class
# This class provides an interface for a p2p connection to a specified node


class NodeConn(asyncore.dispatcher):
    messagemap = dupdate({
        b"version": msg_version,
        b"verack": msg_verack,
        b"addr": msg_addr,
        b"alert": msg_alert,
        b"inv": msg_inv,
        b"getdata": msg_getdata,
        b"getblocks": msg_getblocks,
        b"tx": msg_tx,
        b"block": msg_block,
        b"getaddr": msg_getaddr,
        b"ping": msg_ping,
        b"pong": msg_pong,
        b"headers": msg_headers,
        b"getheaders": msg_getheaders,
        b"reject": msg_reject,
        b"mempool": msg_mempool,
        b"sendheaders": msg_sendheaders,
        b"extversion" : msg_extversion,
        b"xupdate" : msg_xupdate,
        b"sendcmpct": msg_sendcmpct,
        b"cmpctblock": msg_cmpctblock,
        b"getblocktxn": msg_getblocktxn,
        b"blocktxn": msg_blocktxn,
        b"capdinv": msg_capdinv,
        b"capdgetmsg": msg_capdgetmsg,
        b"capdmsg": msg_capdmsg,
        b"capdq": msg_capdquery,
        b"capdqreply": msg_capdqreply,
        b"capdinfo": msg_capdinfo
    }, bumessagemap)

    MAGIC_BYTES = {
        "nexa": b"\x72\x27\x12\x21",   # mainnet
        "testnet3": b"\x72\x27\x12\x22",  # testnet3
        "regtest": b"\xea\xe5\xef\xea"    # regtest
        }

    def __init__(self, dstaddr, dstport, rpc, callback, net="regtest", services=1, send_initial_version = True, extversion_service = False):
        asyncore.dispatcher.__init__(self, map=mininode_socket_map)
        self.log = logging.getLogger("NodeConn(%s:%d)" % (dstaddr, dstport))
        self.dstaddr = dstaddr
        self.dstport = dstport
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sendbuf = b""
        self.recvbuf = b""
        self.ver_send = 209
        self.ver_recv = 209
        self.last_sent = 0
        self.state = "connecting"
        self.network = net
        self.cb = callback
        self.disconnect = False
        self.curIndex = 0
        self.allow0Checksum = False
        self.produce0Checksum = False
        self.num0Checksums = 0
        if send_initial_version:
            # stuff version msg into sendbuf
            vt = msg_version()
            if extversion_service:
                services = services | (1<<11)
            vt.nServices = services
            vt.addrTo.ip = self.dstaddr
            vt.addrTo.port = self.dstport
            vt.addrFrom.ip = "0.0.0.0"
            vt.addrFrom.port = 0
            self.send_message(vt, True)
        print('MiniNode: Connecting to Bitcoin Node IP # ' + dstaddr + ':'
              + str(dstport))
        try:
            self.connect((dstaddr, dstport))
        except:
            self.handle_close()
        self.rpc = rpc
        self.exceptions = []

    def show_debug_msg(self, msg):
        self.log.debug(msg)

    def handle_connect(self):
        self.show_debug_msg("MiniNode: Connected & Listening: \n")
        self.state = "connected"

    def handle_close(self):
        self.show_debug_msg("MiniNode: Closing Connection to %s:%d... "
                            % (self.dstaddr, self.dstport))
        self.state = "closed"
        self.recvbuf = b""
        self.sendbuf = b""
        try:
            self.close()
        except:
            pass
        self.cb.on_close(self)

    def parse_messages(self, buffer):
        if not type(buffer) == type(b""):  # if not a buffer its a file
            buffer = buffer.read()
        tmp = self.cb
        ret = []
        ann = MsgAnnotater()
        self.cb = type("", (), {"deliver": lambda self, conn, msg: ret.append(ann.annotate(msg, conn))})()
        self.inject_data(buffer)
        self.cp = tmp
        return ret

    def inject_data(self, buffer):
        self.recvbuf += buffer
        self.got_data()

    def handle_read(self):
        try:
            t = self.recv(8192)
            if len(t) > 0:
                self.recvbuf += t
                self.got_data()
        except:
            pass

    def readable(self):
        return True

    def writable(self):
        with mininode_lock:
            length = len(self.sendbuf)
        return (length > 0)

    def handle_write(self):
        with mininode_lock:
            try:
                sent = self.send(self.sendbuf)
                # print("actually sent: ", sent,  self.sendbuf)
            except:
                self.handle_close()
                return
            self.sendbuf = self.sendbuf[sent:]

    def got_data(self):
        self.recvBufLen = len(self.recvbuf)
        try:
            while True:
                nowLen = len(self.recvbuf)
                self.curIndex += (self.recvBufLen - nowLen)
                self.recvBufLen = nowLen
                if nowLen < 4:
                    return
                if (self.recvbuf[:4] != self.MAGIC_BYTES[self.network]):
                    raise ValueError("got garbage %s" % repr(self.recvbuf))
                if self.ver_recv < 209:
                    if len(self.recvbuf) < 4 + 12 + 4:
                        return
                    command = self.recvbuf[4:4 + 12].split(b"\x00", 1)[0]
                    msglen = struct.unpack("<i", self.recvbuf[4 + 12:4 + 12 + 4])[0]
                    checksum = None
                    if len(self.recvbuf) < 4 + 12 + 4 + msglen:
                        return
                    msg = self.recvbuf[4 + 12 + 4:4 + 12 + 4 + msglen]
                    self.recvbuf = self.recvbuf[4 + 12 + 4 + msglen:]
                else:
                    if len(self.recvbuf) < 4 + 12 + 4 + 4:
                        return
                    command = self.recvbuf[4:4 + 12].split(b"\x00", 1)[0]
                    msglen = struct.unpack("<i", self.recvbuf[4 + 12:4 + 12 + 4])[0]
                    checksum = self.recvbuf[4 + 12 + 4:4 + 12 + 4 + 4]
                    if len(self.recvbuf) < 4 + 12 + 4 + 4 + msglen:
                        return
                    msg = self.recvbuf[4 + 12 + 4 + 4:4 + 12 + 4 + 4 + msglen]
                    th = sha256(msg)
                    h = sha256(th)
                    if checksum != h[:4]:
                        if checksum == b'\x00\x00\x00\x00':
                            if self.allow0Checksum:
                                self.num0Checksums += 1
                            else:
                                raise ValueError("got zero checksum")
                        else:
                            raise ValueError("got bad checksum " + repr(self.recvbuf))
                    self.recvbuf = self.recvbuf[4 + 12 + 4 + 4 + msglen:]
                if command in self.messagemap:
                    f = BytesIO(msg)
                    t = self.messagemap[command]()
                    t.deserialize(f)
                    self.got_message(t)
                else:
                    print("Unknown command: '" + command.decode() + "' ")
                    self.show_debug_msg("Unknown command: '" + command.decode() + "' " +
                                        repr(msg))
                    # pdb.set_trace()
        except Exception as e:
            print('got_data:', repr(e))
            self.exceptions.append(e)
            import traceback
            traceback.print_tb(sys.exc_info()[2])
            pdb.post_mortem(e.__traceback__)

    def send_message(self, message, pushbuf=False):
        if self.state != "connected" and not pushbuf:
            raise IOError('Not connected, no pushbuf')
        self.show_debug_msg("Enqueue for send %s" % repr(message))
        command = message.command
        data = message.serialize()
        tmsg = self.MAGIC_BYTES[self.network]
        tmsg += command
        tmsg += b"\x00" * (12 - len(command))
        tmsg += struct.pack("<I", len(data))
        if self.ver_send >= 209:
            if self.produce0Checksum:
                tmsg += b"\x00" * 4
            else:
                th = sha256(data)
                h = sha256(th)
                tmsg += h[:4]
        tmsg += data
        with mininode_lock:
            self.sendbuf += tmsg
            self.last_sent = time.time()

    def got_message(self, message):
        if self.last_sent + 30 * 60 < time.time():
            self.send_message(self.messagemap[b'ping']())
        self.show_debug_msg("Recv %s" % repr(message))
        self.cb.deliver(self, message)

    def disconnect_node(self):
        self.disconnect = True


class NetworkThread(Thread):
    def run(self):
        while mininode_socket_map:
            # We check for whether to disconnect outside of the asyncore
            # loop to workaround the behavior of asyncore when using
            # select
            disconnected = []
            for fd, obj in mininode_socket_map.items():
                if obj.disconnect:
                    disconnected.append(obj)
            [obj.handle_close() for obj in disconnected]
            asyncore.loop(0.1, use_poll=True, map=mininode_socket_map, count=1)
        logging.info("mininode network processing thread completed")


# An exception we can raise if we detect a potential disconnect
# (p2p or rpc) before the test is complete
class EarlyDisconnectError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class P2PDataStore(SingleNodeConnCB):
    """A P2P data store class.

    Keeps a block and transaction store and responds correctly to getdata and getheaders requests."""

    def __init__(self):
        super().__init__()
        # store of blocks. key is block hash, value is a CBlock object
        self.block_store = {}
        self.last_block_hash = ''
        # store of txs. key is txid, value is a CTransaction object
        self.tx_store = {}
        self.getdata_requests = []

    def on_getdata(self, conn, message):
        """Check for the tx/block in our stores and if found, reply with an inv message."""
        for inv in message.inv:
            self.getdata_requests.append(inv.hash)
            if inv.type == CInv.MSG_TX and inv.hash in self.tx_store.keys():
                self.send_message(msg_tx(self.tx_store[inv.hash]))
            elif inv.type == CInv.MSG_BLOCK and inv.hash in self.block_store.keys():
                self.send_message(msg_block(self.block_store[inv.hash]))
            else:
                logging.debug(
                    'getdata message type {} received.'.format(hex(inv.type)))

    def on_getheaders(self, conn, message):
        """Search back through our block store for the locator, and reply with a headers message if found."""

        locator, hash_stop = message.locator, message.hashstop

        # Assume that the most recent block added is the tip
        if not self.block_store:
            return

        headers_list = [self.block_store[self.last_block_hash]]
        maxheaders = 2000
        while headers_list[-1].gethash() not in locator.vHave:
            # Walk back through the block store, adding headers to headers_list
            # as we go.
            prev_block_hash = headers_list[-1].hashPrevBlock
            if prev_block_hash in self.block_store:
                prev_block_header = CBlockHeader(
                    self.block_store[prev_block_hash])
                headers_list.append(prev_block_header)
                if prev_block_header.gethash() == hash_stop:
                    # if this is the hashstop header, stop here
                    break
            else:
                logging.debug('block hash {} not found in block store'.format(
                    hex(prev_block_hash)))
                break

        # Truncate the list if there are too many headers
        headers_list = headers_list[:-maxheaders - 1:-1]
        response = msg_headers(headers_list)

        if response is not None:
            self.send_message(response)

    def send_blocks_and_test(self, blocks, node, *, success=True, request_block=True, reject_reason=None, expect_ban=False, expect_disconnect=False, timeout=60):
        """Send blocks to test node and test whether the tip advances.

         - add all blocks to our block_store
         - send all headers
         - the on_getheaders handler will ensure that any getheaders are responded to
         - if request_block is True: wait for getdata for each of the blocks. The on_getdata handler will
           ensure that any getdata messages are responded to
         - if success is True: assert that the node's tip advances to the most recent block
         - if success is False: assert that the node's tip doesn't advance
         - if reject_reason is set: assert that the correct reject message is logged"""

        with mininode_lock:
            for block in blocks:
                self.block_store[block.gethash()] = block
                self.last_block_hash = block.gethash()

        def to_headers(blocks):
            return [CBlockHeader(b) for b in blocks]

        BAN_MSG = "BAN THRESHOLD EXCEEDED"
        expected_msgs = []
        unexpected_msgs = []
        if reject_reason:
            expected_msgs.append(reject_reason)
        if expect_ban:
            expected_msgs.append(BAN_MSG)
        else:
            unexpected_msgs.append(BAN_MSG)
        with node.assert_debug_log(expected_msgs = expected_msgs, unexpected_msgs = unexpected_msgs):

            self.send_message(msg_headers(to_headers(blocks)))

            if request_block:
                ok = wait_until(
                    lambda: blocks[-1].gethash() in self.getdata_requests, timeout=timeout)
                assert ok, "did not receive getdata for {}".format(blocks[-1].gethash())

            if expect_disconnect:
                self.wait_for_disconnect()
            else:
                self.sync_with_ping()

            if success:
                ok = wait_until(lambda: node.getbestblockhash() ==
                           blocks[-1].hash, timeout=timeout)
                assert ok, "node failed to sync to block {}".format(blocks[-1].gethash('hex'))
            else:
                ct = waitForBlockInChainTips(node, blocks[-1].hash, timeout)
                assert ct["status"] == 'invalid'  # Was expecting failure but block is not invalid
                gbbh = node.getbestblockhash()
                print(gbbh, blocks[-1].hash)
                assert gbbh != blocks[-1].hash

    def send_txs_and_test(self, txs, node, *, success=True, expect_ban=False, reject_reason=None, timeout=60):
        """Send txs to test node and test whether they're accepted to the mempool.

         - add all txs to our tx_store
         - send tx messages for all txs
         - if success is True/False: assert that the txs are/are not accepted to the mempool
         - if expect_disconnect is True: Skip the sync with ping
         - if reject_reason is set: assert that the correct reject message is logged."""
        assert(len(txs))
        with mininode_lock:
            for tx in txs:
                self.tx_store[tx.GetId()] = tx

        BAN_MSG = "BAN THRESHOLD EXCEEDED"
        expected_msgs = []
        unexpected_msgs = []
        if reject_reason:
            expected_msgs.append(reject_reason)
        if expect_ban:
            expected_msgs.append(BAN_MSG)
        else:
            unexpected_msgs.append(BAN_MSG)
        with node.assert_debug_log(
            expected_msgs = expected_msgs,
            unexpected_msgs = unexpected_msgs):

            for tx in txs:
                self.send_message(msg_tx(tx))

            self.sync_with_ping()

            if success:
                # Check that all txs are now in the mempool
                for tx in txs:
                    waitFor(timeout, lambda: tx.hash in node.getrawmempool(), onError="{} tx not found in mempool".format(tx.hash))
            else:
                # Check that none of the txs are now in the mempool
                for tx in txs:
                    waitFor(timeout, lambda: tx.hash not in node.getrawmempool(), onError="{} tx not found in mempool".format(tx.hash))
