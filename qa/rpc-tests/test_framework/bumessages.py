import pdb

from .nodemessages import *

CAPD_NOMINAL_MSG_SIZE = 100

CAPD_MIN_FORWARD_MSG_DIFFICULTY = 0x007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
CAPD_MIN_LOCAL_MSG_DIFFICULTY = 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

CAPD_MIN_RELAY_PRIORITY = 2
CAPD_MIN_LOCAL_PRIORITY = 1

CAPD_QUERY_TYPE_MSG = 1
CAPD_QUERY_TYPE_MSG_HASH = 2
CAPD_QUERY_TYPE_ERROR = 3
CAPD_QUERY_TYPE_NOTIFICATION = 0x80
# CAPD_QUERY_TYPE_MSG_COMBINED = 3


def CapdMsgPriorityToDifficultyTarget(priority, msgContentSize):
    if msgContentSize > CAPD_NOMINAL_MSG_SIZE:
        priority = float(priority * msgContentSize) / float(CAPD_NOMINAL_MSG_SIZE)

    ret = CAPD_MIN_LOCAL_MSG_DIFFICULTY / priority;
    return int(ret)


class CapdMsg(object):
    FIELD_HAS_EXPIRATION  = 1
    FIELD_HAS_RESCINDHASH = 2
    def __init__(self, data=None):  # must provide a default empty ctor so deser_vector can construct this object
        self.createTime=0
        self.expiration=None
        self.rescindHash=None
        self.data = data
        self.difficultyBits = 0
        self.nonce = 0
        self.cachedHash = None

    def deserialize(self, f):
        if isinstance(f, str):
            # str - assumed to be hex string
            f = BytesIO(unhexlify(f))
        elif isinstance(f, bytes):
            f = BytesIO(f)

        fields = f.read(1)[0]
        self.createTime = struct.unpack("<Q", f.read(8))[0]
        self.difficultyBits = struct.unpack("<I", f.read(4))[0]
        self.nonce = deser_string(f)
        if fields & self.FIELD_HAS_EXPIRATION:
            self.expiration = struct.unpack("<H", f.read(2))[0]
        else:
            self.expiration = None
        if fields & self.FIELD_HAS_RESCINDHASH:
            self.rescindHash = f.read(20)
        else:
            self.rescindHash = None
        self.data = deser_string(f)
        return self

    def serialize(self, stype=SER_DEFAULT):
        flag = 0
        if self.expiration != None: flag |= self.FIELD_HAS_EXPIRATION
        if self.rescindHash != None: flag |= self.FIELD_HAS_RESCINDHASH
        r = chr(flag).encode()
        r += struct.pack("<Q", self.createTime)
        r += struct.pack("<I", self.difficultyBits)
        r += ser_string(self.nonce)
        if self.expiration != None: r += struct.pack("<H", self.expiration)
        if self.rescindHash != None:
            assert(len(self.rescindHash)==20)
            r += self.rescindHash
        r += ser_string(self.data)
        return r

    def setDifficultyBitsFromPriority(self, priority):
        t = CapdMsgPriorityToDifficultyTarget(priority, len(self.data))
        self.difficultyBits = compact_from_uint256(t)
        return self.difficultyBits

    def solve(self, minPriority):
        self.createTime = int(time.time())
        # convert priority to nBits format and back rather than straight to difficulty
        # because rounding during the conversion
        self.setDifficultyBitsFromPriority(minPriority)

        diffTarget = uint256_from_compact(self.difficultyBits)
        stage1 = sha256(self.serializeForHash())
        n = 0
        while 1:
            self.nonce = n.to_bytes(3, "big")
            hsh = hash256(stage1 + self.nonce)
            hshNum = int.from_bytes(hsh, "little")
            if hshNum <= diffTarget:
                self.cachedHash = hsh
                return True
            n += 1
        return False

    def getHash(self):
        if self.cachedHash != None: return self.cachedHash
        return self.getHash()

    def calcHash(self):
        stage1data = self.serializeForHash()
        stage1 = sha256(stage1data)
        hsh = hash256(stage1 + self.nonce)
        self.cachedHash = hsh
        return hsh

    def serializeForHash(self):
        r = ser_string(self.data)
        r += struct.pack("<Q", self.createTime)

        rs = self.rescindHash
        if rs == None:
            rs = b"\0"*20
        r += rs

        e = self.expiration
        if e == None: e = 0xffff
        r += struct.pack("<H", e)

        r += struct.pack("<I", self.difficultyBits)
        # print("hash serialization %s" % r.hex())
        return r

    def toHex(self):
        """Return the hex string serialization of this object"""
        return hexlify(self.serialize()).decode("utf-8")

    def __eq__(self,other):
        if not isinstance(other,CapdMsg): return False
        return self.createTime==other.createTime and self.expiration==other.expiration and self.rescindHash==other.rescindHash and self.data == other.data and self.difficultyBits == other.difficultyBits and self.nonce == other.nonce

    def __repr__(self):
        return "<CapdMsg createTime=%d expiration=%s difficultyBits=0x%x data=%s>" % (self.createTime, str(self.expiration), self.difficultyBits, ToHex(self.data))

class msg_capdgetinfo(object):
    command = b"capdgetinfo"

    def __init__(self):
        pass

    def deserialize(self, f):
        return self

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_capdgetinfo()"

class msg_capdinfo(object):
    command = b"capdinfo"

    def __init__(self):
        self.localPriority = 0.0
        self.relayPriority = 0.0
        self.highestPriority = 0.0

    def deserialize(self, f):
        self.localPriority = deser_double(f)
        self.relayPriority = deser_double(f)
        self.highestPriority = deser_double(f)
        return self

    def serialize(self):
        return ser_double(self.localPriority) + ser_double(self.relayPriority) + ser_double(self.highestPriority)

    def __repr__(self):
        return "msg_capdinfo(localPriority=%f, relayPriority=%f, highestPriority=%f)" % (self.localPriority, self.relayPriority, self.highestPriority)

class msg_capdinv(object):
    command = b"capdinv"
    CAPD_MSG_TYPE = 72

    def __init__(self, hashes=None):
        self.hashes = hashes

    def deserialize(self, f):
        invType = int(CompactSize().deserialize(f))
        assert(invType == msg_capdinv.CAPD_MSG_TYPE)
        self.hashes = deser_hash32_vector(f)
        return self

    def serialize(self):
        return CompactSize(msg_capdinv.CAPD_MSG_TYPE).serialize() + ser_hash32_vector(self.hashes)

    def __repr__(self):
        if self.hashes is not None:
            return "msg_capdinv(hashes=%s)" % (str(self.hashes))
        else:
            return "msg_capdinv(hashes=None)"

class msg_capdgetmsg(object):
    command = b"capdgetmsg"
    def __init__(self, hashes=None):
        self.hashes = hashes
        self.priorityCutoff = 0

    def deserialize(self, f):
        self.priorityCutoff = deser_double(f)
        self.hashes = deser_hash32_vector(f)
        return self

    def serialize(self):
        return ser_double(self.priorityCutoff) + ser_hash32_vector(self.hashes)

    def __repr__(self):
        if self.hashes is not None:
            return "msg_capdgetmsg()"
        else:
            return "msg_capdgetmsg()"

class msg_capdmsg(object):
    command = b"capdmsg"
    def __init__(self, msgs=None):
        self.msgs = msgs

    def deserialize(self, f):
        self.msgs = deser_vector(f, CapdMsg)
        return self

    def serialize(self):
        return ser_vector(self.msgs)

    def __repr__(self):
        if self.msgs is not None:
            return "msg_capdmsg([%d msgs])" % len(self.msgs)
        else:
            return "msg_capdmsg()"

class msg_capdquery(object):
    command = b"capdq"

    def __init__(self, cookie, typ, start, quantity, content):
        self.cookie = cookie
        self.typ = typ
        self.start = start
        self.quantity = quantity
        self.content = content

    def deserialize(self, f):
        self.cookie = struct.unpack("<I", f.read(4))[0]
        self.typ = struct.unpack("<B", f.read(1))[0]
        self.start = struct.unpack("<I", f.read(4))[0]
        self.quantity = struct.unpack("<I", f.read(4))[0]
        self.content = deser_string(f)
        return self

    def serialize(self):
        r = struct.pack("<I", self.cookie)
        r += struct.pack("<B", self.typ)
        r += struct.pack("<I", self.start)
        r += struct.pack("<I", self.quantity)
        r += ser_string(self.content)
        return r

    def __eq__(self,other):
        if not isinstance(other,msg_capdquery): return False
        return self.cookie == other.cookie and self.typ == other.typ and self.start == other.start and self.quantity == other.quantity and self.content == other.content

    def __repr__(self):
        return "msg_capdquery(cookie=%d, type=%d, start=%d, quantity=%d, content=%s)" % (self.cookie, self.typ, self.start, self.quantity, hexlify(self.content).decode())

class msg_capdqreply(object):
    command = b"capdqreply"

    def __init__(self, cookie=None, typ=None, msgs=None):
        self.cookie = cookie
        self.typ = typ
        self.totalMsgs = len(msgs) if msgs != None else 0  # Because there might be more matching messages than we will provide (although this python code assumes not)
        self.msgs = msgs

    def deserialize(self, f):
        self.cookie = struct.unpack("<I", f.read(4))[0]
        self.typ = struct.unpack("<B", f.read(1))[0]
        if self.typ == CAPD_QUERY_TYPE_ERROR:
            print(f.read(1))
            assert False, "Message error"
        self.totalMsgs = struct.unpack("<I", f.read(4))[0]
        if self.typ == CAPD_QUERY_TYPE_MSG:
            self.msgs = deser_vector(f, CapdMsg)
        elif self.typ == CAPD_QUERY_TYPE_MSG_HASH:
            self.msgs = deser_hash32_vector(f)
        else:
            assert False, "message content type is invalid"
        return self

    def serialize(self):
        r = struct.pack("<I", self.cookie)
        r += struct.pack("<B", self.typ)
        r += struct.pack("<I", self.totalMsgs)
        r += ser_vector(self.msgs)
        return r

    def __eq__(self,other):
        if not isinstance(other,msg_capdqreply): return False
        return self.cookie == other.cookie and self.msgs == other.msgs

    def __repr__(self):
        return "msg_capdqreply(cookie=%d, total=%d, type=%s, msgs=%s)" % (self.cookie, self.totalMsgs, "msgs" if self.typ == CAPD_QUERY_TYPE_MSG else "hashes" if self.typ == CAPD_QUERY_TYPE_MSG_HASH else "unknown", str(self.msgs))

class msg_capdremove(object):
    command = b"capdremove"

    def __init__(self, cookie=None):
        self.cookie = cookie

    def deserialize(self, f):
        self.cookie = struct.unpack("<I", f.read(4))[0]
        return self

    def serialize(self):
        r = struct.pack("<I", self.cookie)
        return r

    def __eq__(self,other):
        if not isinstance(other,msg_capdremove): return False
        return self.cookie == other.cookie

    def __repr__(self):
        return "msg_capdremove(cookie=%d)" % (self.cookie)

class msg_buversion(object):
    command = b"buversion"

    def __init__(self, addrFromPort=None):
        self.addrFromPort = addrFromPort

    def deserialize(self, f):
        self.addrFromPort = struct.unpack("<H", f.read(2))[0]
        return self

    def serialize(self):
        r = b""
        r += struct.pack("<H", self.addrFromPort)
        return r

    def __repr__(self):
        if self.addrFromPort is not None:
            return "msg_buversion(addrFromPort=%d)" % (self.addrFromPort)
        else:
            return "msg_buversion(addrFromPort=None)"


class msg_buverack(object):
    command = b"buverack"

    def __init__(self):
        pass

    def deserialize(self, f):
        return self

    def serialize(self):
        r = b""
        return r

    def __repr__(self):
        return "msg_buverack()"


class QHash(object):
    """quarter hash"""

    def __init__(self, shortHash=None):
        self.hash = shortHash

    def deserialize(self, f):
        self.hash = struct.unpack("<Q", f.read(8))[0]
        return self

    def serialize(self):
        r = b""
        r += struct.pack("<Q", self.hash)
        return r

    def __repr__(self):
        return "QHash(0x%016x)" % (self.hash)


class Hash(object):
    """sha256 hash"""

    def __init__(self, hash=None):
        self.hash = hash

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        return self

    def serialize(self):
        r = b""
        r += ser_uint256(self.hash)
        return r

    def __str__(self):
        return "%064x" % self.hash

    def __repr__(self):
        return "Hash(%064x)" % self.hash


class CXThinBlock(CBlockHeader):
    def __init__(self, header=None, vTxHashes=None, vMissingTx=None):
        super(CXThinBlock, self).__init__(header)
        self.vTxHashes = vTxHashes
        self.vMissingTx = vMissingTx

    def deserialize(self, f):
        super(CXThinBlock, self).deserialize(f)
        self.vTxHashes = deser_vector(f, QHash)
        self.vMissingTx = deser_vector(f, CTransaction)
        return self

    def serialize(self):
        r = b""
        r += super(CXThinBlock, self).serialize()
        r += ser_vector(self.vTxHashes)
        r += ser_vector(self.vMissingTx)
        return r

    def summary(self):
        s = []
        s.append(super(self.__class__, self).summary())
        s.append("\nQuarter Hashes")
        count = 0
        for qh in self.vTxHashes:
            if (count % 5) == 0:
                s.append("\n%4d: " % count)
            s.append("%016x " % qh.hash)
            count += 1

        s.append("\nFull Transactions\n")
        count = 0
        for tx in self.vMissingTx:
            s.append("%4d: %s\n" % (count, tx.summary()))
            count += 1
        return "".join(s)

    def __str__(self):
        return "CXThinBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vTxHashes_len=%d vMissingTx_len=%d)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot, time.ctime(self.nTime), self.nBits, self.nNonce, len(self.vTxHashes), len(self.vMissingTx))

    # For normal "mainnet" blocks, this function produces a painfully large single line output.
    # It is so large, you may be forced to kill your python shell just to get it to stop.
    # But it is easy to accidentally call repr from the python interactive shell or pdb.  There is no current
    # use and removing this function call makes interactive sessions easier to use.
    # However, the function shall be left commented out for symmetry with the other objects and in case
    # it is needed.
    # def __repr__(self):
    #    return "CXThinBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vTxHashes=%s vMissingTx=%s)" \
    #        % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
    #           time.ctime(self.nTime), self.nBits, self.nNonce, repr(self.vTxHashes), repr(self.vMissingTx))


class CThinBlock(CBlockHeader):
    def __init__(self, header=None):
        super(self.__class__, self).__init__(header)
        self.vTxHashes = []
        self.vMissingTx = []

    def deserialize(self, f):
        super(self.__class__, self).deserialize(f)
        self.vTxHashes = deser_vector(f, Hash)
        self.vMissingTx = deser_vector(f, CTransaction)
        return self

    def serialize(self):
        r = b""
        r += super(self.__class__, self).serialize()
        r += ser_vector(self.vTxHashes)
        r += ser_vector(self.vMissingTx)
        return r

    def __str__(self):
        return "CThinBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vTxHashes_len=%d vMissingTx_len=%d)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot, time.ctime(self.nTime), self.nBits, self.nNonce, len(self.vTxHashes), len(self.vMissingTx))

    # For normal "mainnet" blocks, this function produces a painfully large single line output.
    # It is so large, you may be forced to kill your python shell just to get it to stop.
    # But it is easy to accidentally call repr from the python interactive shell or pdb.  There is no current
    # use and removing this function call makes interactive sessions easier to use.
    # However, the function shall be left commented out for symmetry with the other objects and in case
    # it is needed.
    # def __repr__(self):
    #    return "CThinBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vTxHashes=%s vMissingTx=%s)" \
    #        % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
    #           time.ctime(self.nTime), self.nBits, self.nNonce, repr(self.vTxHashes), repr(self.vMissingTx))


class CBloomFilter:
    def __init__(self, vData=b"", hashFuncs=0, tweak=0, flags = 0):
        self.vData = vData
        self.nHashFuncs = hashFuncs
        self.nTweak = tweak
        self.nFlags = flags

    def deserialize(self, f):
        self.vData = deser_string(f)
        self.nHashFuncs = struct.unpack("<I", f.read(4))[0]
        self.nTweak = struct.unpack("<I", f.read(4))[0]
        self.nFlags = struct.unpack("<B", f.read(1))[0]
        return self

    def serialize(self):
        r = b""
        r += ser_string(self.vData)
        r += struct.pack("<I", self.nHashFuncs)
        r += struct.pack("<I", self.nTweak)
        r += struct.pack("<B", self.nFlags)
        return r

    def __repr__(self):
        return "%s(vData=%s)" % (self.__class__.__name__, self.vData)


class CMemPoolSize:
    def __init__(self, vData=None):
        self.vData = vData
        self.nHashFuncs = None
        self.nTweak = None
        self.nFlags = None

    def deserialize(self, f):
        self.vData = deser_string(f)
        self.nHashFuncs = struct.unpack("<I", f.read(4))[0]
        self.nTweak = struct.unpack("<I", f.read(4))[0]
        self.nFlags = struct.unpack("<B", f.read(1))[0]
        return self

    def serialize(self):
        r = b""
        r += ser_string(f, self.vData)
        r += struct.pack("<I", self.nHashFuncs)
        r += struct.pack("<I", self.nTweak)
        r += struct.pack("<B", self.nFlags)
        return r

    def __repr__(self):
        return "%s(vData=%s)" % (self.__class__.__name__, self.vData)



class msg_thinblock(object):
    command = b"thinblock"

    def __init__(self, block=None):
        if block is None:
            self.block = CThinBlock()
        else:
            self.block = block

    def deserialize(self, f):
        self.block.deserialize(f)
        return self

    def serialize(self):
        return self.block.serialize()

    def __str__(self):
        return "msg_thinblock(block=%s)" % (str(self.block))

    def __repr__(self):
        return "msg_thinblock(block=%s)" % (repr(self.block))


class msg_xthinblock(object):
    command = b"xthinblock"

    def __init__(self, block=None):
        if block is None:
            self.block = CXThinBlock()
        else:
            self.block = block

    def deserialize(self, f):
        self.block.deserialize(f)
        return self

    def serialize(self):
        return self.block.serialize()

    def __str__(self):
        return "msg_xthinblock(block=%s)" % (str(self.block))

    def __repr__(self):
        return "msg_xthinblock(block=%s)" % (repr(self.block))


class msg_Xb(object):
    """Expedited block message"""
    command = b"Xb"
    EXPEDITED_MSG_HDR = 1
    EXPEDITED_MSG_XTHIN = 2

    def __init__(self, block=None, hops=0, msgType=EXPEDITED_MSG_XTHIN):
        self.msgType = msgType
        self.hops = hops
        self.block = block

    def deserialize(self, f):
        self.msgType = struct.unpack("<B", f.read(1))[0]
        self.hops = struct.unpack("<B", f.read(1))[0]
        if self.msgType == EXPEDITED_MSG_XTHIN:
            self.block = CXThinBlock()
            self.block.deserialize(f)
        else:
            self.block = None
        return self

    def serialize(self):
        r = b""
        r += struct.pack("<B", self.msgType)
        r += struct.pack("<B", self.hops)
        if self.msgType == EXPEDITED_MSG_XTHIN:
            r += self.block.serialize()
        return r

    def __str__(self):
        return "msg_Xb(block=%s)" % (str(self.block))

    def __repr__(self):
        return "msg_Xb(block=%s)" % (repr(self.block))


class msg_get_xthin(object):
    command = b"get_xthin"

    def __init__(self, inv=None, filter=None):
        self.inv = inv
        self.filter = filter if filter != None else CBloomFilter()

    def deserialize(self, f):
        self.inv = CInv()
        self.inv.deserialize(f)
        self.filter = CBloomFilter()
        self.filter.deserialize(f)
        return self

    def serialize(self):
        r = b""
        r += self.inv.serialize()
        r += self.filter.serialize()
        return r

    def __repr__(self):
        return "%s(inv=%s,filter=%s)" % (self.__class__.__name__, repr(self.inv), repr(self.filter))

class msg_get_thin(object):
    command = b"get_thin"

    def __init__(self, inv=None):
        self.inv = inv

    def deserialize(self, f):
        self.inv = CInv()
        self.inv.deserialize(f)
        return self

    def serialize(self):
        r = b""
        r += self.inv.serialize()
        return r

    def __repr__(self):
        return "%s(inv=%s)" % (self.__class__.__name__, repr(self.inv))


class msg_filterload(object):
    command = b"filterload"

    def __init__(self, inv=None, filter=None):
        self.filter = filter

    def deserialize(self, f):
        self.filter = CBloomFilter()
        self.filter.deserialize(f)
        return self

    def serialize(self):
        r = b""
        r += self.filter.serialize()
        return r

    def __repr__(self):
        return "%s(filter=%s)" % (self.__class__.__name__, repr(self.filter))


class msg_filteradd(object):
    command = b"filteradd"

    def __init__(self, inv=None, filter=None):
        self.filter = filter

    def deserialize(self, f):
        self.filter = deser_string(f)
        return self

    def serialize(self):
        r = b""
        r += ser_string(f, self.filter)
        return r

    def __repr__(self):
        return "%s(filteradd=%s)" % (self.__class__.__name__, repr(self.filter))


class msg_filterclear(object):
    command = b"filterclear"

    def __init__(self):
        pass

    def deserialize(self, f):
        return self

    def serialize(self):
        r = b""
        return r

    def __repr__(self):
        return "msg_filterclear()"


class msg_get_xblocktx(object):
    command = b"get_xblocktx"

    def __init__(self, blockhash=None, qhashes=None):
        self.blockhash = blockhash
        self.setCheapHashesToRequest = qhashes

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        self.setCheapHashesToRequest = deser_vector(f, QHash)
        return self

    def serialize(self):
        r = b""
        r += ser_uint256(self.blockhash)
        r += ser_vector(self.setCheapHashesToRequest)
        return r

    def __repr__(self):
        return "%s(blockhash=%s,qhash=%s)" % (self.__class__.__name__, repr(self.blockhash), repr(self.setCheapHashesToRequest))


class msg_req_xpedited(object):
    """request expedited blocks"""
    command = b"req_xpedited"
    EXPEDITED_STOP = 1
    EXPEDITED_BLOCKS = 2
    EXPEDITED_TXNS = 4

    def __init__(self, options=None):
        self.options = options

    def deserialize(self, f):
        self.options = struct.unpack("<Q", f.read(8))[0]
        return self

    def serialize(self):
        r = b""
        r += struct.pack("<Q", self.options)
        return r

    def __repr__(self):
        return "%s(0x%x)" % (self.__class__.__name__, self.options)


bumessagemap = {
    msg_xthinblock.command: msg_xthinblock,
    msg_thinblock.command: msg_thinblock,
    msg_get_xthin.command: msg_get_xthin,
    msg_get_xblocktx.command: msg_get_xblocktx,
    msg_filterload.command: msg_filterload,
    msg_filteradd.command: msg_filteradd,
    msg_filterclear.command: msg_filterclear,
    msg_Xb.command: msg_Xb,
    msg_req_xpedited.command: msg_req_xpedited,
}
