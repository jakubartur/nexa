// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include "arith_uint256.h"
#include "pow.h"
#include "primitives/block.h"
#include "sync.h"
#include "tinyformat.h"
#include "uint256.h"
#include "util.h"

#include <atomic>
#include <vector>

extern CSharedCriticalSection cs_mapBlockIndex;
extern CTweak<uint64_t> nextMaxBlockSize;

class CBlockFileInfo
{
public:
    uint32_t nBlocks; //!< number of blocks stored in file
    uint64_t nSize; //!< number of used bytes of block file
    uint64_t nUndoSize; //!< number of used bytes in the undo file
    uint32_t nHeightFirst; //!< lowest height of block in file
    uint32_t nHeightLast; //!< highest height of block in file
    uint64_t nTimeFirst; //!< earliest time of block in file
    uint64_t nTimeLast; //!< latest time of block in file

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
    }

    void SetNull()
    {
        nBlocks = 0;
        nSize = 0;
        nUndoSize = 0;
        nHeightFirst = 0;
        nHeightLast = 0;
        nTimeFirst = 0;
        nTimeLast = 0;
    }

    CBlockFileInfo() { SetNull(); }
    std::string ToString() const;

    /** update statistics (does not update nSize) */
    void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn)
    {
        if (nBlocks == 0 || nHeightFirst > nHeightIn)
            nHeightFirst = nHeightIn;
        if (nBlocks == 0 || nTimeFirst > nTimeIn)
            nTimeFirst = nTimeIn;
        nBlocks++;
        if (nHeightIn > nHeightLast)
            nHeightLast = nHeightIn;
        if (nTimeIn > nTimeLast)
            nTimeLast = nTimeIn;
    }
};

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(VARINT(nFile, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() { SetNull(); }
    CDiskBlockPos(int nFileIn, unsigned int nPosIn)
    {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b)
    {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) { return !(a == b); }
    void SetNull()
    {
        nFile = -1;
        nPos = 0;
    }
    bool IsNull() const { return (nFile == -1); }
    std::string ToString() const { return strprintf("CBlockDiskPos(nFile=%i, nPos=%i)", nFile, nPos); }
};

enum BlockStatus : uint32_t
{
    //! Unused.
    BLOCK_VALID_UNKNOWN = 0,

    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER = 1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE = 2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS = 3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends
    //! Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN = 4,

    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS = 5,

    //! All validity bits.
    BLOCK_VALID_MASK =
        BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS | BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA = 8, //! full block available in blk*.dat
    BLOCK_HAVE_UNDO = 16, //! undo data available in rev*.dat
    BLOCK_HAVE_MASK = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID = 64, //! stage after last reached validness failed
    BLOCK_FAILED_CHILD = 128, //! descends from failed block
    BLOCK_FAILED_MASK = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
    BLOCK_PROCESSED = 256, //! block was processed (maybe pruned, maybe good, maybe bad)
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBlockIndex
{
public:
    //! pointer to the hash of the block, if any. Memory is owned by this CBlockIndex
    const uint256 *phashBlock;

    //! pointer to the index of the predecessor of this block
    CBlockIndex *pprev;

    //! pointer to the index of some further predecessor of this block
    CBlockIndex *pskip;

    //! height of the entry in the chain. The genesis block has height 0
    int64_t height() const { return ((int64_t)header.height); }

    //! Which # file this block is stored in (blk?????.dat)
    int nFile;

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos;

    //! Access the chain's total work as committed in the block header
    arith_uint256 chainWork() const { return UintToArith256(header.chainWork); }
    //! Access the transaction count as committed in the block header
    unsigned int txCount() const { return header.txCount; }
    //! Access the block time as committed in the block header
    unsigned int time() const { return header.nTime; }
    //! Access the difficulty target in "nBits" format, as committed in the block header
    uint32_t tgtBits() const { return header.nBits; }
    //! Access the merkle root as committed in the block header
    uint256 hashMerkleRoot() const { return header.hashMerkleRoot; }
    //! Access the nonce as committed in the block header
    const std::vector<unsigned char> &nonce() const { return header.nonce; }

    //! Return true if this block has been processed */
    bool processed() const { return ((nStatus & BLOCK_PROCESSED) != 0); }

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero only if and only if transactions for this block and all its parents are available.
    uint64_t nChainTx;

    //! Verification status of this block. See enum BlockStatus
    unsigned int nStatus;

    //! block header
    CBlockHeader header;

    //! Sequential id assigned to distinguish order in which blocks are received.
    uint64_t nSequenceId;

    //! The time (in seconds) the block header was added to the index.
    uint64_t nTimeReceived;

    //! Used in mining to determine the boundaries for block size
    uint64_t nNextMaxBlockSize;

    void SetNull()
    {
        phashBlock = nullptr;
        pprev = nullptr;
        pskip = nullptr;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainTx = 0;
        nStatus = 0;
        nSequenceId = 0;
        nTimeReceived = 0;
        nNextMaxBlockSize = 0;

        header.SetNull();
    }

    CBlockIndex() { SetNull(); }
    CBlockIndex(const CBlockHeader &block)
    {
        SetNull();
        header = block;
    }

    CDiskBlockPos GetBlockPos() const
    {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA)
        {
            ret.nFile = nFile;
            ret.nPos = nDataPos;
        }
        return ret;
    }

    CDiskBlockPos GetUndoPos() const
    {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO)
        {
            ret.nFile = nFile;
            ret.nPos = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block = header;
        // hashPrevBlock not initialized? So in release mode overwrite it
        if (pprev)
        {
            DbgAssert(header.hashPrevBlock == pprev->GetBlockHash(), block.hashPrevBlock = pprev->GetBlockHash());
        }
        return block;
    }

    /** return true for every block from fork block and forward [x,+inf)
     * state: fork activated */
    bool forkActivated(int time) const;

    /** return true only if we are exactly on the fork block [x,x]
     * state: fork activated */
    bool forkActivateNow(int time) const;

    /** This will check if the Fork will be enabled at the next block
     * i.e. we are at block x - 1, [x-1, +inf]
     * state fork: enabled or activated */
    bool IsforkActiveOnNextBlock(int time) const;

    /** return true only if 1st condition is true (Median past time > fork time)
     * and not the 2nd, i.e. we are at precisely [x-1,x-1]
     * state: fork enabled but not activateda */
    bool forkAtNextBlock(int time) const;

    uint256 GetBlockHash() const { return *phashBlock; }
    int64_t GetBlockTime() const { return (int64_t)header.nTime; }
    uint64_t GetBlockSize() const { return header.size; }
    enum
    {
        nMedianTimeSpan = 11
    };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t *pbegin = &pmedian[nMedianTimeSpan];
        int64_t *pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex *pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
        {
            if (pindex)
            {
                *(--pbegin) = pindex->GetBlockTime();
            }
        }

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin) / 2];
    }

    /** Return the time the header was added to the blockindex */
    int64_t GetHeaderReceivedTime() const { return nTimeReceived; }
    std::string ToString() const
    {
        return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)", pprev, header.height,
            header.hashMerkleRoot.ToString(), GetBlockHash().ToString());
    }

    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        AssertWriteLockHeld(cs_mapBlockIndex);
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo)
        {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    CBlockIndex *GetAncestor(int height);
    const CBlockIndex *GetAncestor(int height) const;

    //! Find the next maximum block size allowed
    uint64_t GetNextMaxBlockSize() const
    {
        // for testing purposes you can override the adapative block size settings
        // by using the tweak.
        if (nextMaxBlockSize.Value())
            return nextMaxBlockSize.Value();
        return nNextMaxBlockSize;
    }
};

arith_uint256 GetBlockProof(const CBlockIndex &block);

/**
 * Return the time it would take to redo the work difference between from and
 * to, assuming the current hashrate corresponds to the difficulty at tip, in
 * seconds.
 */
int64_t GetBlockProofEquivalentTime(const CBlockIndex &to,
    const CBlockIndex &from,
    const CBlockIndex &tip,
    const Consensus::Params &);

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
const CBlockIndex *LastCommonAncestor(const CBlockIndex *pa, const CBlockIndex *pb);

/**
 * Check if two block index are on the same fork.
 */
bool AreOnTheSameFork(const CBlockIndex *pa, const CBlockIndex *pb);

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    CDiskBlockIndex() {}
    explicit CDiskBlockIndex(const CBlockIndex *pindex) : CBlockIndex(*pindex) {}

    friend bool operator<(const CDiskBlockIndex &a, const CDiskBlockIndex &b) { return a.height() < b.height(); }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        // This is the serialization version, not the block version
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(VARINT(_nVersion, VarIntMode::NONNEGATIVE_SIGNED));

        READWRITE(VARINT(nStatus));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile, VarIntMode::NONNEGATIVE_SIGNED));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // block header
        READWRITE(header);

        // sequence id and time received
        READWRITE(VARINT(nSequenceId));
        READWRITE(nTimeReceived);

        // max size for the next block in the chain
        READWRITE(nNextMaxBlockSize);
    }

    uint256 GetBlockHash() const { return header.GetHash(); }


    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrevBlock=%s)", GetBlockHash().ToString(),
            header.hashPrevBlock.ToString());
        return str;
    }
};

/** An in-memory indexed chain of blocks. */
class CChain
{
private:
    std::vector<CBlockIndex *> vChain;

    // hold a copy of the tip outside of the vector so it can be accessed without holding cs_main
    std::atomic<CBlockIndex *> tip;

public:
    mutable CSharedCriticalSection cs_chainLock;

    CChain() : tip(nullptr) {}
    /** Reset this chain to constructed state -- used in unit tests to switch blockchains */
    void reset()
    {
        vChain.resize(0);
        tip = nullptr;
    }
    /** Returns the index entry for the genesis block of this chain, or nullptr if none. */
    CBlockIndex *Genesis() const { return vChain.size() > 0 ? vChain[0] : nullptr; }
    /** Returns the index entry for the tip of this chain, or nullptr if none.  Does not require cs_main. */
    CBlockIndex *Tip() const { return tip; }
    /** Returns the index entry at a particular height in this chain, or nullptr if no such height exists. */
    CBlockIndex *operator[](int nHeight) const
    {
        READLOCK(cs_chainLock);
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return nullptr;
        // We can return this outside of the lock because CBlockIndex objects are never deleted
        return vChain[nHeight];
    }

    /** Returns the index entry at a particular height in this chain, or nullptr if no such height exists. Lock free */
    CBlockIndex *_idx(int nHeight) const
    {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return nullptr;
        // We can return this outside of the lock because CBlockIndex objects are never deleted
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b)
    {
        READLOCK(a.cs_chainLock);
        READLOCK(b.cs_chainLock);
        return a.vChain.size() == b.vChain.size() && a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const
    {
        /* null pointer isn't in this chain but caller should not send in the first place */
        DbgAssert(pindex, return false);
        // lock not needed because operator [] locks
        return (*this)[pindex->height()] == pindex;
    }

    /** Efficiently check whether a block is present in this chain.  Lock free */
    bool _Contains(const CBlockIndex *pindex) const
    {
        /* null pointer isn't in this chain but caller should not send in the first place */
        DbgAssert(pindex, return false);
        return _idx(pindex->height()) == pindex;
    }

    /** Find the successor of a block in this chain, or nullptr if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const
    {
        READLOCK(cs_chainLock);
        if (_Contains(pindex))
            return _idx(pindex->height() + 1);
        else
            return nullptr;
    }

    /** Return the maximal height in the chain.  Does not require cs_main */
    int64_t Height() const
    {
        auto tmp = tip.load();
        if (tmp)
            return tmp->height();
        else
            return -1;
    }
    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator GetLocator(const CBlockIndex *pindex = nullptr) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;
};

#endif // BITCOIN_CHAIN_H
