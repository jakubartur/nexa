// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_MINER_H
#define NEXA_MINER_H

#include "primitives/block.h"
#include "txmempool.h"

#include <memory>
#include <stdint.h>

#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"

class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_coinbaseFlags;

extern std::atomic<int64_t> nTotalPackage;

// Padding for block header VARINT's
static const uint64_t TXCOUNT_VARINT_PADDING = 5;
static const uint64_t HEIGHT_VARINT_PADDING = 5;
static const uint64_t FEEPOOL_VARINT_PADDING = 5;

namespace Consensus
{
struct Params;
};

static const bool DEFAULT_PRINTPRIORITY = false;

// Determine the correct version bits based on bip135 choices and passed settings
int32_t UtilMkBlockTmplVersionBits(int32_t version,
    const std::set<std::string> &setClientRules,
    CBlockIndex *pindexPrev,
    UniValue *paRules,
    UniValue *pvbavailable);

struct CBlockTemplate
{
    CBlockRef block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;

    CBlockTemplate() { block = MakeBlockRef(); }
};


/** Comparator for CTxMemPool::TxIdIter objects.
 *  It simply compares the internal memory address of the CTxMemPoolEntry object
 *  pointed to. This means it has no meaning, and is only useful for using them
 *  as key in other indexes.
 */
struct CompareCTxMemPoolIter
{
    bool operator()(const CTxMemPool::TxIdIter &a, const CTxMemPool::TxIdIter &b) const { return &(*a) < &(*b); }
};

/** A comparator that sorts transactions based on number of ancestors.
 * This is sufficient to sort an ancestor package in an order that is valid
 * to appear in a block.
 */
struct CompareTxIdIterByAncestorCount
{
    bool operator()(const CTxMemPool::TxIdIter &a, const CTxMemPool::TxIdIter &b)
    {
        if (a->GetCountWithAncestors() != b->GetCountWithAncestors())
            return a->GetCountWithAncestors() < b->GetCountWithAncestors();
        return CTxMemPool::CompareIteratorById()(a, b);
    }
};


/** Generate a new block, without valid proof-of-work */
class BlockAssembler
{
private:
    const CChainParams &chainparams;

    // Configuration parameters for the block size
    uint64_t nBlockMaxSize = 0;
    uint64_t nBlockMinSize = 0;

    // Information on the current status of the block
    uint64_t nBlockSize = 0;
    uint64_t nBlockTx = 0;
    unsigned int nBlockSigOps = 0;
    CAmount nFees = 0;
    CTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight = 0;
    int64_t nLockTimeCutoff = 0;

    // Variables used for addPriorityTxs
    int lastFewTxs = 0;
    bool blockFinished = false;

    uint64_t maxSigOpsAllowed = 0;

public:
    BlockAssembler(const CChainParams &chainparams);
    /** Construct a new block template with coinbase to scriptPubKeyIn */
    std::unique_ptr<CBlockTemplate> CreateNewBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize = -1);

private:
    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize = -1);
    /** Add a tx to the block */
    void AddToBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPool::TxIdIter iter);

    // Methods for how to add transactions to a block.
    /** Add transactions based on tx "priority" */
    void addPriorityTxs(std::vector<const CTxMemPoolEntry *> *vtxe);

    /** Add transactions based on feerate including unconfirmed ancestors */
    void addPackageTxs(std::vector<const CTxMemPoolEntry *> *vtxe, bool fAllowDirty);

    // helper function for addPriorityTxs
    bool IsIncrementallyGood(uint64_t nExtraSize, unsigned int nExtraSigOps);
    /** Test if tx will still "fit" in the block */
    bool TestForBlock(CTxMemPool::TxIdIter iter);
    /** Test if tx still has unconfirmed parents not yet in block */
    bool isStillDependent(CTxMemPool::TxIdIter iter);

    /** Bytes to reserve for coinbase and block header */
    uint64_t reserveBlockSize(const CScript &scriptPubKeyIn, int64_t coinbaseSize = -1);

    /** Constructs a coinbase transaction */
    CTransactionRef coinbaseTx(const CScript &scriptPubKeyIn, int nHeight, CAmount nValue);

    // helper functions for addPackageTxs()
    /** Test whether a package, if added to the block, would make the block exceed the sigops limits */
    bool TestPackageSigOps(uint64_t packageSize, unsigned int packageSigOps);
    /** Test if a set of transactions are all final */
    bool TestPackageFinality(const CTxMemPool::setEntries &package);
    /** Sort the package in an order that is valid to appear in a block */
    void SortForBlock(const CTxMemPool::setEntries &package, std::vector<CTxMemPool::TxIdIter> &sortedEntries);
};

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev);

// TODO: There is no mining.h
// Create mining.h (The next two functions are in mining.cpp) or leave them here ?

/** Submit a mined block */
UniValue SubmitBlock(ConstCBlockRef pblock);
/** Make a block template to send to miners. */
// implemented in mining.cpp
UniValue mkblocktemplate(const UniValue &params,
    int64_t coinbaseSize = -1,
    CBlock *pblockOut = nullptr,
    const CScript &coinbaseScript = CScript());

// Force block template recalculation the next time a template is requested
void SignalBlockTemplateChange();

#endif // NEXA_MINER_H
