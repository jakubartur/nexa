// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKDB_BLOCKSTORAGE_H
#define BLOCKDB_BLOCKSTORAGE_H

#include "blockleveldb.h"
#include "main.h"
#include "undo.h"

enum FlushStateMode
{
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};


static const BlockDBMode DEFAULT_BLOCK_DB_MODE = SEQUENTIAL_BLOCK_FILES;
extern BlockDBMode BLOCK_DB_MODE;
extern CDatabaseAbstract *pblockdb;

/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const uint64_t DEFAULT_BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const uint64_t DEFAULT_UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
extern uint64_t blockfile_chunk_size;
extern uint64_t undofile_chunk_size;

void InitializeBlockStorage(const int64_t &_nBlockTreeDBCache,
    const int64_t &_nBlockDBCache,
    const int64_t &_nBlockUndoDBCache);

/** Catch leveldb up with sequential block files */
void SyncStorage(const CChainParams &chainparams);

/** Functions for disk access for blocks */
ConstCBlockRef ReadBlockFromDisk(const CBlockIndex *pindex, const Consensus::Params &consensusParams);
bool WriteBlockToDisk(const ConstCBlockRef pblock,
    CDiskBlockPos &pos,
    const CMessageHeader::MessageStartChars &messageStart,
    const int *pHeight = nullptr);

bool WriteUndoToDisk(const CBlockUndo &blockundo,
    CDiskBlockPos &pos,
    const CBlockIndex *pindex,
    const CMessageHeader::MessageStartChars &messageStart);
bool ReadUndoFromDisk(CBlockUndo &blockundo, const CDiskBlockPos &pos, const CBlockIndex *pindex);

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined
 * target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet,
 * 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
void FindFilesToPrune(std::set<int> &setFilesToPrune, uint64_t nPruneAfterHeight);

/** Flush all state, indexes and buffers to disk. */
bool FlushStateToDiskInternal(CValidationState &state,
    FlushStateMode mode = FLUSH_STATE_ALWAYS,
    bool fFlushForPrune = false,
    std::set<int> setFilesToPrune = {});
bool FlushStateToDisk(CValidationState &state, FlushStateMode mode);
void FlushStateToDisk();
/** Prune block files and flush state to disk. */
void PruneAndFlush();

bool FindBlockPos(CValidationState &state,
    CDiskBlockPos &pos,
    uint64_t nAddSize,
    unsigned int nHeight,
    uint64_t nTime,
    bool fKnown = false);

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, uint64_t nAddSize);


extern BlockDBMode BLOCK_DB_MODE;

#endif // BLOCKDB_BLOCKSTORAGE_H
