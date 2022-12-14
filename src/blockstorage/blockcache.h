// Copyright (c) 2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKDB_BLOCKCACHE_H
#define BLOCKDB_BLOCKCACHE_H

#include "main.h"
#include "primitives/block.h"
#include "sync.h"

#include <unordered_map>


class CBlockCache
{
private:
    enum BlockType
    {
        CBLOCK,
        CTAILSTORMBLOCK,
    };

    struct CCacheEntry
    {
        int64_t nEntryTime;
        uint64_t nHeight;
        ConstCBlockRef pblock;
    };

    mutable CSharedCriticalSection cs_blockcache;
    /** an in memory cache of blocks */
    std::unordered_map<uint256, CCacheEntry, BlockHasher> cache GUARDED_BY(cs_blockcache);

    /** Current in memory byte size of the block cache */
    int64_t nBytesCache GUARDED_BY(cs_blockcache) = 0;

    /** Maximum allowed byte size of the cache */
    int64_t nMaxSizeCache GUARDED_BY(cs_blockcache) = 0;

    /** how much to increment or decrement the cache size at one time */
    const uint64_t nIncrement = 1;

    int64_t nMaxTxpool;

public:
    CBlockCache()
    {
        // set to 1- for until init is called
        nMaxTxpool = -1;
    };

    void Init()
    {
        if (nMaxTxpool < 0)
        {
            nMaxTxpool = maxTxPool.Value() * ONE_MEGABYTE;
        }
    }

    /** Add a block to the block cache */
    void AddBlock(const ConstCBlockRef pblock, uint64_t nHeight);

    /** Find and return a block from the block cache */
    ConstCBlockRef GetBlock(uint256 hash) const;

    /** Remove a block from the block cache */
    void EraseBlock(const uint256 &hash);


private:
    /** Adjust the block download window */
    void _CalculateDownloadWindow(const ConstCBlockRef pblock);

    /** Trim the cache when necessary */
    void _TrimCache();
};
extern CBlockCache blockcache;

#endif // BLOCKDB_BLOCKCACHE_H
