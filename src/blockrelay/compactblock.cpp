// Copyright (c) 2016-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "blockrelay/blockrelay_common.h"
#include "blockrelay/compactblock.h"
#include "blockstorage/blockstorage.h"
#include "chainparams.h"
#include "connmgr.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "dosman.h"
#include "expedited.h"
#include "hashwrapper.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "random.h"
#include "requestManager.h"
#include "streams.h"
#include "timedata.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "util.h"
#include "utiltime.h"
#include "validation/validation.h"


static bool ReconstructBlock(CNode *pfrom,
    int &missingCount,
    int &unnecessaryCount,
    std::shared_ptr<CBlockThinRelay> pblock);


uint64_t GetShortID(const uint64_t &shorttxidk0, const uint64_t &shorttxidk1, const uint256 &txhash)
{
    static_assert(CompactBlock::SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}

#define MIN_TRANSACTION_SIZE (::GetSerializeSize(CTransaction(), SER_NETWORK, PROTOCOL_VERSION))

CompactBlock::CompactBlock(const CBlock &block, const CRollingFastFilter<4 * 1024 * 1024> *inventoryKnown)
    : nSize(0), nonce(GetRand(std::numeric_limits<uint64_t>::max())), nWaitingFor(0), header(block)
{
    FillShortTxIDSelector();

    if (block.vtx.empty())
        throw std::invalid_argument(__func__ + std::string(" expects coinbase tx"));

    //< Index of a prefilled tx is its diff from last index.
    size_t prevIndex = 0;
    prefilledtxn.push_back(PrefilledTransaction{0, *block.vtx[0]});
    for (size_t i = 1; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *block.vtx[i];
        if (inventoryKnown && !inventoryKnown->contains(tx.GetId()))
        {
            prefilledtxn.push_back(PrefilledTransaction{static_cast<uint32_t>(i - (prevIndex + 1)), tx});
            prevIndex = i;
        }
        else
        {
            shorttxids.push_back(GetShortID(tx.GetId()));
        }
    }
}

void CompactBlock::FillShortTxIDSelector() const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header << nonce;
    CSHA256 hasher;
    hasher.Write((unsigned char *)&(*stream.begin()), stream.end() - stream.begin());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t CompactBlock::GetShortID(const uint256 &txhash) const
{
    return ::GetShortID(shorttxidk0, shorttxidk1, txhash);
}

void validateCompactBlock(std::shared_ptr<CompactBlock> cmpctblock)
{
    if (cmpctblock->header.IsNull() || (cmpctblock->shorttxids.empty() && cmpctblock->prefilledtxn.empty()))
        throw std::invalid_argument("empty data in compact block");

    int64_t lastprefilledindex = -1;
    for (size_t i = 0; i < cmpctblock->prefilledtxn.size(); i++)
    {
        if (cmpctblock->prefilledtxn[i].tx.IsNull())
            throw std::invalid_argument("null tx in compact block");

        // index is a uint32_t, so cant overflow here
        lastprefilledindex += static_cast<uint64_t>(cmpctblock->prefilledtxn[i].index) + 1;
        if (lastprefilledindex > std::numeric_limits<uint32_t>::max())
            throw std::invalid_argument("tx index overflows");

        if (static_cast<uint64_t>(lastprefilledindex) > cmpctblock->shorttxids.size() + i)
        {
            // If we are inserting a tx at an index greater than our full list of shorttxids
            // plus the number of prefilled txn we've inserted, then we have txn for which we
            // have neither a prefilled txn or a shorttxid!
            throw std::invalid_argument("invalid index for tx");
        }
    }
}

/**
 * Handle an incoming compactblock.  The block is fully validated, and if any
 * transactions are missing we re-request them.
 */
bool CompactBlock::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    // Deserialize compactblock and store a block to reconstruct
    CompactBlock tmp;
    vRecv >> tmp;
    auto pblock = thinrelay.SetBlockToReconstruct(pfrom, tmp.header.GetHash());
    pblock->cmpctblock = std::make_shared<CompactBlock>(std::forward<CompactBlock>(tmp));

    std::shared_ptr<CompactBlock> compactBlock = pblock->cmpctblock;

    // Message consistency checking
    if (!IsCompactBlockValid(pfrom, compactBlock))
    {
        dosMan.Misbehaving(pfrom, 100);
        thinrelay.ClearAllBlockData(pfrom, pblock->GetHash());
        return error("Received an invalid compactblock from peer %s\n", pfrom->GetLogName());
    }

    // Is there a previous block or header to connect with?
    CBlockIndex *pprev = LookupBlockIndex(compactBlock->header.hashPrevBlock);
    if (!pprev)
        return error("compact block from peer %s will not connect, unknown previous block %s", pfrom->GetLogName(),
            compactBlock->header.hashPrevBlock.ToString());

    CValidationState state;
    if (!ContextualCheckBlockHeader(Params(), compactBlock->header, state, pprev))
    {
        // compact block does not fit within our blockchain
        dosMan.Misbehaving(pfrom, 100);
        return error(
            "compact block from peer %s contextual error: %s", pfrom->GetLogName(), state.GetRejectReason().c_str());
    }

    CInv inv(MSG_BLOCK, compactBlock->header.GetHash());
    requester.UpdateBlockAvailability(pfrom->GetId(), inv.hash);
    LOG(CMPCT, "received compact block %s from peer %s of %d bytes\n", inv.hash.ToString(), pfrom->GetLogName(),
        compactBlock->GetSize());

    // Ban a node for sending unrequested compact blocks
    if (!thinrelay.IsBlockInFlight(pfrom, NetMsgType::CMPCTBLOCK, inv.hash))
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("unrequested compact block from peer %s", pfrom->GetLogName());
    }

    // Check if we've already received this block and have it on disk
    if (AlreadyHaveBlock(inv))
    {
        requester.AlreadyReceived(pfrom, inv);
        thinrelay.ClearAllBlockData(pfrom, inv.hash);

        LOG(CMPCT, "Received compactblock but returning because we already have this block %s on disk, peer=%s\n",
            inv.hash.ToString(), pfrom->GetLogName());
        return true;
    }

    return compactBlock->process(pfrom, pblock);
}


bool CompactBlock::process(CNode *pfrom, std::shared_ptr<CBlockThinRelay> pblock)
{
    *((CBlockHeader *)(pblock.get())) = header;

    // Store the salt used by this peer.
    pfrom->shorttxidk0.store(shorttxidk0);
    pfrom->shorttxidk1.store(shorttxidk1);

    DbgAssert(pblock->cmpctblock != nullptr, return false);
    DbgAssert(pblock->cmpctblock.get() == this, return false);
    std::shared_ptr<CompactBlock> cmpctBlock = pblock->cmpctblock;

    // Because the list of shorttxids is not complete (missing the prefilled transaction hashes), we need
    // to first create the full list of compactblock shortid hashes, in proper order.
    //
    // Also, create the mapMissingTx from all the supplied tx's in the compact block

    // Reconstruct the list of shortid's and in the correct order taking into account the prefilled txns.
    if (prefilledtxn.empty())
    {
        cmpctBlock->vTxHashes = shorttxids;
    }
    else
    {
        // Add hashes either from the prefilled txn vector or from the shorttxids vector.
        std::vector<uint64_t>::iterator iterShortID = shorttxids.begin();
        for (const PrefilledTransaction &prefilled : prefilledtxn)
        {
            if (prefilled.index == 0)
            {
                uint64_t shorthash = GetShortID(prefilled.tx.GetId());
                cmpctBlock->vTxHashes.push_back(shorthash);
                cmpctBlock->mapMissingTx[shorthash] = MakeTransactionRef(prefilled.tx);
                continue;
            }

            // Add shortxid's until we get to the next prefilled txn
            for (size_t i = 0; i < prefilled.index; i++)
            {
                if (iterShortID != shorttxids.end())
                {
                    cmpctBlock->vTxHashes.push_back(*iterShortID);
                    iterShortID++;
                }
                else
                    break;
            }

            // Add the prefilled txn and then get the next one
            cmpctBlock->vTxHashes.push_back(GetShortID(prefilled.tx.GetId()));
            cmpctBlock->mapMissingTx[GetShortID(prefilled.tx.GetId())] = MakeTransactionRef(prefilled.tx);
        }

        // Add the remaining shorttxids, if any.
        std::vector<uint64_t>::iterator it = cmpctBlock->vTxHashes.end();
        cmpctBlock->vTxHashes.insert(it, iterShortID, shorttxids.end());
    }

    // Create a map of all short tx hashes pointing to their full tx hash counterpart
    // We need to check all transaction sources (orphan list, mempool, and new (incoming) transactions in this block)
    int missingCount = 0;
    int unnecessaryCount = 0;
    std::map<uint64_t, uint256> mapPartialTxHash;
    std::vector<uint256> memPoolHashes;
    std::set<uint64_t> setHashesToRequest;
    unsigned int nWaitingForTxns = cmpctBlock->nWaitingFor;

    bool fMerkleRootCorrect = true;
    {
        {
            READLOCK(orphanpool.cs_orphanpool);
            for (auto &mi : orphanpool.mapOrphanTransactions)
            {
                uint64_t cheapHash = GetShortID(mi.first);
                mapPartialTxHash[cheapHash] = mi.first;
            }
        }
        mempool.queryIds(memPoolHashes);
        for (uint64_t i = 0; i < memPoolHashes.size(); i++)
        {
            uint64_t cheapHash = GetShortID(memPoolHashes[i]);
            mapPartialTxHash[cheapHash] = memPoolHashes[i];
        }
        for (auto &mi : cmpctBlock->mapMissingTx)
        {
            uint64_t cheapHash = mi.first;
            mapPartialTxHash[cheapHash] = mi.second->GetId();
        }

        // Start gathering the full tx hashes. If some are not available then add them to setHashesToRequest.
        uint256 nullhash;
        for (const uint64_t &cheapHash : pblock->cmpctblock->vTxHashes)
        {
            if (mapPartialTxHash.find(cheapHash) != mapPartialTxHash.end())
            {
                pblock->cmpctblock->vTxHashes256.push_back(mapPartialTxHash[cheapHash]);
            }
            else
            {
                pblock->cmpctblock->vTxHashes256.push_back(nullhash); // placeholder
                setHashesToRequest.insert(cheapHash);

                // If there are more hashes to request than available indices then we will not be able to
                // reconstruct the compact block so just send a full block.
                if (setHashesToRequest.size() > std::numeric_limits<uint32_t>::max())
                {
                    // Since we can't process this compactblock then clear out the data from memory
                    thinrelay.ClearAllBlockData(pfrom, pblock->GetHash());

                    thinrelay.RequestBlock(pfrom, header.GetHash());
                    return error("Too many re-requested hashes for compactblock: requesting a full block");
                }
            }
        }

        // We don't need this after here.
        mapPartialTxHash.clear();

        // Reconstruct the block if there are no hashes to re-request
        if (setHashesToRequest.empty())
        {
            bool mutated;
            uint256 merkleroot = ComputeMerkleRoot(pblock->cmpctblock->vTxHashes256, &mutated);
            if (header.hashMerkleRoot != merkleroot || mutated)
            {
                fMerkleRootCorrect = false;
            }
            else
            {
                if (!ReconstructBlock(pfrom, missingCount, unnecessaryCount, pblock))
                    return false;
            }
        }
    } // End locking orphanpool.cs, mempool.cs
    LOG(CMPCT, "Current in memory compactblock size is %ld bytes\n", pblock->nCurrentBlockSize);

    // These must be checked outside of the mempool.cs lock or deadlock may occur.
    // A merkle root mismatch here does not cause a ban because and expedited node will forward an xthin
    // without checking the merkle root, therefore we don't want to ban our expedited nodes. Just re-request
    // a full block if a mismatch occurs.
    if (!fMerkleRootCorrect)
    {
        thinrelay.ClearAllBlockData(pfrom, header.GetHash());
        thinrelay.RequestBlock(pfrom, header.GetHash());

        return error("mismatched merkle root on compactblock: rerequesting a full block, peer=%s", pfrom->GetLogName());
    }

    nWaitingForTxns = missingCount;
    LOG(CMPCT, "compactblock waiting for: %d, unnecessary: %d, total txns: %d received txns: %d\n", nWaitingForTxns,
        unnecessaryCount, pblock->vtx.size(), cmpctBlock->mapMissingTx.size());

    // If there are any missing hashes or transactions then we request them here.
    // This must be done outside of the mempool.cs lock or may deadlock.
    if (setHashesToRequest.size() > 0)
    {
        nWaitingForTxns = setHashesToRequest.size();

        // find the index in the block associated with the hash
        uint64_t nIndex = 0;
        std::vector<uint32_t> vIndexesToRequest;
        for (auto cheaphash : cmpctBlock->vTxHashes)
        {
            if (setHashesToRequest.find(cheaphash) != setHashesToRequest.end())
                vIndexesToRequest.push_back(nIndex);
            nIndex++;
        }
        CompactReRequest compactReRequest;
        compactReRequest.blockhash = header.GetHash();
        compactReRequest.indexes = vIndexesToRequest;
        pfrom->PushMessage(NetMsgType::GETBLOCKTXN, compactReRequest);

        // Update run-time statistics of compact block bandwidth savings
        compactdata.UpdateInBoundReRequestedTx(nWaitingForTxns);
        return true;
    }

    // If there are still any missing transactions then we must clear out the compactblock data
    // and re-request a full block (This should never happen because we just checked the various pools).
    if (missingCount > 0)
    {
        // Since we can't process this compactblock then clear out the data from memory
        thinrelay.ClearAllBlockData(pfrom, header.GetHash());

        thinrelay.RequestBlock(pfrom, header.GetHash());
        return error("Still missing transactions for compactblock: re-requesting a full block");
    }

    // We now have all the transactions now that are in this block
    int blockSize = pblock->GetBlockSize();
    LOG(CMPCT, "Reassembled compactblock for %s (%d bytes). Message was %d bytes, compression ratio %3.2f, peer=%s\n",
        pblock->GetHash().ToString(), blockSize, cmpctBlock->GetSize(),
        ((float)blockSize) / ((float)cmpctBlock->GetSize()), pfrom->GetLogName());

    // Update run-time statistics of compact block bandwidth savings
    compactdata.UpdateInBound(cmpctBlock->GetSize(), blockSize);
    LOG(CMPCT, "compact block stats: %s\n", compactdata.ToString());

    // Process the full block
    PV->HandleBlockMessage(pfrom, NetMsgType::CMPCTBLOCK, pblock, GetInv());

    return true;
}

bool CompactReRequest::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    CompactReRequest compactReRequest;
    vRecv >> compactReRequest;
    // Message consistency checking
    if (compactReRequest.indexes.empty() || compactReRequest.blockhash.IsNull())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("incorrectly constructed getblocktxn received.  Banning peer=%s", pfrom->GetLogName());
    }

    // We use MSG_TX here even though we refer to blockhash because we need to track
    // how many xblocktx requests we make in case of DOS
    CInv inv(MSG_TX, compactReRequest.blockhash);
    LOG(CMPCT, "received getblocktxn for %s peer=%s\n", inv.hash.ToString(), pfrom->GetLogName());

    std::vector<CTransaction> vTx;
    CBlockIndex *hdr = LookupBlockIndex(inv.hash);
    if (!hdr)
    {
        dosMan.Misbehaving(pfrom, 20);
        return error("Requested block is not available");
    }
    else
    {
        if (hdr->height() < (chainActive.Tip()->height() - (int)thinrelay.MAX_THINTYPE_BLOCKS_IN_FLIGHT))
            return error(CMPCT, "getblocktxn request too far from the tip");

        const Consensus::Params &consensusParams = Params().GetConsensus();
        ConstCBlockRef pblock = ReadBlockFromDisk(hdr, consensusParams);
        if (!pblock)
        {
            // We do not assign misbehavior for not being able to read a block from disk because we already
            // know that the block is in the block index from the step above. Secondly, a failure to read may
            // be our own issue or the remote peer's issue in requesting too early.  We can't know at this point.
            return error("Cannot load block from disk -- Block txn request possibly received before assembled");
        }

        CompactReReqResponse compactReqResponse(*pblock, compactReRequest.indexes);
        pfrom->PushMessage(NetMsgType::BLOCKTXN, compactReqResponse);
        pfrom->txsSent += compactReRequest.indexes.size();
    }

    return true;
}

bool CompactReReqResponse::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    std::string strCommand = NetMsgType::BLOCKTXN;
    size_t msgSize = vRecv.size();
    CompactReReqResponse compactReReqResponse;
    vRecv >> compactReReqResponse;

    // Message consistency checking
    CInv inv(MSG_CMPCT_BLOCK, compactReReqResponse.blockhash);
    if (compactReReqResponse.txn.empty() || compactReReqResponse.blockhash.IsNull())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error(
            "incorrectly constructed compactReReqResponse or inconsistent compactblock data received.  Banning peer=%s",
            pfrom->GetLogName());
    }
    LOG(CMPCT, "received compactReReqResponse for %s peer=%s\n", inv.hash.ToString(), pfrom->GetLogName());
    {
        // Do not process unrequested xblocktx unless from an expedited node.
        if (!thinrelay.IsBlockInFlight(pfrom, NetMsgType::CMPCTBLOCK, inv.hash) && !connmgr->IsExpeditedUpstream(pfrom))
        {
            dosMan.Misbehaving(pfrom, 10);
            return error("Received compactReReqResponse %s from peer %s but was unrequested", inv.hash.ToString(),
                pfrom->GetLogName());
        }
    }

    auto pblock = thinrelay.GetBlockToReconstruct(pfrom, compactReReqResponse.blockhash);
    if (pblock == nullptr)
        return error("No block available to reconstruct for blocktxn");
    std::shared_ptr<CompactBlock> cmpctBlock = pblock->cmpctblock;

    // Check if we've already received this block and have it on disk
    if (AlreadyHaveBlock(inv))
    {
        requester.AlreadyReceived(pfrom, inv);
        thinrelay.ClearAllBlockData(pfrom, inv.hash);

        LOG(CMPCT,
            "Received compactReReqResponse but returning because we already have this block %s on disk, peer=%s\n",
            inv.hash.ToString(), pfrom->GetLogName());
        return true;
    }

    // Create the mapMissingTx from all the supplied tx's in the compactblock
    for (const CTransaction &tx : compactReReqResponse.txn)
        cmpctBlock->mapMissingTx[GetShortID(pfrom->shorttxidk0.load(), pfrom->shorttxidk1.load(), tx.GetId())] =
            MakeTransactionRef(tx);

    // Get the full hashes from the compactReReqResponse and add them to the compactBlockHashes vector.  These should
    // be all the missing or null hashes that we re-requested.
    DbgAssert(cmpctBlock->vTxHashes256.size() == cmpctBlock->vTxHashes.size(), return false);
    int count = 0;
    for (size_t i = 0; i < cmpctBlock->vTxHashes256.size(); i++)
    {
        if (cmpctBlock->vTxHashes256[i].IsNull())
        {
            std::map<uint64_t, CTransactionRef>::iterator val = cmpctBlock->mapMissingTx.find(cmpctBlock->vTxHashes[i]);
            if (val != cmpctBlock->mapMissingTx.end())
            {
                cmpctBlock->vTxHashes256[i] = val->second->GetId();
            }
            count++;
        }
    }
    LOG(CMPCT, "Got %d Re-requested txs, needed %d of them from peer=%s\n", compactReReqResponse.txn.size(), count,
        pfrom->GetLogName());


    // At this point we should have all the full hashes in the block. Check that the merkle
    // root in the block header matches the merkleroot calculated from the hashes provided.
    bool mutated;

    uint256 merkleroot = ComputeMerkleRoot(cmpctBlock->vTxHashes256, &mutated);
    if (pblock->hashMerkleRoot != merkleroot || mutated)
    {
        thinrelay.ClearAllBlockData(pfrom, inv.hash);
        return error("Merkle root for %s does not match computed merkle root, peer=%s", inv.hash.ToString(),
            pfrom->GetLogName());
    }
    LOG(CMPCT, "Merkle Root check passed for %s peer=%s\n", inv.hash.ToString(), pfrom->GetLogName());

    int missingCount = 0;
    int unnecessaryCount = 0;
    // Look for each transaction in our various pools and buffers.
    // With compactblocks the vTxHashes contains only the first 6 bytes of the tx hash.
    {
        if (!ReconstructBlock(pfrom, missingCount, unnecessaryCount, pblock))
            return false;
    }

    // If we're still missing transactions then bail out and just request the full block. This should never
    // happen unless we're under some kind of attack or somehow we lost transactions out of our memory pool
    // while we were retreiving missing transactions.
    if (missingCount > 0)
    {
        // Since we can't process this compactblock then clear out the data from memory
        thinrelay.ClearAllBlockData(pfrom, inv.hash);

        thinrelay.RequestBlock(pfrom, inv.hash);
        return error("Still missing transactions after reconstructing block, peer=%s: re-requesting a full block",
            pfrom->GetLogName());
    }
    else
    {
        // We have all the transactions now that are in this block: try to reassemble and process.
        CInv inv2(CInv(MSG_BLOCK, compactReReqResponse.blockhash));

        // for compression statistics, we have to add up the size of compactblock and the re-requested Txns.
        uint64_t nSizeCompactBlockTx = msgSize;
        uint64_t nBlockSize = pblock->GetBlockSize();
        uint64_t nCmpctBlkSize = cmpctBlock->GetSize();
        LOG(CMPCT,
            "Reassembled compactReReqResponse for %s (%d bytes). Message was %d bytes (compactblock) and %d bytes "
            "(re-requested tx), compression ratio %3.2f, peer=%s\n",
            pblock->GetHash().ToString(), nBlockSize, nCmpctBlkSize, nSizeCompactBlockTx,
            ((float)nBlockSize) / ((float)nCmpctBlkSize + (float)nSizeCompactBlockTx), pfrom->GetLogName());

        // Update run-time statistics of compactblock bandwidth savings.
        // We add the original compactblock size with the size of transactions that were re-requested.
        // This is NOT double counting since we never accounted for the original compactblock due to the re-request.
        compactdata.UpdateInBound(nSizeCompactBlockTx + nCmpctBlkSize, nBlockSize);
        LOG(CMPCT, "compactblock stats: %s\n", compactdata.ToString());

        PV->HandleBlockMessage(pfrom, strCommand, pblock, inv2);
    }

    return true;
}

static bool ReconstructBlock(CNode *pfrom,
    int &missingCount,
    int &unnecessaryCount,
    std::shared_ptr<CBlockThinRelay> pblock)
{
    // We must have all the full tx hashes by this point.  We first check for any duplicate
    // transaction ids.  This is a possible attack vector and has been used in the past.
    {
        std::set<uint256> setHashes(pblock->cmpctblock->vTxHashes256.begin(), pblock->cmpctblock->vTxHashes256.end());
        if (setHashes.size() != pblock->cmpctblock->vTxHashes256.size())
        {
            thinrelay.ClearAllBlockData(pfrom, pblock->GetHash());
            return error("Duplicate transaction ids, peer=%s", pfrom->GetLogName());
        }
    }

    // Add the header size to the current size being tracked
    thinrelay.AddBlockBytes(::GetSerializeSize(pblock->GetBlockHeader(), SER_NETWORK, PROTOCOL_VERSION), pblock);

    // Look for each transaction in our various pools and buffers.
    // With compactblocks the vTxHashes contains only the first 6 bytes of the tx hash.
    for (const uint256 &hash : pblock->cmpctblock->vTxHashes256)
    {
        // Replace the truncated hash with the full hash value if it exists
        CTransactionRef ptx = nullptr;
        if (!hash.IsNull())
        {
            // Check the commit queue first. If we check the mempool first and it's not in there then when we release
            // the lock on the mempool it may get transfered from the commitQ to the mempool before we have time to
            // grab the lock on the commitQ and we'll think we don't have the transaction.
            // the mempool.
            bool inMemPool = false;
            bool inCommitQ = false;
            ptx = CommitQGet(hash);
            if (ptx)
            {
                inCommitQ = true;
            }
            else
            {
                // if it's not in the mempool then check the commitQ
                ptx = mempool.get(hash);
                if (ptx)
                    inMemPool = true;
            }

            // Continue checking if we still don't have the txn
            bool inMissingTx = false;
            bool inOrphanCache = false;
            if (!ptx)
            {
                uint64_t nShortId = GetShortID(pfrom->shorttxidk0.load(), pfrom->shorttxidk1.load(), hash);
                std::map<uint64_t, CTransactionRef>::iterator iter1 = pblock->cmpctblock->mapMissingTx.find(nShortId);
                if (iter1 != pblock->cmpctblock->mapMissingTx.end())
                {
                    inMissingTx = true;
                    ptx = iter1->second;
                }
                else
                {
                    READLOCK(orphanpool.cs_orphanpool);
                    std::map<uint256, CTxOrphanPool::COrphanTx>::iterator iter2 =
                        orphanpool.mapOrphanTransactions.find(hash);
                    if (iter2 != orphanpool.mapOrphanTransactions.end())
                    {
                        inOrphanCache = true;
                        ptx = iter2->second.ptx;
                    }
                }

                // XVal: these transactions still need to be verified since they were not in the mempool
                // or CommitQ.
                if (ptx)
                    pblock->setUnVerifiedTxns.insert(hash);
            }
            if (((inMemPool || inCommitQ) && inMissingTx) || (inOrphanCache && inMissingTx))
                unnecessaryCount++;
        }
        if (!ptx)
            missingCount++;


        // In order to prevent a memory exhaustion attack we track transaction bytes used to recreate the block
        // in order to see if we've exceeded any limits and if so clear out data and return.
        if (ptx)
            thinrelay.AddBlockBytes(ptx->GetTxSize(), pblock);
        if (pblock->nCurrentBlockSize > thinrelay.GetMaxAllowedBlockSize())
        {
            uint64_t nBlockBytes = pblock->nCurrentBlockSize;
            thinrelay.ClearAllBlockData(pfrom, pblock->GetHash());
            pfrom->fDisconnect = true;
            return error("Reconstructed block %s (size:%llu) has caused max memory limit %llu bytes to be "
                         "exceeded, peer=%s",
                pblock->GetHash().ToString(), nBlockBytes, thinrelay.GetMaxAllowedBlockSize(), pfrom->GetLogName());
        }

        // Add this transaction. If the tx is null we still add it as a placeholder to keep the correct
        // ordering.
        pblock->vtx.emplace_back(ptx);
    }
    // Now that we've rebuilt the block successfully we can set the XVal flag which is used in
    // ConnectBlock() to determine which if any inputs we can skip the checking of inputs.
    pblock->fXVal = DEFAULT_XVAL_ENABLED;

    return true;
}


template <class T>
void CCompactBlockData::expireStats(std::map<int64_t, T> &statsMap)
{
    AssertLockHeld(cs_compactblockstats);
    // Delete any entries that are more than 24 hours old
    int64_t nTimeCutoff = getTimeForStats() - 60 * 60 * 24 * 1000;

    typename std::map<int64_t, T>::iterator iter = statsMap.begin();
    while (iter != statsMap.end())
    {
        // increment to avoid iterator becoming invalid when erasing below
        typename std::map<int64_t, T>::iterator mi = iter++;

        if (mi->first < nTimeCutoff)
            statsMap.erase(mi);
    }
}

template <class T>
void CCompactBlockData::updateStats(std::map<int64_t, T> &statsMap, T value)
{
    AssertLockHeld(cs_compactblockstats);
    statsMap[getTimeForStats()] = value;
    expireStats(statsMap);
}


//  Calculate average of values in map. Return 0 for no entries.
// Expires values before calculation.
double CCompactBlockData::average(std::map<int64_t, uint64_t> &map)
{
    AssertLockHeld(cs_compactblockstats);

    expireStats(map);

    if (map.size() == 0)
        return 0.0;

    uint64_t accum = 0U;
    for (const std::pair<const int64_t, uint64_t> &ref : map)
    {
        // avoid wraparounds
        accum = std::max(accum, accum + ref.second);
    }
    return (double)accum / map.size();
}

double CCompactBlockData::computeTotalBandwidthSavingsInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats)
{
    AssertLockHeld(cs_compactblockstats);
    if (nOriginalSize() >= nCompactSize())
        return (double)0;

    return double(nOriginalSize() - nCompactSize());
}

double CCompactBlockData::compute24hAverageCompressionInternal(
    std::map<int64_t, std::pair<uint64_t, uint64_t> > &mapCompactBlocks) EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats)
{
    AssertLockHeld(cs_compactblockstats);

    expireStats(mapCompactBlocks);

    double nCompressionRate = 0;
    uint64_t nCompactSizeTotal = 0;
    uint64_t nOriginalSizeTotal = 0;
    for (const auto &mi : mapCompactBlocks)
    {
        nCompactSizeTotal += mi.second.first;
        nOriginalSizeTotal += mi.second.second;
    }

    if (nOriginalSizeTotal > 0)
        nCompressionRate = 100 - (100 * (double)(nCompactSizeTotal) / nOriginalSizeTotal);

    if (nCompressionRate > 0)
        return nCompressionRate;
    else
        return (double)0;
}

double CCompactBlockData::compute24hInboundRerequestTxPercentInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats)
{
    AssertLockHeld(cs_compactblockstats);

    expireStats(mapCompactBlocksInBoundReRequestedTx);
    expireStats(mapCompactBlocksInBound);

    double nReRequestRate = 0;
    uint64_t nTotalReRequests = 0;
    uint64_t nTotalReRequestedTxs = 0;
    for (const auto &mi : mapCompactBlocksInBoundReRequestedTx)
    {
        nTotalReRequests += 1;
        nTotalReRequestedTxs += mi.second;
    }

    if (mapCompactBlocksInBound.size() > 0)
        nReRequestRate = 100 * (double)nTotalReRequests / mapCompactBlocksInBound.size();

    return nReRequestRate;
}

void CCompactBlockData::UpdateInBound(uint64_t nCompactBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_compactblockstats);
    // Update InBound compactblock tracking information
    nOriginalSize += nOriginalBlockSize;
    nCompactSize += nCompactBlockSize;
    nInBoundBlocks += 1;
    updateStats(mapCompactBlocksInBound, std::pair<uint64_t, uint64_t>(nCompactBlockSize, nOriginalBlockSize));
}

void CCompactBlockData::UpdateOutBound(uint64_t nCompactBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_compactblockstats);
    nOriginalSize += nOriginalBlockSize;
    nCompactSize += nCompactBlockSize;
    nOutBoundBlocks += 1;
    updateStats(mapCompactBlocksOutBound, std::pair<uint64_t, uint64_t>(nCompactBlockSize, nOriginalBlockSize));
}

void CCompactBlockData::UpdateResponseTime(double nResponseTime)
{
    LOCK(cs_compactblockstats);

    // only update stats if IBD is complete
    if (IsChainNearlySyncd() && IsCompactBlocksEnabled())
    {
        updateStats(mapCompactBlockResponseTime, nResponseTime);
    }
}

void CCompactBlockData::UpdateValidationTime(double nValidationTime)
{
    LOCK(cs_compactblockstats);

    // only update stats if IBD is complete
    if (IsChainNearlySyncd() && IsCompactBlocksEnabled())
    {
        updateStats(mapCompactBlockValidationTime, nValidationTime);
    }
}

void CCompactBlockData::UpdateInBoundReRequestedTx(int nReRequestedTx)
{
    LOCK(cs_compactblockstats);

    // Update InBound compactblock tracking information
    updateStats(mapCompactBlocksInBoundReRequestedTx, nReRequestedTx);
}

void CCompactBlockData::UpdateMempoolLimiterBytesSaved(unsigned int nBytesSaved)
{
    LOCK(cs_compactblockstats);
    nMempoolLimiterBytesSaved += nBytesSaved;
}

void CCompactBlockData::UpdateCompactBlock(uint64_t nCompactBlockSize)
{
    LOCK(cs_compactblockstats);
    nTotalCompactBlockBytes += nCompactBlockSize;
    updateStats(mapCompactBlock, nCompactBlockSize);
}

void CCompactBlockData::UpdateFullTx(uint64_t nFullTxSize)
{
    LOCK(cs_compactblockstats);
    nTotalCompactBlockBytes += nFullTxSize;
    updateStats(mapFullTx, nFullTxSize);
}

std::string CCompactBlockData::ToString()
{
    LOCK(cs_compactblockstats);
    double size = computeTotalBandwidthSavingsInternal();
    std::ostringstream ss;
    ss << nInBoundBlocks() << " inbound and " << nOutBoundBlocks() << " outbound compactblocks have saved "
       << formatInfoUnit(size) << " of bandwidth";
    return ss.str();
}

// Calculate the percentage compression over the last 24 hours for inbound blocks
std::string CCompactBlockData::InBoundPercentToString()
{
    LOCK(cs_compactblockstats);

    double nCompressionRate = compute24hAverageCompressionInternal(mapCompactBlocksInBound);

    // NOTE: Potential gotcha, compute24hAverageCompressionInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapCompactBlocksInBound
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapCompactBlocksInBound.size()
       << " Inbound  compactblocks (last 24hrs): " << nCompressionRate << "%";
    return ss.str();
}

// Calculate the percentage compression over the last 24 hours for outbound blocks
std::string CCompactBlockData::OutBoundPercentToString()
{
    LOCK(cs_compactblockstats);

    double nCompressionRate = compute24hAverageCompressionInternal(mapCompactBlocksOutBound);

    // NOTE: Potential gotcha, compute24hAverageCompressionInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapCompactBlocksOutBound
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapCompactBlocksOutBound.size()
       << " Outbound compactblocks (last 24hrs): " << nCompressionRate << "%";
    return ss.str();
}

// Calculate the average response time over the last 24 hours
std::string CCompactBlockData::ResponseTimeToString()
{
    LOCK(cs_compactblockstats);

    expireStats(mapCompactBlockResponseTime);

    std::vector<double> vResponseTime;

    double nResponseTimeAverage = 0;
    double nPercentile = 0;
    double nTotalResponseTime = 0;
    double nTotalEntries = 0;
    for (const auto &mi : mapCompactBlockResponseTime)
    {
        nTotalEntries += 1;
        nTotalResponseTime += mi.second;
        vResponseTime.push_back(mi.second);
    }

    if (nTotalEntries > 0)
    {
        nResponseTimeAverage = (double)nTotalResponseTime / nTotalEntries;

        // Calculate the 95th percentile
        uint64_t nPercentileElement = static_cast<int>((nTotalEntries * 0.95) + 0.5) - 1;
        sort(vResponseTime.begin(), vResponseTime.end());
        nPercentile = vResponseTime[nPercentileElement];
    }

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    ss << "Response time   (last 24hrs) AVG:" << nResponseTimeAverage << ", 95th pcntl:" << nPercentile;
    return ss.str();
}

// Calculate the average validation time over the last 24 hours
std::string CCompactBlockData::ValidationTimeToString()
{
    LOCK(cs_compactblockstats);

    expireStats(mapCompactBlockValidationTime);

    std::vector<double> vValidationTime;

    double nValidationTimeAverage = 0;
    double nPercentile = 0;
    double nTotalValidationTime = 0;
    double nTotalEntries = 0;
    for (const auto &mi : mapCompactBlockValidationTime)
    {
        nTotalEntries += 1;
        nTotalValidationTime += mi.second;
        vValidationTime.push_back(mi.second);
    }

    if (nTotalEntries > 0)
    {
        nValidationTimeAverage = (double)nTotalValidationTime / nTotalEntries;

        // Calculate the 95th percentile
        uint64_t nPercentileElement = static_cast<int>((nTotalEntries * 0.95) + 0.5) - 1;
        sort(vValidationTime.begin(), vValidationTime.end());
        nPercentile = vValidationTime[nPercentileElement];
    }

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    ss << "Validation time (last 24hrs) AVG:" << nValidationTimeAverage << ", 95th pcntl:" << nPercentile;
    return ss.str();
}

// Calculate the transaction re-request ratio and counter over the last 24 hours
std::string CCompactBlockData::ReRequestedTxToString()
{
    LOCK(cs_compactblockstats);

    double nReRequestRate = compute24hInboundRerequestTxPercentInternal();

    // NOTE: Potential gotcha, compute24hInboundRerequestTxPercentInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapCompactBlocksInBoundReRequestedTx
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Tx re-request rate (last 24hrs): " << nReRequestRate
       << "% Total re-requests:" << mapCompactBlocksInBoundReRequestedTx.size();
    return ss.str();
}

std::string CCompactBlockData::MempoolLimiterBytesSavedToString()
{
    LOCK(cs_compactblockstats);
    double size = (double)nMempoolLimiterBytesSaved();
    std::ostringstream ss;
    ss << "CompactBlock mempool limiting has saved " << formatInfoUnit(size) << " of bandwidth";
    return ss.str();
}

// Calculate the average compact block size
std::string CCompactBlockData::CompactBlockToString()
{
    LOCK(cs_compactblockstats);
    double avgCompactBlockSize = average(mapCompactBlock);
    std::ostringstream ss;
    ss << "CompactBlock size (last 24hrs) AVG: " << formatInfoUnit(avgCompactBlockSize);
    return ss.str();
}

// Calculate the average size of all full txs sent with block
std::string CCompactBlockData::FullTxToString()
{
    LOCK(cs_compactblockstats);
    double avgFullTxSize = average(mapFullTx);
    std::ostringstream ss;
    ss << "compactblock full transactions size (last 24hrs) AVG: " << formatInfoUnit(avgFullTxSize);
    return ss.str();
}

void CCompactBlockData::ClearCompactBlockStats()
{
    LOCK(cs_compactblockstats);

    nOriginalSize.Clear();
    nCompactSize.Clear();
    nInBoundBlocks.Clear();
    nOutBoundBlocks.Clear();
    nMempoolLimiterBytesSaved.Clear();
    nTotalCompactBlockBytes.Clear();
    nTotalFullTxBytes.Clear();

    mapCompactBlocksInBound.clear();
    mapCompactBlocksOutBound.clear();
    mapCompactBlockResponseTime.clear();
    mapCompactBlockValidationTime.clear();
    mapCompactBlocksInBoundReRequestedTx.clear();
    mapCompactBlock.clear();
    mapFullTx.clear();
}

void CCompactBlockData::FillCompactBlockQuickStats(CompactBlockQuickStats &stats)
{
    if (!IsCompactBlocksEnabled())
        return;

    LOCK(cs_compactblockstats);

    stats.nTotalInbound = nInBoundBlocks();
    stats.nTotalOutbound = nOutBoundBlocks();
    stats.nTotalBandwidthSavings = computeTotalBandwidthSavingsInternal();

    // NOTE: The following calls rely on the side-effect of the compute*Internal
    //       calls also calling expireStats on the associated statistics maps
    //       This is why we set the % value first, then the count second for compression values
    stats.fLast24hInboundCompression = compute24hAverageCompressionInternal(mapCompactBlocksInBound);
    stats.nLast24hInbound = mapCompactBlocksInBound.size();
    stats.fLast24hOutboundCompression = compute24hAverageCompressionInternal(mapCompactBlocksOutBound);
    stats.nLast24hOutbound = mapCompactBlocksOutBound.size();
    stats.fLast24hRerequestTxPercent = compute24hInboundRerequestTxPercentInternal();
    stats.nLast24hRerequestTx = mapCompactBlocksInBoundReRequestedTx.size();
}

bool IsCompactBlocksEnabled() { return GetBoolArg("-use-compactblocks", true); }
void SendCompactBlock(ConstCBlockRef pblock, CNode *pfrom, const CInv &inv)
{
    if (inv.type == MSG_CMPCT_BLOCK)
    {
        CompactBlock compactBlock;
        {
            LOCK(pfrom->cs_inventory);
            compactBlock = CompactBlock(*pblock, &pfrom->filterInventoryKnown);
        }
        uint64_t nSizeBlock = pblock->GetBlockSize();

        // Send a compact block
        if (compactBlock.GetSize() < nSizeBlock)
        {
            compactdata.UpdateOutBound(compactBlock.GetSize(), nSizeBlock);
            pfrom->PushMessage(NetMsgType::CMPCTBLOCK, compactBlock);
            LOG(CMPCT, "Sent compact block - compactblock size: %d vs block size: %d peer: %s\n",
                compactBlock.GetSize(), nSizeBlock, pfrom->GetLogName());

            compactdata.UpdateCompactBlock(compactBlock.GetSize());
            compactdata.UpdateFullTx(::GetSerializeSize(compactBlock.prefilledtxn, SER_NETWORK, PROTOCOL_VERSION));
            pfrom->blocksSent += 1;
        }
        else // send full block
        {
            pfrom->PushMessage(NetMsgType::BLOCK, *pblock);
            LOG(CMPCT, "Sent regular block instead - compactblock size: %d vs block size: %d , peer: %s\n",
                compactBlock.GetSize(), nSizeBlock, pfrom->GetLogName());
        }
    }
}

bool IsCompactBlockValid(CNode *pfrom, std::shared_ptr<CompactBlock> compactBlock)
{
    validateCompactBlock(compactBlock);

    // Check that we havn't exceeded the max allowable block size that would be reconstructed from this
    // set of hashes
    uint64_t nTxnsInBlock = compactBlock->shorttxids.size() + compactBlock->prefilledtxn.size();
    if (nTxnsInBlock > (thinrelay.GetMaxAllowedBlockSize() / MIN_TX_SIZE))
        return error("Number of hashes in compactblock would reconstruct a block greather than the block size limit\n");

    // check block header
    CValidationState state;
    if (!CheckBlockHeader(Params().GetConsensus(), compactBlock->header, state, true))
    {
        return error("Received invalid header for compactblock %s from peer %s",
            compactBlock->header.GetHash().ToString(), pfrom->GetLogName());
    }
    if (state.Invalid())
    {
        return error("Received invalid header for compactblock %s from peer %s",
            compactBlock->header.GetHash().ToString(), pfrom->GetLogName());
    }

    return true;
}
