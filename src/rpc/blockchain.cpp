// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/blockchain.h"

#include "amount.h"
#include "blockstorage/blockstorage.h"
#include "blockstorage/sequential_files.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "coins.h"
#include "consensus/grouptokens.h"
#include "consensus/validation.h"
#include "dstencode.h"
#include "hashwrapper.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "streams.h"
#include "sync.h"
#include "tweak.h"
#include "txadmission.h"
#include "txdb.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "undo.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation/validation.h"
#include "validation/verifydb.h"
#include "wallet/grouptokenwallet.h"

#include <stdint.h>

#include <univalue.h>

#include <boost/algorithm/string.hpp>
#include <boost/thread/thread.hpp> // boost::thread::interrupt
#include <mutex>

extern CTweak<int> maxReorgDepth;

// In case of operator error, limit the rollback of a chain to 100 blocks
static uint32_t nDefaultRollbackLimit = 100;

using namespace std;

void ScriptPubKeyToJSON(const CScript &scriptPubKey, UniValue &out, bool fIncludeHex);

double GetDifficulty(const CBlockIndex *blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == nullptr)
    {
        if (chainActive.Tip() == nullptr)
            return 1.0;
        else
            blockindex = chainActive.Tip();
    }

    int nShift = (blockindex->tgtBits() >> 24) & 0xff;

    double dDiff = (double)0x0000ffff / (double)(blockindex->tgtBits() & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


UniValue blockheaderToJSON(const CBlockIndex *blockindex, UniValue &result)
{
    if (!blockindex)
        throw std::runtime_error("No entry found in the block index");

    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->height() + 1;
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", (uint64_t)blockindex->height());
    result.pushKV("size", blockindex->header.size);
    result.pushKV("txcount", blockindex->header.txCount);
    result.pushKV("feePoolAmt", blockindex->header.feePoolAmt);
    result.pushKV("merkleroot", blockindex->hashMerkleRoot().GetHex());
    result.pushKV("time", (int64_t)blockindex->time());
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("nonce", HexStr(blockindex->nonce()));
    result.pushKV("bits", strprintf("%08x", blockindex->tgtBits()));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->chainWork().GetHex());
    result.pushKV("utxoCommitment", HexStr(blockindex->header.utxoCommitment));
    result.pushKV("minerData", HexStr(blockindex->header.minerData));

    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    result.pushKV("ancestorhash", blockindex->header.hashAncestor.GetHex());

    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockheaderToJSON(const CBlockIndex *blockindex)
{
    UniValue result(UniValue::VOBJ);
    blockheaderToJSON(blockindex, result);
    return result;
}

UniValue blockToJSON(const CBlock &block,
    const CBlockIndex *blockindex,
    bool txDetails /* = false */,
    bool listTxns /* = true */)
{
    UniValue result(UniValue::VOBJ);
    blockheaderToJSON(blockindex, result);

    UniValue txs(UniValue::VARR);
    UniValue txidems(UniValue::VARR);
    if (listTxns)
    {
        int64_t txTime = -1; // Don't display the time in the tx because its in the block data.
        for (const auto &tx : block.vtx)
        {
            if (txDetails)
            {
                UniValue objTx(UniValue::VOBJ);
                TxToJSON(*tx, txTime, uint256(), objTx);
                txs.push_back(objTx);
            }
            else
            {
                txs.push_back(tx->GetId().GetHex());
                txidems.push_back(tx->GetIdem().GetHex());
            }
        }
        if (txDetails) // Details contains both id an idem
        {
            result.pushKV("tx", txs);
        }
        else
        {
            result.pushKV("txid", txs);
            result.pushKV("txidem", txidems);
        }
    }
    else
    {
        result.pushKV("txcount", (uint64_t)block.vtx.size());
    }
    return result;
}

UniValue getblockcount(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error("getblockcount\n"
                            "\nReturns the number of blocks in the longest block chain.\n"
                            "\nResult:\n"
                            "n    (numeric) The current block count\n"
                            "\nExamples:\n" +
                            HelpExampleCli("getblockcount", "") + HelpExampleRpc("getblockcount", ""));
    return chainActive.Height();
}

UniValue getbestblockhash(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error("getbestblockhash\n"
                            "\nReturns the hash of the best (tip) block in the longest block chain.\n"
                            "\nResult\n"
                            "\"hex\"      (string) the block hash hex encoded\n"
                            "\nExamples\n" +
                            HelpExampleCli("getbestblockhash", "") + HelpExampleRpc("getbestblockhash", ""));

    return chainActive.Tip()->GetBlockHash().GetHex();
}

UniValue getfinalizedblockhash(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error("getfinalizedblockhash\n"
                                 "\nReturns the hash of the currently finalized block\n"
                                 "\nResult:\n"
                                 "\"hex\"      (string) the block hash hex encoded\n");
    }

    if (maxReorgDepth.Value() < 0)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Block finalization is not enabled");

    LOCK(cs_main);
    const CBlockIndex *blockIndexFinalized = GetFinalizedBlock();
    if (blockIndexFinalized)
    {
        return blockIndexFinalized->GetBlockHash().GetHex();
    }
    return UniValue(UniValue::VSTR);
}

UniValue getdifficulty(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n" +
            HelpExampleCli("getdifficulty", "") + HelpExampleRpc("getdifficulty", ""));

    return GetDifficulty();
}

std::string EntryDescriptionString()
{
    return "    \"size\" : n,             (numeric) transaction size in bytes\n"
           "    \"fee\" : n,              (numeric) transaction fee in " +
           CURRENCY_UNIT +
           "\n"
           "    \"modifiedfee\" : n,      (numeric) transaction fee with fee deltas used for mining priority\n"
           "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 "
           "GMT\n"
           "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
           "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
           "    \"currentpriority\" : n,  (numeric) transaction priority now (including manual adjustments)\n"
           "    \"ancestorcount\" : n,    (numeric) number of in-txpool ancestor transactions (including this one)\n"
           "    \"ancestorsize\" : n,     (numeric) size of in-txpool ancestors (including this one)\n"
           "    \"ancestorfees\" : n,     (numeric) modified fees (see above) of in-txpool ancestors (including this "
           "one)\n"
           "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
           "        \"transactionid\",    (string) parent transaction idem\n"
           "       ... ]\n"
           "    \"spentby\" : [           (array) unconfirmed transactions spending outputs from this transaction\n"
           "        \"transactionidem\",    (string) child transaction idem\n"
           "       ... ]\n";
}

void entryToJSON(UniValue &info, const CTxMemPoolEntry &e)
{
    AssertLockHeld(mempool.cs_txmempool);

    info.pushKV("size", (int)e.GetTxSize());
    info.pushKV("fee", ValueFromAmount(e.GetFee()));
    info.pushKV("modifiedfee", ValueFromAmount(e.GetModifiedFee()));
    info.pushKV("time", e.GetTime());
    info.pushKV("height", (int)e.GetHeight());
    info.pushKV("doublespent", (e.dsproof == 1 ? true : false));
    info.pushKV("startingpriority", e.GetPriority(e.GetHeight()));

    double priority = e.GetPriority(chainActive.Height());
    CAmount dummy = 0;
    // Adjust the priority by any CLI changes
    mempool._ApplyDeltas(e.GetTx().GetId(), priority, dummy);
    mempool._ApplyDeltas(e.GetTx().GetIdem(), priority, dummy);
    info.pushKV("currentpriority", priority);
    info.pushKV("ancestorcount", e.GetCountWithAncestors());
    info.pushKV("ancestorsize", e.GetSizeWithAncestors());
    info.pushKV("ancestorfees", e.GetModFeesWithAncestors());
    const CTransaction &tx = e.GetTx();
    set<string> setDepends;
    const CTxMemPool::setEntries &parents = mempool.GetMemPoolParents(tx);
    for (const auto &p : parents)
    {
        setDepends.insert(p->GetTx().GetIdem().GetHex());
    }

    UniValue depends(UniValue::VARR);
    for (const string &dep : setDepends)
    {
        depends.push_back(dep);
    }
    info.pushKV("depends", depends);

    UniValue spent(UniValue::VARR);
    const CTxMemPool::TxIdIter &it = mempool.mapTx.find(tx.GetId());
    const CTxMemPool::setEntries &setChildren = mempool.GetMemPoolChildren(it);
    for (const CTxMemPool::TxIdIter &childiter : setChildren)
    {
        spent.push_back(childiter->GetTx().GetIdem().ToString());
    }
    info.pushKV("spentby", spent);
}

UniValue mempoolToJSON(bool fVerbose /* = false */, bool idem /* = false */)
{
    if (fVerbose)
    {
        READLOCK(mempool.cs_txmempool);
        UniValue o(UniValue::VOBJ);
        for (const CTxMemPoolEntry &e : mempool.mapTx)
        {
            const uint256 &hash = (idem) ? e.GetTx().GetIdem() : e.GetTx().GetId();
            UniValue info(UniValue::VOBJ);
            entryToJSON(info, e);
            o.pushKV(hash.ToString(), info);
        }
        return o;
    }
    else
    {
        vector<uint256> vtxid;
        if (idem)
            mempool.queryIdems(vtxid);
        else
            mempool.queryIds(vtxid);

        UniValue a(UniValue::VARR);
        for (const uint256 &hash : vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue orphanpoolToJSON()
{
    vector<uint256> vHashes;
    orphanpool.QueryIds(vHashes);

    UniValue a(UniValue::VARR);
    for (const uint256 &hash : vHashes)
        a.push_back(hash.ToString());

    return a;
}

UniValue getrawtxpool(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getrawtxpool ( verbose ) (id or idem)\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of "
            "2. id or idem        (string, optional, default=idem) return transaction idem or id\n"
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n" +
            EntryDescriptionString() +
            "  }, ...\n"
            "}\n"
            "\nExamples\n" +
            HelpExampleCli("getrawtxpool", "true") + HelpExampleRpc("getrawtxpool", "true"));

    bool idem = true;
    bool fVerbose = false;
    if (params.size() > 0)
    {
        if (params[0].isStr())
            fVerbose = InterpretBool(params[0].get_str());
        else if (params[0].isNum())
            fVerbose = (params[0].get_int() != 0);
        else
            fVerbose = params[0].get_bool();
    }
    if (params.size() > 1)
    {
        std::string s = params[1].get_str();
        makeLowercase(s);
        if (s == "id")
            idem = false;
        else if (s != "idem")
            throw JSONRPCError(RPC_INVALID_PARAMS, "2nd parameter must be 'id' or 'idem'");
    }

    return mempoolToJSON(fVerbose, idem);
}

UniValue getrawtxpoolbyid(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getrawtxpool ( verbose ) ( id or idem)\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of "
            "2. id or idem           (string, optional, default=idem) return transaction idem or id\n"
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n" +
            EntryDescriptionString() +
            "  }, ...\n"
            "}\n"
            "\nExamples\n" +
            HelpExampleCli("getrawtxpool", "true") + HelpExampleRpc("getrawtxpool", "true"));

    bool fVerbose = false;
    bool idem = true;
    if (params.size() > 0)
        fVerbose = params[0].get_bool();
    if (params.size() > 1)
    {
        std::string s = params[1].get_str();
        makeLowercase(s);
        if (s == "id")
            idem = false;
        else if (s != "idem")
            throw JSONRPCError(RPC_INVALID_PARAMS, "2nd parameter must be 'id' or 'idem'");
    }

    return mempoolToJSON(fVerbose, idem);
}

UniValue getraworphanpool(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error("getraworphanpool\n"
                            "\nReturns all transaction ids in orphan pool as a json array of string transaction ids.\n"
                            "\nResult:\n"
                            "[                     (json array of string)\n"
                            "  \"transactionid\"     (string) The transaction id\n"
                            "  ,...\n"
                            "]\n"
                            "\nExamples\n" +
                            HelpExampleCli("getraworphanpool", "") + HelpExampleRpc("getraworphanpool", ""));

    return orphanpoolToJSON();
}

UniValue gettxpoolancestors(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "gettxpoolancestors txid (verbose)\n"
            "\nIf txid is in the txpool, returns all in-txpool ancestors.\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in txpool)\n"
            "2. verbose                  (boolean, optional, default=false) true for a json object, false for array of "
            "transaction ids\n"
            "\nResult (for verbose=false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an in-txpool ancestor transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose=true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n" +
            EntryDescriptionString() +
            "  }, ...\n"
            "}\n"
            "\nExamples\n" +
            HelpExampleCli("gettxpoolancestors", "\"mytxid\"") + HelpExampleRpc("gettxpoolancestors", "\"mytxid\""));
    }

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    uint256 paramhash = ParseHashV(params[0], "parameter 1");

    READLOCK(mempool.cs_txmempool);

    CTxMemPool::TxIdIter it = mempool._getIdIter(paramhash);
    if (it == mempool.mapTx.end())
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in txpool");
    }

    CTxMemPool::setEntries setAncestors;
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    mempool._CalculateMemPoolAncestors(*it, setAncestors, noLimit, noLimit, dummy, nullptr, false);

    if (!fVerbose)
    {
        UniValue o(UniValue::VARR);
        for (CTxMemPool::TxIdIter ancestorIt : setAncestors)
        {
            o.push_back(ancestorIt->GetTx().GetId().ToString());
        }

        return o;
    }
    else
    {
        UniValue o(UniValue::VOBJ);
        for (CTxMemPool::TxIdIter ancestorIt : setAncestors)
        {
            const CTxMemPoolEntry &e = *ancestorIt;
            const uint256 &hash = e.GetTx().GetId();
            UniValue info(UniValue::VOBJ);
            entryToJSON(info, e);
            o.pushKV(hash.ToString(), info);
        }
        return o;
    }
}

UniValue gettxpooldescendants(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        throw runtime_error(
            "gettxpooldescendants txid (verbose)\n"
            "\nIf txid is in the txpool, returns all in-txpool descendants.\n"
            "\nArguments:\n"
            "1. \"txid\"                   (string, required) The transaction id (must be in txpool)\n"
            "2. verbose                  (boolean, optional, default=false) true for a json object, false for array of "
            "transaction ids\n"
            "\nResult (for verbose=false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an in-txpool descendant transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose=true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n" +
            EntryDescriptionString() +
            "  }, ...\n"
            "}\n"
            "\nExamples\n" +
            HelpExampleCli("gettxpooldescendants", "\"mytxid\"") +
            HelpExampleRpc("gettxpooldescendants", "\"mytxid\""));
    }

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    uint256 paramhash = ParseHashV(params[0], "parameter 1");

    WRITELOCK(mempool.cs_txmempool);

    CTxMemPool::TxIdIter it = mempool._getIdIter(paramhash);
    if (it == mempool.mapTx.end())
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in txpool");
    }

    CTxMemPool::setEntries setDescendants;
    mempool._CalculateDescendants(it, setDescendants);
    // CTxMemPool::CalculateDescendants will include the given tx
    setDescendants.erase(it);

    if (!fVerbose)
    {
        UniValue o(UniValue::VARR);
        for (auto descendantIt : setDescendants)
        {
            o.push_back(descendantIt->GetTx().GetId().ToString());
        }

        return o;
    }
    else
    {
        UniValue o(UniValue::VOBJ);
        for (auto descendantIt : setDescendants)
        {
            const CTxMemPoolEntry &e = *descendantIt;
            const uint256 &hash = e.GetTx().GetId();
            UniValue info(UniValue::VOBJ);
            entryToJSON(info, e);
            o.pushKV(hash.ToString(), info);
        }
        return o;
    }
}

UniValue gettxpoolentry(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw runtime_error("gettxpoolentry txid\n"
                            "\nReturns txpool data for given transaction\n"
                            "\nArguments:\n"
                            "1. \"txid\"                   (string, required) The transaction id (must be in txpool)\n"
                            "\nResult:\n"
                            "{                           (json object)\n" +
                            EntryDescriptionString() +
                            "}\n"
                            "\nExamples\n" +
                            HelpExampleCli("gettxpoolentry", "\"mytxid\"") +
                            HelpExampleRpc("gettxpoolentry", "\"mytxid\""));
    }

    uint256 hash = ParseHashV(params[0], "parameter 1");

    READLOCK(mempool.cs_txmempool);

    CTxMemPool::TxIdIter it = mempool._getIdIter(hash);
    if (it == mempool.mapTx.end())
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in txpool");
    }

    // Update the ancestor chain state if this transaction is part of
    // an unconfirmed chain
    mempool.UpdateTxnChainState(it);

    const CTxMemPoolEntry &e = *it;
    UniValue info(UniValue::VOBJ);
    entryToJSON(info, e);
    return info;
}

UniValue getblockhash(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("getblockhash index\n"
                            "\nReturns hash of block in best-block-chain at index provided.\n"
                            "\nArguments:\n"
                            "1. index         (numeric, required) The block index\n"
                            "\nResult:\n"
                            "\"hash\"         (string) The block hash\n"
                            "\nExamples:\n" +
                            HelpExampleCli("getblockhash", "1000") + HelpExampleRpc("getblockhash", "1000"));

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex *pblockindex = chainActive[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

UniValue getblockheader(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getblockheader hash_or_height ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
            "If verbose is true, returns an Object with information about blockheader <hash>.\n"
            "\nArguments:\n"
            "1. \"hash_or_height\"          (string|numeric, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded "
            "data\n"
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main "
            "chain\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"size\" : n,            (numeric) The size of the block\n"
            "  \"txcount\" : n,         (numeric) The number of transactions in the block\n"
            "  \"feePoolAmt\" : n,      (numeric) The fee pool amount\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string)  The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"chainwork\" : \"0000...1f3\"     (string) Expected number of hashes required to produce the current "
            "chain (in hex)\n"
            "  \"utxoCommitment\" : n,  (hash)    The utxo commitment\n"
            "  \"minerdata\" : \"xxxx\",        (string) A hex string identifier that the miner provides\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"ancestorblockhash\" : \"hash\",  (string) The hash of the ancestor block\n"
            "  \"nextblockhash\" : \"hash\",      (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"") +
            HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\""));

    CBlockIndex *pindex = nullptr;
    bool isNumber = true;
    int height = -1;
    if (!params[0].isNum())
    {
        // determine if string is the height or block hash
        const std::string param0 = params[0].get_str();
        isNumber = (param0.size() <= 20);
        if (isNumber)
        {
            // if it was a number as a string, try to convert it to an int
            try
            {
                height = std::stoi(param0);
            }
            catch (const std::invalid_argument &ia)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid argument: %s. Block height %s is not a valid value", ia.what(), param0.c_str()));
            }
        }
        else
        {
            // if not grab the block by hash
            const uint256 hash(uint256S(param0));
            pindex = LookupBlockIndex(hash);
            if (!pindex)
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found by block hash");
            }
            if (!chainActive.Contains(pindex))
            {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER, strprintf("Block is not in chain %s", Params().NetworkIDString()));
            }
        }
    }
    else
    {
        height = params[0].get_int();
    }
    if (isNumber)
    {
        const int current_tip = chainActive.Height();
        if (height < 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        if (height > current_tip)
        {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }
        LOG(RPC, "%s for height %d (tip is at %d)", __func__, height, current_tip);
        pindex = chainActive[height];
        DbgAssert(pindex && pindex->height() == height, throw std::runtime_error(__func__));
    }

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (!pindex)
        throw std::runtime_error("No entry found in the block index");
    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }
    else
        return blockheaderToJSON(pindex);
}

// Allows passing int instead of bool
static bool is_param_trueish(const UniValue &param)
{
    if (param.isNum())
    {
        return static_cast<bool>(param.get_int());
    }
    return param.get_bool();
}

// Return the block data that corresponds to a given header.  If the block data does not exist, then throw an
// exception that's compatible with our RPC interface.
static CBlock GetBlockChecked(const CBlockIndex *pblockindex)
{
    if (IsBlockPruned(pblockindex))
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");

    const ConstCBlockRef pblock = ReadBlockFromDisk(pblockindex, Params().GetConsensus());
    if (!pblock)
    {
        // Block not found on disk. This could be because we have the block
        // header in our index but don't have the block (for example if a
        // non-whitelisted node sends us an unrequested long chain of valid
        // blocks, we add the headers to our index, but don't accept the
        // block).
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }
    return *pblock;
}

static CBlockUndo GetUndoChecked(const CBlockIndex *pblockindex)
{
    DbgAssert(pblockindex, throw std::runtime_error(__func__));
    CBlockUndo blockUndo;
    if (IsBlockPruned(pblockindex))
    {
        throw JSONRPCError(RPC_MISC_ERROR, "Undo data not available (pruned data)");
    }

    if (!ReadUndoFromDisk(blockUndo, pblockindex->GetUndoPos(), pblockindex->pprev))
    {
        throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
    }

    return blockUndo;
}

static UniValue getblock(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "getblock hash_or_height ( verbosity ) ( tx_count )\n"
            "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbosity is 1, returns the block header with a list of transaction hashes in the block\n"
            "If verbosity is 2, returns the block header with a list of all decoded transaction details in the block\n"
            "If tx_count is true, returns a block header with a count of all transactions in the block.\n"
            "\nArguments:\n"
            "1. \"hash_or_height\"      (string|numeric, required) The block hash or height.\n"
            "2. \"verbosity\"           (numeric, optional, default=1) 0 for hex-encoded data, 1 \n"
            "                          for a block header with list of txn hashes, and 2 for a block header with \n"
            "                          detailed transaction data.\n"
            "3. \"tx_count\"            (boolean, optional, default=false true to get a block header with a count of \n"
            "                          of transactions in the block.\n"
            "\nResult (for verbosity = 1, tx_count = false):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main "
            "chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"txcount\" : n,         (numeric) The number of transactions in the block\n"
            "  \"feePoolAmt\" : n,      (numeric) The fee pool amount\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"versionHex\" : \"00000000\", (string) The block version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"chainwork\" : \"xxxx\",  (string) Expected number of hashes required to produce the chain up to this "
            "block (in hex)\n"
            "  \"utxoCommitment\" : n,  (hash)    The utxo commitment\n"
            "  \"minerdata\" : \"xxxx\",        (string) A hex string identifier that the miner provides\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"ancestorblockhash\" : \"hash\",  (string) The hash of the ancestor block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbosity = 2, tx_count = false):\n"
            "{\n"
            "Same as for verbosity = 1 but with all the un-encoded details of each transaction\n"
            "}\n"
            "\nResult (for verbosity=0):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"") +
            HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\""));

    CBlockIndex *pindex = nullptr;
    bool isNumber = true;
    int height = -1;
    if (!params[0].isNum())
    {
        // determine if string is the height or block hash
        const std::string param0 = params[0].get_str();
        isNumber = (param0.size() <= 20);
        if (isNumber)
        {
            // if it was a number as a string, try to convert it to an int
            try
            {
                height = std::stoi(param0);
            }
            catch (const std::invalid_argument &ia)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid argument: %s. Block height %s is not a valid value", ia.what(), param0.c_str()));
            }
        }
        else
        {
            // if not grab the block by hash
            const uint256 hash(uint256S(param0));
            pindex = LookupBlockIndex(hash);
            if (!pindex)
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found by block hash");
            }
        }
    }
    else
    {
        height = params[0].get_int();
    }
    if (isNumber)
    {
        const int current_tip = chainActive.Height();
        if (height < 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        if (height > current_tip)
        {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }
        LOG(RPC, "%s for height %d (tip is at %d)", __func__, height, current_tip);
        pindex = chainActive[height];
        DbgAssert(pindex && pindex->height() == height, throw std::runtime_error(__func__));
    }

    DbgAssert(pindex != nullptr, throw std::runtime_error(__func__));

    int nVerbose = 1;
    bool fListTxns = true;
    if (params.size() > 1)
    {
        if (params[1].isNum())
            nVerbose = params[1].get_int();
        else
            nVerbose = is_param_trueish(params[1]);
    }
    if (params.size() == 3)
    {
        fListTxns = !(is_param_trueish(params[2]));
    }

    const CBlock block = GetBlockChecked(pindex);

    if (nVerbose == 0 && fListTxns == true)
    {
        return block.GetHex();
    }

    bool fVerbose = false;
    if (nVerbose == 1)
        fVerbose = false;
    else if (nVerbose == 2)
        fVerbose = true;

    return blockToJSON(block, pindex, fVerbose, fListTxns);
}

static void ApplyStats(CCoinsStats &stats, CHashWriter &ss, const COutPoint &outpt, const Coin &coin)
{
    ss << outpt;
    ss << coin;
    stats.nTransactionOutputs++;
    stats.nTotalAmount += coin.GetValue();
}

//! Calculate statistics about the unspent transaction output set
static bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    DbgAssert(pcursor, throw std::runtime_error(__func__));

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = pcursor->GetBestBlock();
    stats.nTransactionOutputs = 0;
    stats.nTotalAmount = 0;

    CBlockIndex *pindex = LookupBlockIndex(stats.hashBlock);
    stats.nHeight = (pindex ? pindex->height() : -1);
    ss << stats.hashBlock;
    COutPoint prevkey;
    while (pcursor->Valid())
    {
        boost::this_thread::interruption_point();
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin))
        {
            ApplyStats(stats, ss, key, coin);
        }
        else
        {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    stats.hashSerialized = ss.GetHash();
    stats.nDiskSize = view->EstimateSize();
    return true;
}


UniValue gettxoutsetinfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error("gettxoutsetinfo\n"
                            "\nReturns statistics about the unspent transaction output set.\n"
                            "Note this call may take some time.\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"height\":n,     (numeric) The current block height (index)\n"
                            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
                            "  \"txouts\": n,            (numeric) The number of output transactions\n"
                            "  \"hash_serialized\": \"hash\",   (string) The hash of the serialized UTXO (commitment)\n"
                            "  \"disk_size\": n,         (numeric) The estimated size of the chainstate on disk\n"
                            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
                            "}\n"
                            "\nExamples:\n" +
                            HelpExampleCli("gettxoutsetinfo", "") + HelpExampleRpc("gettxoutsetinfo", ""));

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (GetUTXOStats(pcoinsdbview, stats))
    {
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("hash_serialized", stats.hashSerialized.GetHex());
        ret.pushKV("disk_size", stats.nDiskSize);
        ret.pushKV("total_amount", ValueFromAmount(stats.nTotalAmount));
    }
    return ret;
}

UniValue evicttransaction(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "evicttransaction \"txid\"\n"
            "\nRemove transaction from txpool.  Note that it could be re-added quickly if relayed by another node\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "\nResult:\n"
            "The number of transactions removed (children must also be removed)\n"
            "\nExamples:\n" +
            HelpExampleCli("evicttransaction", "\"txid\"") + HelpExampleRpc("evicttransaction", "\"txid\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    return UniValue(mempool.Remove(hash));
}

UniValue gettxout(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error("gettxout \"txid\" n ( includetxpool )\n"
                            "\nReturns details about an unspent transaction output.\n"
                            "\nArguments:\n"
                            "1. \"txid\"       (string, required) The transaction id\n"
                            "2. n              (numeric, required) vout value\n"
                            "3. includetxpool  (boolean, optional) Whether to included the mem pool\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
                            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
                            "  \"value\" : x.xxx,           (numeric) The transaction value in " +
                            CURRENCY_UNIT +
                            "\n"
                            "  \"scriptPubKey\" : {         (json object)\n"
                            "     \"asm\" : \"code\",       (string) \n"
                            "     \"hex\" : \"hex\",        (string) \n"
                            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
                            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
                            "     \"addresses\" : [          (array of string) array of nexa addresses\n"
                            "        \"nexaaddress\"     (string) nexa address\n"
                            "        ,...\n"
                            "     ]\n"
                            "  },\n"
                            "  \"version\" : n,            (numeric) The version\n"
                            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
                            "}\n"

                            "\nExamples:\n"
                            "\nGet unspent transactions\n" +
                            HelpExampleCli("listunspent", "") + "\nView the details\n" +
                            HelpExampleCli("gettxout", "\"txid\" 1") + "\nAs a json rpc call\n" +
                            HelpExampleRpc("gettxout", "\"txid\", 1"));

    UniValue ret(UniValue::VOBJ);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    int n = params[1].get_int();
    COutPoint out(hash, n);
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    Coin coin;
    if (fMempool)
    {
        READLOCK(mempool.cs_txmempool);
        CCoinsViewMemPool view(pcoinsTip, mempool);
        // TODO: filtering spent coins should be done by the CCoinsViewMemPool
        if (!view.GetCoin(out, coin) || mempool.isSpent(out))
        {
            return NullUniValue;
        }
    }
    else
    {
        if (!pcoinsTip->GetCoin(out, coin))
        {
            return NullUniValue;
        }
    }

    CBlockIndex *pindex = LookupBlockIndex(pcoinsTip->GetBestBlock());
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if (coin.nHeight == MEMPOOL_HEIGHT)
    {
        ret.pushKV("confirmations", 0);
    }
    else
    {
        ret.pushKV("confirmations", (int64_t)(pindex->height() - coin.nHeight + 1));
    }
    ret.pushKV("value", ValueFromAmount(coin.out.nValue));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coin.out.scriptPubKey, o, true);
    ret.pushKV("scriptPubKey", o);
    ret.pushKV("coinbase", (bool)coin.fCoinBase);

    return ret;
}

UniValue verifychain(const UniValue &params, bool fHelp)
{
    int nCheckLevel = GetArg("-checklevel", DEFAULT_CHECKLEVEL);
    int nCheckDepth = GetArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    if (fHelp || params.size() > 2)
        throw runtime_error("verifychain ( checklevel numblocks )\n"
                            "\nVerifies blockchain database.\n"
                            "\nArguments:\n"
                            "1. checklevel   (numeric, optional, 0-4, default=" +
                            strprintf("%d", nCheckLevel) +
                            ") How thorough the block verification is.\n"
                            "2. numblocks    (numeric, optional, default=" +
                            strprintf("%d", nCheckDepth) +
                            ", 0=all) The number of blocks to check.\n"
                            "\nResult:\n"
                            "true|false       (boolean) Verified or not\n"
                            "\nExamples:\n" +
                            HelpExampleCli("verifychain", "") + HelpExampleRpc("verifychain", ""));

    LOCK(cs_main);

    if (params.size() > 0)
        nCheckLevel = params[0].get_int();
    if (params.size() > 1)
        nCheckDepth = params[1].get_int();

    return CVerifyDB().VerifyDB(Params(), pcoinsTip, nCheckLevel, nCheckDepth);
}

#if 0 // unused
/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int version, CBlockIndex *pindex, const Consensus::Params &consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    bool activated = false;
    switch (version)
    {
        // Kept as an example
        // case 3:
        //    activated = pindex->height() >= consensusParams.BIP66Height;
        //    break;
    }
    rv.pushKV("status", activated);
    return rv;
}


static UniValue SoftForkDesc(const std::string &name,
    int version,
    CBlockIndex *pindex,
    const Consensus::Params &consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    rv.pushKV("id", name);
    rv.pushKV("version", version);
    rv.pushKV("reject", SoftForkMajorityDesc(version, pindex, consensusParams));
    return rv;
}
#endif

static void pushBackThresholdStatus(UniValue &rv,
    const Consensus::Params &consensusParams,
    const ThresholdState thresholdState,
    Consensus::DeploymentPos id,
    VersionBitBIP versionBitBIP)
{
    if (versionBitBIP == BIP_135)
    {
        rv.pushKV("bit", (int)id);
    }
    switch (thresholdState)
    {
    case THRESHOLD_DEFINED:
        rv.pushKV("status", "defined");
        break;
    case THRESHOLD_STARTED:
        rv.pushKV("status", "started");
        break;
    case THRESHOLD_LOCKED_IN:
        rv.pushKV("status", "locked_in");
        break;
    case THRESHOLD_ACTIVE:
        rv.pushKV("status", "active");
        break;
    case THRESHOLD_FAILED:
        rv.pushKV("status", "failed");
        break;
    }
    if (versionBitBIP == BIP_009 && THRESHOLD_STARTED == thresholdState)
    {
        rv.pushKV("bit", consensusParams.vDeployments[id].bit);
    }
    rv.pushKV("startTime", consensusParams.vDeployments[id].nStartTime);
    rv.pushKV("timeout", consensusParams.vDeployments[id].nTimeout);
}

static UniValue BIP9SoftForkDesc(const Consensus::Params &consensusParams, Consensus::DeploymentPos id)
{
    UniValue rv(UniValue::VOBJ);
    const ThresholdState thresholdState = VersionBitsTipState(consensusParams, id);
    pushBackThresholdStatus(rv, consensusParams, thresholdState, id, BIP_009);

    return rv;
}

// bip135 begin
static UniValue BIP135ForkDesc(const Consensus::Params &consensusParams, Consensus::DeploymentPos id)
{
    UniValue rv(UniValue::VOBJ);
    const ThresholdState thresholdState = VersionBitsTipState(consensusParams, id);
    pushBackThresholdStatus(rv, consensusParams, thresholdState, id, BIP_135);
    rv.pushKV("windowsize", consensusParams.vDeployments[id].windowsize);
    rv.pushKV("threshold", consensusParams.vDeployments[id].threshold);
    rv.pushKV("minlockedblocks", consensusParams.vDeployments[id].minlockedblocks);
    rv.pushKV("minlockedtime", consensusParams.vDeployments[id].minlockedtime);
    return rv;
}
// bip135 end

UniValue getblockchaininfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"
            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"mediantime\": xxxxxx,     (numeric) median time for the current best block\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"initialblockdownload\": xxxx, (bool) (debug information) estimate of whether this node is in Initial "
            "Block Download mode.\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"size_on_disk\": xxxxxx,   (numeric) the estimated size of the block and undo files on disk\n"
            "  \"pruned\": xx,             (boolean) if the blocks are subject to pruning\n"
            "  \"pruneheight\": xxxxxx,    (numeric) lowest-height complete block stored (only present if pruning is "
            "enabled)\n"
            "  \"prune_target_size\": xxxxxx,  (numeric) the target size used by pruning (only present if automatic "
            "pruning is enabled)\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) block version\n"
            "        \"reject\": {            (object) progress toward rejecting pre-softfork blocks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "        },\n"
            "     }, ...\n"
            "  ],\n"
            "  \"bip9_softforks\": {          (object) status of BIP9 softforks in progress\n"
            "     \"xxxx\" : {                (string) name of the softfork\n"
            "        \"status\": \"xxxx\",    (string) one of \"defined\", \"started\", \"lockedin\", \"active\", "
            "\"failed\"\n"
            "        \"bit\": xx,             (numeric) the bit, 0-28, in the block version field used to signal this "
            "soft fork\n"
            "        \"startTime\": xx,       (numeric) the minimum median time past of a block at which the bit gains "
            "its meaning\n"
            "        \"timeout\": xx          (numeric) the median time past of a block at which the deployment is "
            "considered failed if not yet locked in\n"
            "     }\n"
            "  }\n"
            // bip135 begin
            "  \"bip135_forks\": {            (object) status of BIP135 forks in progress\n"
            "     \"xxxx\" : {                (string) name of the fork\n"
            "        \"status\": \"xxxx\",      (string) one of \"defined\", \"started\", \"locked_in\", \"active\", "
            "\"failed\"\n"
            "        \"bit\": xx,             (numeric) the bit (0-28) in the block version field used to signal this "
            "fork (only for \"started\" status)\n"
            "        \"startTime\": xx,       (numeric) the minimum median time past of a block at which the bit gains "
            "its meaning\n"
            "        \"windowsize\": xx,      (numeric) the number of blocks over which the fork status is tallied\n"
            "        \"threshold\": xx,       (numeric) the number of blocks in a window that must signal for fork to "
            "lock in\n"
            "        \"minlockedblocks\": xx, (numeric) the minimum number of blocks to elapse after lock-in and "
            "before activation\n"
            "        \"minlockedtime\": xx,   (numeric) the minimum number of seconds to elapse after median time past "
            "of lock-in until activation\n"
            "     }\n"
            "  }\n"
            // bip135 end
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockchaininfo", "") + HelpExampleRpc("getblockchaininfo", ""));

    LOCK(cs_main);

    CBlockIndex *tip = chainActive.Tip();
    if (!tip)
        throw runtime_error("No Chain Tip");

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", Params().NetworkIDString());
    obj.pushKV("blocks", (int)chainActive.Height());
    obj.pushKV("headers", pindexBestHeader ? pindexBestHeader.load()->height() : -1);
    obj.pushKV("bestblockhash", tip->GetBlockHash().GetHex());
    obj.pushKV("difficulty", (double)GetDifficulty());
    obj.pushKV("mediantime", (int64_t)tip->GetMedianTimePast());
    obj.pushKV("verificationprogress", Checkpoints::GuessVerificationProgress(tip, !fCheckpointsEnabled));
    obj.pushKV("initialblockdownload", IsInitialBlockDownload());
    obj.pushKV("chainwork", tip->chainWork().GetHex());
    obj.pushKV("size_on_disk", CalculateCurrentUsage());
    obj.pushKV("pruned", fPruneMode);
    if (fPruneMode)
    {
        CBlockIndex *block = tip;
        {
            READLOCK(cs_mapBlockIndex);
            while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA))
            {
                block = block->pprev;
            }
        }

        if (block != nullptr)
        {
            obj.pushKV("pruneheight", block->height());
        }
        else
        {
            obj.pushKV("pruneheight", 0);
        }

        obj.pushKV("prune_target_size", nPruneTarget);
    }

    const Consensus::Params &consensusParams = Params().GetConsensus();
    UniValue softforks(UniValue::VARR);
    UniValue bip9_softforks(UniValue::VOBJ);
    UniValue bip135_forks(UniValue::VOBJ); // bip135 added
    // bip135 begin : add all the configured forks
    for (int i = 0; i < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++)
    {
        Consensus::DeploymentPos bit = static_cast<Consensus::DeploymentPos>(i);
        const struct ForkDeploymentInfo &vbinfo = VersionBitsDeploymentInfo[bit];
        if (IsConfiguredDeployment(consensusParams, bit))
        {
            bip9_softforks.pushKV(vbinfo.name, BIP9SoftForkDesc(consensusParams, bit));
            bip135_forks.pushKV(vbinfo.name, BIP135ForkDesc(consensusParams, bit));
        }
    }

    obj.pushKV("softforks", softforks);
    obj.pushKV("bip9_softforks", bip9_softforks);
    // to maintain backward compat initially, we introduce a new list for the full BIP135 data
    obj.pushKV("bip135_forks", bip135_forks);
    // bip135 end

    return obj;
}

std::set<CBlockIndex *, CompareBlocksByHeight> GetChainTips()
{
    /*
     * Idea:  the set of chain tips is chainActive.tip, plus orphan blocks which do not have another orphan building off
     * of them.
     * Algorithm:
     *  - Make one pass through mapBlockIndex, picking out the orphan blocks, and also storing a set of the orphan
     * block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - add chainActive.Tip()
     */
    std::set<CBlockIndex *, CompareBlocksByHeight> setTips;
    std::set<CBlockIndex *> setOrphans;
    std::set<CBlockIndex *> setPrevs;

    READLOCK(cs_mapBlockIndex);
    for (const std::pair<const uint256, CBlockIndex *> &item : mapBlockIndex)
    {
        DbgAssert(item.second != nullptr, );
        if (!item.second)
            continue;

        if (!chainActive.Contains(item.second))
        {
            setOrphans.insert(item.second);
            setPrevs.insert(item.second->pprev);
        }
    }

    for (auto &it : setOrphans)
    {
        if (setPrevs.erase(it) == 0)
        {
            setTips.insert(it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(chainActive.Tip());

    return setTips;
}

UniValue getchaintips(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"chainwork\": \"xxxx\"     (string) total amount of work in this chain, in hexadecimal\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) length of branch connecting the tip to the main chain (zero for "
            "main chain)\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, "
            "headers-only, invalid)\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully "
            "validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"
            "\nExamples:\n" +
            HelpExampleCli("getchaintips", "") + HelpExampleRpc("getchaintips", ""));

    // Get the set of chaintips
    std::set<CBlockIndex *, CompareBlocksByHeight> setTips;
    setTips = GetChainTips();

    /* Construct the output array.  */
    WRITELOCK(cs_mapBlockIndex); // for nStatus
    UniValue res(UniValue::VARR);
    for (const CBlockIndex *block : setTips)
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->height());
        obj.pushKV("chainwork", block->chainWork().GetHex());
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->height() - chainActive.FindFork(block)->height();
        obj.pushKV("branchlen", branchLen);

        string status;
        if (chainActive.Contains(block))
        {
            // This block is part of the currently active chain.
            status = "active";
        }
        else if (block->nStatus & BLOCK_FAILED_MASK)
        {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        }
        else if (!block->IsLinked())
        {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        }
        else if (block->IsValid(BLOCK_VALID_SCRIPTS))
        {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block
            // once, but was reorganized.
            status = "valid-fork";
        }
        else if (block->IsValid(BLOCK_VALID_TREE))
        {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the
            // most-work chain.
            status = "valid-headers";
        }
        else
        {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(obj);
    }

    return res;
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("size", (int64_t)mempool.size());
    ret.pushKV("bytes", (int64_t)mempool.GetTotalTxSize());
    ret.pushKV("usage", (int64_t)mempool.DynamicMemoryUsage());
    ret.pushKV("maxtxpool", (int64_t)maxTxPool.Value() * ONE_MEGABYTE);
    int64_t minfee = (int64_t)::minRelayTxFee.GetFeePerK();
    ret.pushKV("txpoolminfee", ValueFromAmount(minfee));
    double smoothedTps = 0.0, instantaneousTps = 0.0, peakTps = 0.0;
    mempool.GetTransactionRateStatistics(smoothedTps, instantaneousTps, peakTps);
    try
    {
        ret.pushKV("tps", std::stod(strprintf("%.2f", smoothedTps)));
    }
    catch (...)
    {
        ret.pushKV("tps", "N/A");
    }
    try
    {
        ret.pushKV("peak_tps", std::stod(strprintf("%.2f", peakTps)));
    }
    catch (...)
    {
        ret.pushKV("peak_tps", "N/A");
    }

    return ret;
}

UniValue gettxpoolinfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error("gettxpoolinfo\n"
                            "\nReturns details on the active state of the TX memory pool.\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"size\": xxxxx,               (numeric) Current tx count\n"
                            "  \"bytes\": xxxxx,              (numeric) Sum of all tx sizes\n"
                            "  \"usage\": xxxxx,              (numeric) Total memory usage for the transaction pool\n"
                            "  \"maxtxpool\": xxxxx,          (numeric) Maximum memory usage for the transaction pool\n"
                            "  \"txpoolminfee\": xxxxx        (numeric) Minimum fee for tx to be accepted\n"
                            "  \"tps\": xxxxx                 (numeric) Transactions per second accepted\n"
                            "  \"peak_tps\": xxxxx            (numeric) Peak Transactions per second accepted\n"
                            "}\n"
                            "\nExamples:\n" +
                            HelpExampleCli("gettxpoolinfo", "") + HelpExampleRpc("gettxpoolinfo", ""));

    return mempoolInfoToJSON();
}

UniValue orphanpoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("size", (int64_t)orphanpool.GetOrphanPoolSize());
    ret.pushKV("bytes", (int64_t)orphanpool.GetOrphanPoolBytes());

    return ret;
}

UniValue getorphanpoolinfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error("getorphanpoolinfo\n"
                            "\nReturns details on the active state of the TX orphan pool.\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"size\": xxxxx,               (numeric) Current tx count\n"
                            "  \"bytes\": xxxxx,              (numeric) Sum of all tx sizes\n"
                            "}\n"
                            "\nExamples:\n" +
                            HelpExampleCli("getorphanpoolinfo", "") + HelpExampleRpc("getorphanoolinfo", ""));

    return orphanpoolInfoToJSON();
}

UniValue invalidateblock(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("invalidateblock \"hash\"\n"
                            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"
                            "\nArguments:\n"
                            "1. hash   (string, required) the hash of the block to mark as invalid\n"
                            "\nResult:\n"
                            "\nExamples:\n" +
                            HelpExampleCli("invalidateblock", "\"blockhash\"") +
                            HelpExampleRpc("invalidateblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    TxAdmissionPause txlock;

    CBlockIndex *pblockindex = LookupBlockIndex(hash);
    if (!pblockindex)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    LOCK(cs_main);

    InvalidateBlock(state, Params().GetConsensus(), pblockindex);

    if (state.IsValid())
    {
        ActivateBestChain(state, Params());
    }

    if (!state.IsValid())
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue finalizeblock(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
    {
        throw std::runtime_error("finalizeblock \"blockhash\"\n"

                                 "\nTreats a block as final. It cannot be reorged. Any chain\n"
                                 "that does not contain this block is invalid. Used on a less\n"
                                 "work chain, it can effectively PUTS YOU OUT OF CONSENSUS.\n"
                                 "USE WITH CAUTION!\n"
                                 "\nResult:\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("finalizeblock", "\"blockhash\"") +
                                 HelpExampleRpc("finalizeblock", "\"blockhash\""));
    }

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    if (maxReorgDepth.Value() < 0)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Block finalization is not enabled");
    else
    {
        CBlockIndex *pblockindex;
        {
            READLOCK(cs_mapBlockIndex);
            if (mapBlockIndex.count(hash) == 0)
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }

            pblockindex = mapBlockIndex[hash];
        }
        FinalizeBlockAndInvalidate(state, pblockindex);
    }

    if (state.IsValid())
    {
        ActivateBestChain(state, Params());
    }

    if (!state.IsValid())
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"
            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("reconsiderblock", "\"blockhash\"") + HelpExampleRpc("reconsiderblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    CBlockIndex *pblockindex = LookupBlockIndex(hash);
    if (!pblockindex)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    {
        LOCK(cs_main);
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid())
    {
        ActivateBestChain(state, Params());
    }

    if (!state.IsValid())
    {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    uiInterface.NotifyBlockTip(false, chainActive.Tip(), false);

    return NullUniValue;
}

std::string RollBackChain(int nRollBackHeight, bool fOverride)
{
    LOCK(cs_main);
    uint32_t nRollBack = chainActive.Height() - nRollBackHeight;
    if (nRollBack > nDefaultRollbackLimit && !fOverride)
        return "You are attempting to rollback the chain by " + std::to_string(nRollBack) +
               " blocks, however the limit is " + std::to_string(nDefaultRollbackLimit) + " blocks. Set " +
               "the override to true if you want rollback more than the default";

    // Lock block validation threads to make sure no new inbound block announcements
    // cause any block validation state to change while we're unwinding the chain.
    LOCK(PV->cs_blockvalidationthread);

    while (chainActive.Height() > nRollBackHeight)
    {
        // save the current tip
        CBlockIndex *pindex = chainActive.Tip();

        CValidationState state;
        // Disconnect the tip and by setting the third param (fRollBack) to true we avoid having to resurrect
        // the transactions from the block back into the txpool, which saves a great deal of time.
        if (!DisconnectTip(state, Params().GetConsensus(), true))
        {
            return "RPC_DATABASE_ERROR: " + state.GetRejectReason();
        }

        if (!state.IsValid())
        {
            return "RPC_DATABASE_ERROR: " + state.GetRejectReason();
        }

        // Invalidate the now previous block tip after it was diconnected so that the chain will not reconnect
        // if another block arrives.
        InvalidateBlock(state, Params().GetConsensus(), pindex);
        if (!state.IsValid())
        {
            return "RPC_DATABASE_ERROR: " + state.GetRejectReason();
        }

        uiInterface.NotifyBlockTip(false, chainActive.Tip(), false);
    }

    return "";
}

UniValue rollbackchain(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error("rollbackchain \"blockheight\"\n"
                            "\nRolls back the blockchain to the height indicated.\n"
                            "\nArguments:\n"
                            "1. blockheight   (int, required) the height that you want to roll the chain \
                            back to (only maxiumum rollback of " +
                            std::to_string(nDefaultRollbackLimit) +
                            " blocks allowed)\n"
                            "2. override      (boolean, optional, default=false) rollback more than the \
                            allowed default limit of " +
                            std::to_string(nDefaultRollbackLimit) +
                            " blocks)\n"
                            "\nResult:\n"
                            "\nExamples:\n" +
                            HelpExampleCli("rollbackchain", "\"501245\"") +
                            HelpExampleCli("rollbackchain", "\"495623 true\"") +
                            HelpExampleRpc("rollbackchain", "\"blockheight\""));

    std::string error;
    int nRollBackHeight = params[0].get_int();
    bool fOverride = false;
    if (params.size() > 1)
        fOverride = params[1].get_bool();

    error = RollBackChain(nRollBackHeight, fOverride);

    if (error.size() > 0)
        throw runtime_error(error.c_str());

    return NullUniValue;
}

std::string ReconsiderMostWorkChain(bool fOverride)
{
    // Error message to return;
    std::string error;

    // Find pindex of most work chain regardless of whether is is valid or not.
    AssertLockHeld(cs_main);

    // Get the set of chaintips
    std::set<CBlockIndex *, CompareBlocksByHeight> setTips;
    setTips = GetChainTips();

    // Find the longest chaintip regardless if it is currently the active one.
    CBlockIndex *pMostWork = chainActive.Tip();
    for (CBlockIndex *pTip : setTips)
    {
        if (pMostWork->chainWork() < pTip->chainWork())
            pMostWork = pTip;
    }
    std::set<CBlockIndex *, CompareBlocksByHeight> setTipsToVerify;
    setTipsToVerify.insert(pMostWork);

    // We need to check if there are duplicate chaintips that have the most work
    // as could happen during a fork. If there are duplicates then we need to test each tip
    // to find out which is the correct fork.
    {
        // parse though chaintips again to find if there are duplicates
        for (CBlockIndex *pTip : setTips)
        {
            if (pMostWork->chainWork() == pTip->chainWork())
                setTipsToVerify.insert(pTip);
        }
    }

    for (CBlockIndex *pTipToVerify : setTipsToVerify)
    {
        // if no duplicates then return since there is nothing to do. We are already on the correct chain
        if (pTipToVerify->chainWork() == chainActive.Tip()->chainWork())
        {
            LOGA("Nothing to do. Already on the correct chain.");
            return "Nothing to do. Already on the correct chain.";
        }

        // Find where chainActive meets the most work chaintip
        const CBlockIndex *pFork;
        pFork = chainActive.FindFork(pTipToVerify);

        // Rollback to the common forkheight so that both chains will be invalidated.
        error = RollBackChain(pFork->height(), fOverride);
        if (error.size() > 0)
            return error;

        // If we got here then rollbackchain() was sucessful and we didn't throw an exception.
        // Now reconsider the new chain.
        LOGA("reconsider block: %s\n", pTipToVerify->GetBlockHash().ToString().c_str());
        CValidationState state;
        ReconsiderBlock(state, pTipToVerify);
        if (state.IsValid())
        {
            _ActivateBestChain(state, Params());
        }
        if (!state.IsValid())
        {
            return "RPC_DATABASE_ERROR: " + state.GetRejectReason();
        }

        if (pTipToVerify->chainWork() == chainActive.Tip()->chainWork())
        {
            LOGA("Active chain has been successfully moved to a new chaintip.");
        }
    }

    return "";
}

UniValue reconsidermostworkchain(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error("reconsidermostworkchain \"[override]\"\n"
                            "\nWill rollback the chain if needed and then sync to the most work chain. If this\n"
                            "client was not upgraded before a hard fork and marked the \"real\" chain as invalid,\n"
                            "then this command should be run after upgrading the client so as to join the correct\n"
                            "and most work chain\n"
                            "\nArguments:\n"
                            "1. override      (boolean, optional, default=false)"
                            "\nResult:\n"
                            "\nExamples:\n" +
                            HelpExampleCli("reconsidermostworkchain", "") +
                            HelpExampleCli("reconsidermostworkchain", "\"true\"") +
                            HelpExampleRpc("reconsidermostworkchain", "\"true\""));

    std::string error;
    bool fOverride = false;
    if (params.size() > 0)
        fOverride = params[0].get_bool();

    {
        TxAdmissionPause txlock;
        LOCK(cs_main);
        error = ReconsiderMostWorkChain(fOverride);
    }

    if (error.size() > 0)
        throw runtime_error(error.c_str());

    return NullUniValue;
}

template <typename T>
static T CalculateTruncatedMedian(std::vector<T> &scores)
{
    size_t size = scores.size();
    if (size == 0)
    {
        return 0;
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0)
    {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    }
    else
    {
        return scores[size / 2];
    }
}

void CalculatePercentilesBySize(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES],
    std::vector<std::pair<CAmount, int64_t> > &scores,
    int64_t total_size)
{
    if (scores.empty())
    {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_size / 10.0, total_size / 4.0, total_size / 2.0, (total_size * 3.0) / 4.0, (total_size * 9.0) / 10.0};

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto &element : scores)
    {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES &&
               cumulative_weight >= weights[next_percentile_index])
        {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++)
    {
        result[i] = scores.back().first;
    }
}

template <typename T>
static inline bool SetHasKeys(const std::set<T> &set)
{
    return false;
}
template <typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T> &set, const Tk &key, const Args &...args)
{
    return (set.count(key) != 0) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD = sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

static UniValue getblockstats(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
    {
        throw std::runtime_error(
            "getblockstats hash_or_height ( stats )\n"
            "\nCompute per block statistics for a given window. All amounts are in satoshis.\n"
            "It won't work for some heights with pruning.\n"
            "\nArguments:\n"
            "1. \"hash_or_height\"     (string or numeric, required) The block hash or height of the target block\n"
            "2. \"stats\"              (array,  optional) Values to plot, by default all values (see result below)\n"
            "    [\n"
            "      \"height\",         (string, optional) Selected statistic\n"
            "      \"time\",           (string, optional) Selected statistic\n"
            "      ,...\n"
            "    ]\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"avgfee\": xxxxx,          (numeric) Average fee in the block\n"
            "  \"avgfeerate\": xxxxx,      (numeric) Average feerate (in satoshis per virtual byte)\n"
            "  \"avgtxsize\": xxxxx,       (numeric) Average transaction size\n"
            "  \"blockhash\": xxxxx,       (string) The block hash (to check for potential reorgs)\n"
            "  \"blocksize\": xxxxx,       (numeric) The block size in bytes\n"
            "  \"nextmaxblocksize\": xxxxx,(numeric) The next maximum block size that can be mined, in bytes\n"
            "  \"feerate_percentiles\": [  (array of numeric) Feerates at the 10th, 25th, 50th, 75th, and 90th "
            "percentile weight unit (in satoshis per virtual byte)\n"
            "      \"10th_percentile_feerate\",      (numeric) The 10th percentile feerate\n"
            "      \"25th_percentile_feerate\",      (numeric) The 25th percentile feerate\n"
            "      \"50th_percentile_feerate\",      (numeric) The 50th percentile feerate\n"
            "      \"75th_percentile_feerate\",      (numeric) The 75th percentile feerate\n"
            "      \"90th_percentile_feerate\",      (numeric) The 90th percentile feerate\n"
            "  ],\n"
            "  \"height\": xxxxx,          (numeric) The height of the block\n"
            "  \"ins\": xxxxx,             (numeric) The number of inputs (excluding coinbase)\n"
            "  \"maxfee\": xxxxx,          (numeric) Maximum fee in the block\n"
            "  \"maxfeerate\": xxxxx,      (numeric) Maximum feerate (in satoshis per virtual byte)\n"
            "  \"maxtxsize\": xxxxx,       (numeric) Maximum transaction size\n"
            "  \"medianfee\": xxxxx,       (numeric) Truncated median fee in the block\n"
            "  \"mediantime\": xxxxx,      (numeric) The block median time past\n"
            "  \"mediantxsize\": xxxxx,    (numeric) Truncated median transaction size\n"
            "  \"minfee\": xxxxx,          (numeric) Minimum fee in the block\n"
            "  \"minfeerate\": xxxxx,      (numeric) Minimum feerate (in satoshis per virtual byte)\n"
            "  \"mintxsize\": xxxxx,       (numeric) Minimum transaction size\n"
            "  \"outs\": xxxxx,            (numeric) The number of outputs\n"
            "  \"sequence_id\": xxxxx,     (numeric) The arrival order of a block at any given height\n"
            "  \"subsidy\": xxxxx,         (numeric) The block subsidy\n"
            "  \"time\": xxxxx,            (numeric) The block time\n"
            "  \"time_received\": xxxxx,   (numeric) The first time either the header or block was received\n"
            "  \"total_out\": xxxxx,       (numeric) Total amount in all outputs (excluding coinbase and thus reward "
            "[ie subsidy + totalfee])\n"
            "  \"total_size\": xxxxx,      (numeric) Total size of all non-coinbase transactions\n"
            "  \"totalfee\": xxxxx,        (numeric) The fee total\n"
            "  \"txs\": xxxxx,             (numeric) The number of transactions (excluding coinbase)\n"
            "  \"utxo_increase\": xxxxx,   (numeric) The increase/decrease in the number of unspent outputs\n"
            "  \"utxo_size_inc\": xxxxx,   (numeric) The increase/decrease in size for the utxo index (not discounting "
            "op_return and similar)\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockstats", "1000 '[\"minfeerate\",\"avgfeerate\"]'") +
            HelpExampleRpc("getblockstats", "1000 '[\"minfeerate\",\"avgfeerate\"]'"));
    }

    LOCK(cs_main);

    CBlockIndex *pindex = nullptr;
    bool isNumber = true;
    int height = -1;
    if (!params[0].isNum())
    {
        // determine if string is the height or block hash
        const std::string param0 = params[0].get_str();
        isNumber = (param0.size() <= 20);
        if (isNumber)
        {
            // if it was a number as a string, try to convert it to an int
            try
            {
                height = std::stoi(param0);
            }
            catch (const std::invalid_argument &ia)
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid argument: %s. Block height %s is not a valid value", ia.what(), param0.c_str()));
            }
        }
        else
        {
            // if not grab the block by hash
            const uint256 hash(uint256S(param0));
            pindex = LookupBlockIndex(hash);
            if (!pindex)
            {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found by block hash");
            }
            if (!chainActive.Contains(pindex))
            {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER, strprintf("Block is not in chain %s", Params().NetworkIDString()));
            }
        }
    }
    else
    {
        height = params[0].get_int();
    }
    if (isNumber)
    {
        const int current_tip = chainActive.Height();
        if (height < 0)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        if (height > current_tip)
        {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }
        LOG(RPC, "%s for height %d (tip is at %d)", __func__, height, current_tip);
        pindex = chainActive[height];
        DbgAssert(pindex && pindex->height() == height, throw std::runtime_error(__func__));
    }

    DbgAssert(pindex != nullptr, throw std::runtime_error(__func__));

    std::set<std::string> stats;
    if (!params[1].isNull())
    {
        const UniValue stats_univalue = params[1].get_array();
        for (unsigned int i = 0; i < stats_univalue.size(); i++)
        {
            const std::string stat = stats_univalue[i].get_str();
            stats.insert(stat);
        }
    }

    const CBlock block = GetBlockChecked(pindex);
    const CBlockUndo blockUndo = pindex->pprev ? GetUndoChecked(pindex) : CBlockUndo();
    // This property is required in the for loop below (and ofc every tx should have undo data)
    DbgAssert(blockUndo.vtxundo.size() >= block.vtx.size() - 1,
        throw JSONRPCError(RPC_DATABASE_ERROR, "Block undo data is corrupt"));

    const bool do_all = stats.size() == 0; // Calculate everything if nothing selected (default)
    const bool do_mediantxsize = do_all || stats.count("mediantxsize") != 0;
    const bool do_medianfee = do_all || stats.count("medianfee") != 0;
    const bool do_feerate_percentiles = do_all || stats.count("feerate_percentiles") != 0;
    const bool loop_inputs = do_all || do_medianfee || do_feerate_percentiles ||
                             SetHasKeys(stats, "utxo_size_inc", "totalfee", "avgfee", "avgfeerate", "minfee", "maxfee",
                                 "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.count("total_out") || stats.count("num_data_only") ||
                              stats.count("utxo_increase");
    const bool do_calculate_size =
        do_mediantxsize || SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize", "avgfeerate",
                               "feerate_percentiles", "minfeerate", "maxfeerate");

    CAmount maxfee = 0;
    CAmount maxfeerate = 0;
    CAmount minfee = MAX_MONEY;
    CAmount minfeerate = MAX_MONEY;
    CAmount total_out = 0;
    CAmount totalfee = 0;
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = std::numeric_limits<int64_t>::max();
    int64_t outputs = 0;
    int64_t dataOutputs = 0;
    int64_t total_size = 0;
    int64_t utxo_size_inc = 0;
    std::vector<CAmount> fee_array;
    std::vector<std::pair<CAmount, int64_t> > feerate_array;
    std::vector<int64_t> txsize_array;

    for (size_t i = 0; i < block.vtx.size(); ++i)
    {
        const auto &tx = block.vtx.at(i);
        outputs += tx->vout.size();

        CAmount tx_total_out = 0;
        if (loop_outputs)
        {
            for (const CTxOut &out : tx->vout)
            {
                tx_total_out += out.nValue;
                if (out.IsDataOnly())
                    dataOutputs++;
                else
                {
                    utxo_size_inc += GetSerializeSize(out, SER_NETWORK, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
                }
            }
        }

        if (tx->IsCoinBase())
        {
            continue;
        }

        inputs += tx->vin.size(); // Don't count coinbase's fake input
        total_out += tx_total_out; // Don't count coinbase reward

        int64_t tx_size = 0;
        if (do_calculate_size)
        {
            tx_size = tx->GetTxSize();
            if (do_mediantxsize)
            {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        if (loop_inputs)
        {
            CAmount tx_total_in = 0;
            const auto &txundo = blockUndo.vtxundo.at(i - 1);
            for (const Coin &coin : txundo.vprevout)
            {
                const CTxOut &prevoutput = coin.out;

                tx_total_in += prevoutput.nValue;
                utxo_size_inc -= GetSerializeSize(prevoutput, SER_NETWORK, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
            }

            CAmount txfee = tx_total_in - tx_total_out;
            DbgAssert(MoneyRange(txfee), throw std::runtime_error(__func__));
            if (do_medianfee)
            {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            CAmount feerate = tx_size ? txfee / tx_size : 0;
            if (do_feerate_percentiles)
            {
                feerate_array.emplace_back(feerate, tx_size);
            }
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    CAmount feerate_percentiles[NUM_GETBLOCKSTATS_PERCENTILES] = {0};
    CalculatePercentilesBySize(feerate_percentiles, feerate_array, total_size);

    UniValue feerates_res(UniValue::VARR);
    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++)
    {
        feerates_res.push_back(ValueFromAmount(feerate_percentiles[i]));
    }

    UniValue ret_all(UniValue::VOBJ);
    ret_all.pushKV("avgfee", ValueFromAmount((block.vtx.size() > 1) ? totalfee / (block.vtx.size() - 1) : 0));
    ret_all.pushKV("avgfeerate", ValueFromAmount(total_size ? totalfee / total_size : 0)); // Unit: sat/byte
    ret_all.pushKV("avgtxsize", (block.vtx.size() > 1) ? total_size / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("blockhash", pindex->GetBlockHash().GetHex());
    ret_all.pushKV("blocksize", pindex->GetBlockSize());
    ret_all.pushKV("nextmaxblocksize", pindex->GetNextMaxBlockSize());
    ret_all.pushKV("feerate_percentiles", feerates_res);
    ret_all.pushKV("height", (int64_t)pindex->height());
    ret_all.pushKV("ins", inputs);
    ret_all.pushKV("maxfee", ValueFromAmount(maxfee));
    ret_all.pushKV("maxfeerate", ValueFromAmount(maxfeerate));
    ret_all.pushKV("maxtxsize", maxtxsize);
    ret_all.pushKV("medianfee", ValueFromAmount(CalculateTruncatedMedian(fee_array)));
    ret_all.pushKV("mediantime", pindex->GetMedianTimePast());
    ret_all.pushKV("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret_all.pushKV("minfee", ValueFromAmount((minfee == MAX_MONEY) ? 0 : minfee));
    ret_all.pushKV("minfeerate", ValueFromAmount((minfeerate == MAX_MONEY) ? 0 : minfeerate));
    ret_all.pushKV("mintxsize", mintxsize == std::numeric_limits<int64_t>::max() ? 0 : mintxsize);
    ret_all.pushKV("outs", outputs);
    {
        READLOCK(cs_mapBlockIndex);
        ret_all.pushKV("sequence_id", pindex->nSequenceId);
    }
    ret_all.pushKV("subsidy", ValueFromAmount(GetBlockSubsidy(pindex->height(), Params().GetConsensus())));
    ret_all.pushKV("time", pindex->GetBlockTime());
    {
        READLOCK(cs_mapBlockIndex);
        ret_all.pushKV("time_received", pindex->nTimeReceived);
    }
    ret_all.pushKV("total_out", ValueFromAmount(total_out));
    ret_all.pushKV("total_size", total_size);
    ret_all.pushKV("totalfee", ValueFromAmount(totalfee));
    ret_all.pushKV("txs", (int64_t)block.vtx.size());
    ret_all.pushKV("num_data_only", dataOutputs);
    ret_all.pushKV("utxo_increase", outputs - dataOutputs - inputs);
    ret_all.pushKV("utxo_size_inc", utxo_size_inc);

    if (do_all)
    {
        return ret_all;
    }

    UniValue ret(UniValue::VOBJ);
    for (const std::string &stat : stats)
    {
        const UniValue &value = ret_all[stat];
        if (value.isNull())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic %s", stat));
        }
        ret.pushKV(stat, value);
    }
    return ret;
}

UniValue savetxpool(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error("savetxpool\n"
                                 "\nDumps the txpool to disk.\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("savetxpool", "") + HelpExampleRpc("savetxpool", ""));
    }

    if (!DumpTxPool())
    {
        throw JSONRPCError(RPC_MISC_ERROR, "Unable to dump txpool to disk");
    }

    return NullUniValue;
}

UniValue saveorphanpool(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error("saveorphanpool\n"
                                 "\nDumps the orphanpool to disk.\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("saveorphanpool", "") + HelpExampleRpc("saveorphanpool", ""));
    }

    if (!orphanpool.DumpOrphanPool())
    {
        throw JSONRPCError(RPC_MISC_ERROR, "Unable to dump orphanpool to disk");
    }

    return NullUniValue;
}

UniValue getchaintxstats(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 2)
    {
        throw std::runtime_error(
            "getchaintxstats ( nblocks blockhash )\n"
            "\nCompute statistics about the total number and rate of transactions in the chain.\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, optional) Size of the window in number of blocks (default: one month).\n"
            "2. \"blockhash\"  (string, optional) The hash of the block that ends the window.\n"
            "\nResult:\n"
            "{\n"
            "  \"time\": xxxxx,        (numeric) The timestamp for the statistics in UNIX format.\n"
            "  \"window_final_block_hash\": \"...\",      (string) The hash of the final block in the window.\n"
            "  \"window_final_block_height\": xxxxx,    (numeric) The height of the final block in the window.\n"
            "  \"window_block_count\": xxxxx,           (numeric) Size of the window in number of blocks.\n"
            "  \"window_tx_count\": xxxxx,              (numeric) The number of transactions in the window. Only "
            "returned if \"window_block_count\" is > 0.\n"
            "  \"window_interval\": xxxxx,              (numeric) The elapsed time in the window in seconds. Only "
            "returned if \"window_block_count\" is > 0.\n"
            "  \"txcount\": xxxxx,     (numeric) The total number of transactions in the chain up to that point.\n"
            "  \"txrate\": x.xx,       (numeric) The average rate of transactions per second in the window.\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getchaintxstats", "") + HelpExampleRpc("getchaintxstats", "2016"));
    }
    const CBlockIndex *pindex;
    int blockcount = 30 * 24 * 60 * 60 / Params().GetConsensus().nPowTargetSpacing; // By default: 1 month

    if (params.size() > 0 && !params[0].isNull())
    {
        blockcount = params[0].get_int();
    }

    bool havehash = params.size() > 1 && !params[1].isNull();
    uint256 hash;
    if (havehash)
    {
        hash = uint256S(params[1].get_str());
    }

    {
        if (havehash)
        {
            {
                READLOCK(cs_mapBlockIndex);
                auto it = mapBlockIndex.find(hash);
                if (it == mapBlockIndex.end())
                {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
                pindex = it->second;
            }
            if (!chainActive.Contains(pindex))
            {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
            }
        }
        else
        {
            pindex = chainActive.Tip();
        }
    }

    DbgAssert(pindex != nullptr, throw std::runtime_error(__func__));

    if (blockcount < 1 || blockcount >= pindex->height())
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 1 and the block's height");
    }

    const CBlockIndex *pindexPast = pindex->GetAncestor(pindex->height() - blockcount);
    int nTimeDiff = pindex->GetMedianTimePast() - pindexPast->GetMedianTimePast();
    int nTxDiff = pindex->nChainTx - pindexPast->nChainTx;

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pindex->time());
    ret.pushKV("txcount", (int64_t)pindex->nChainTx);
    ret.pushKV("txrate", ((double)nTxDiff) / nTimeDiff);
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_final_block_height", pindex->height());
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0)
    {
        ret.pushKV("window_tx_count", nTxDiff);
        ret.pushKV("window_interval", nTimeDiff);
        if (nTimeDiff > 0)
        {
            ret.pushKV("txrate", ((double)nTxDiff) / nTimeDiff);
        }
    }
    return ret;
}


//! Search for a given set of pubkey scripts
bool FindGroupTokenID(std::atomic<int> &scan_progress,
    const std::atomic<bool> &should_abort,
    int64_t &count,
    CCoinsViewCursor *cursor,
    const CGroupTokenID &needle,
    std::map<COutPoint, Coin> &out_results)
{
    scan_progress = 0;
    count = 0;
    while (cursor->Valid())
    {
        COutPoint key;
        Coin coins;
        if (!cursor->GetKey(key) || !cursor->GetValue(coins))
            return false;

        const CTxOut &out = coins.out;
        if (!out.IsNull())
        {
            if (++count % 8192 == 0)
            {
                boost::this_thread::interruption_point();
                if (should_abort)
                {
                    // allow to abort the scan via the abort reference
                    return false;
                }
            }
            if (count % 256 == 0)
            {
                // update progress reference every 256 item
                uint32_t high = 0x100 * *key.hash.begin() + *(key.hash.begin() + 1);
                scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
            }
            CGroupTokenInfo tokenGrp(out.scriptPubKey);
            // must be sitting in any group address
            if ((tokenGrp.associatedGroup != NoGroup) && !tokenGrp.isAuthority() && tokenGrp.associatedGroup == needle)
            {
                out_results.emplace(key, coins);
            }
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::mutex g_utxosetscan;
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve;

public:
    explicit CoinsViewScanReserver() : m_could_reserve(false) {}
    bool reserve()
    {
        assert(!m_could_reserve);
        std::lock_guard<std::mutex> lock(g_utxosetscan);
        if (g_scan_in_progress)
        {
            return false;
        }
        g_scan_in_progress = true;
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver()
    {
        if (m_could_reserve)
        {
            std::lock_guard<std::mutex> lock(g_utxosetscan);
            g_scan_in_progress = false;
        }
    }
};

enum class OutputScriptType
{
    UNKNOWN,
    P2PK,
    P2PKH,
    P2SH_P2WPKH,
    P2WPKH
};

#ifdef ENABLE_WALLET

UniValue scantokens(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "scantokens <action> ( <scanobjects> )\n"
            "\nScans the unspent transaction output set for possible entries that belong to a specified token group.\n"
            "\nArguments:\n"
            "1. \"action\"                     (string, required) The action to execute\n"
            "                                      \"start\" for starting a scan\n"
            "                                      \"abort\" for aborting the current scan (returns true when abort "
            "was successful)\n"
            "                                      \"status\" for progress report (in %) of the current scan\n"
            "2. \"tokenGroupID\"               (string, optional) Token group identifier\n"
            "\n"
            "\nResult:\n"
            "{\n"
            "  \"unspents\": [\n"
            "    {\n"
            "    \"txid\" : \"transactionid\",   (string) The transaction id\n"
            "    \"vout\" : n,                 (numeric) the vout value\n"
            "    \"address\" : \"address\",      (string) the address that received the tokens\n"
            "    \"scriptPubKey\" : \"script\",  (string) the script key\n"
            "    \"tokenAmount\" : xxx,       (numeric) The total token amount of the unspent output\n"
            "    \"height\" : n,               (numeric) Height of the unspent transaction output\n"
            "   }\n"
            "   ,...], \n"
            " \"totalAmount\" : xxx,          (numeric) The total token amount of all found unspent outputs\n"
            "]\n");

    RPCTypeCheck(params, {UniValue::VSTR, UniValue::VSTR});

    UniValue result(UniValue::VOBJ);
    if (params[0].get_str() == "status")
    {
        CoinsViewScanReserver reserver;
        if (reserver.reserve())
        {
            // no scan in progress
            return NullUniValue;
        }
        result.pushKV("progress", g_scan_progress);
        return result;
    }
    else if (params[0].get_str() == "abort")
    {
        CoinsViewScanReserver reserver;
        if (reserver.reserve())
        {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    }
    else if (params[0].get_str() == "start")
    {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        CAmount total_in = 0;

        if (!params[1].isStr())
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No token group ID specified");
        }

        CGroupTokenID needle = DecodeGroupToken(params[1].get_str());
        if (!needle.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid group specified");
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        g_scan_progress = 0;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        {
            LOCK(cs_main);
            FlushStateToDisk();
            pcursor = std::unique_ptr<CCoinsViewCursor>(pcoinsdbview->Cursor());
            assert(pcursor);
        }
        bool res = FindGroupTokenID(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needle, coins);
        result.pushKV("success", res);
        result.pushKV("searchedItems", count);

        for (const auto &it : coins)
        {
            const COutPoint &outpoint = it.first;
            const Coin &coin = it.second;
            const CTxOut &txo = coin.out;
            const CGroupTokenInfo &tokenGroupInfo = CGroupTokenInfo(txo.scriptPubKey);
            CTxDestination dest;
            ExtractDestination(txo.scriptPubKey, dest);

            input_txos.push_back(txo);
            total_in += tokenGroupInfo.quantity;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("outpoint", outpoint.hash.GetHex());
            if (IsValidDestination(dest))
            {
                unspent.pushKV("address", EncodeDestination(dest));
            }
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey.begin(), txo.scriptPubKey.end()));
            unspent.pushKV("amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("satoshis", txo.nValue);
            unspent.pushKV("tokenAmount", tokenGroupInfo.quantity);
            unspent.pushKV("height", (int32_t)coin.nHeight);

            unspents.push_back(unspent);
        }

        result.pushKV("unspents", unspents);
        result.pushKV("totalAmount", total_in);
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid command");
    }
    return result;
}

#endif

static const CRPCCommand commands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    {"blockchain", "getblockchaininfo", &getblockchaininfo, true},
    {"blockchain", "getchaintxstats", &getchaintxstats, true},
    {"blockchain", "getbestblockhash", &getbestblockhash, true},
    {"blockchain", "getblockcount", &getblockcount, true},
    {"blockchain", "getblock", &getblock, true},
    {"blockchain", "getblockhash", &getblockhash, true},
    {"blockchain", "getblockheader", &getblockheader, true},
    {"blockchain", "getchaintips", &getchaintips, true},
    {"blockchain", "getdifficulty", &getdifficulty, true},
    {"blockchain", "gettxpoolancestors", &gettxpoolancestors, true},
    {"blockchain", "gettxpooldescendants", &gettxpooldescendants, true},
    {"blockchain", "gettxpoolentry", &gettxpoolentry, true},
    {"blockchain", "gettxpoolinfo", &gettxpoolinfo, true},
    {"blockchain", "getorphanpoolinfo", &getorphanpoolinfo, true},
    {"blockchain", "evicttransaction", &evicttransaction, true},
    {"blockchain", "getrawtxpool", &getrawtxpool, true},
    {"blockchain", "getrawtxpoolbyid", &getrawtxpoolbyid, true},
    {"blockchain", "getraworphanpool", &getraworphanpool, true},
    {"blockchain", "gettxout", &gettxout, true},
    {"blockchain", "gettxoutsetinfo", &gettxoutsetinfo, true},
    {"blockchain", "savetxpool", &savetxpool, true},
    {"blockchain", "saveorphanpool", &saveorphanpool, true},
    {"blockchain", "verifychain", &verifychain, true},
    {"blockchain", "getblockstats", &getblockstats, true},
#ifdef ENABLE_WALLET
    {"blockchain", "scantokens", &scantokens, true},
#endif
    /* Not shown in help */
    {"hidden", "invalidateblock", &invalidateblock, true},
    {"hidden", "reconsiderblock", &reconsiderblock, true},
    {"hidden", "rollbackchain", &rollbackchain, true},
    {"hidden", "reconsidermostworkchain", &reconsidermostworkchain, true},
    {"hidden", "finalizeblock", &finalizeblock, true},
    {"hidden", "getfinalizedblockhash", &getfinalizedblockhash, true},
};

void RegisterBlockchainRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}
