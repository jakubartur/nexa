// Copyright (c) 2015 G. Andrew Stone
// Copyright (c) 2016-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_UNLIMITED_H
#define NEXA_UNLIMITED_H

#include "blockrelay/thinblock.h"
#include "chain.h"
#include "checkqueue.h"
#include "coins.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "leakybucket.h"
#include "net.h"
#include "script/script_error.h"
#include "stat.h"
#include "tweak.h"
#include "txmempool.h"
#include "univalue/include/univalue.h"
#include "validation/forks.h"

#include <list>
#include <thread>
#include <vector>

enum
{
    TYPICAL_BLOCK_SIZE = DEFAULT_NEXT_MAX_BLOCK_SIZE, // used for initial buffer size
    DEFAULT_COINBASE_RESERVE_SIZE = 1000,
    MAX_COINBASE_SCRIPTSIG_SIZE = 100,
    DEFAULT_CHECKPOINT_DAYS =
        30, // Default for the number of days in the past we check scripts during initial block download

    MAX_HEADER_REQS_DURING_IBD = 3,
    // if the blockchain is this far (in seconds) behind the current time, only request headers from a single
    // peer.  This makes IBD more efficient.
    SINGLE_PEER_REQUEST_MODE_AGE = (24 * 60 * 60),

    // How many blocks from tip do we consider than chain to be "nearly" synced.
    DEFAULT_BLOCKS_FROM_TIP = 2,
};

class CBlock;
class CBlockIndex;
class CValidationState;
struct CDiskBlockPos;
class CNode;
class CNodeRef;
class CChainParams;

/** Add or remove a string to indicate ongoing status */
class CStatusString
{
    mutable CCriticalSection cs_status_string;
    std::set<std::string> strSet;

public:
    void Set(const std::string &yourStatus);
    void Clear(const std::string &yourStatus);

    std::string GetPrintable() const;
};

extern CStatusString statusStrings;

extern std::set<CBlockIndex *> setDirtyBlockIndex;
extern uint32_t blockVersion; // Overrides the mined block version if non-zero

// Fork configuration
/** This specifies the MTP time of the next fork */
extern uint64_t nMiningForkTime;

/** BU Default maximum number of Outbound connections to simultaneously allow*/
extern int nMaxOutConnections;

// BU005: Strings specific to the config of this client that should be communicated to other clients
extern std::vector<std::string> BUComments;
extern std::string minerComment; // An arbitrary field that miners can change to annotate their blocks

// The number of days in the past we check scripts during initial block download
extern CTweak<uint64_t> checkScriptDays;

// Allow getblocktemplate to succeed even if this node chain tip blocks are old or this node is not connected
extern CTweak<bool> unsafeGetBlockTemplate;

// Let node operators to use another set of network magic bits
extern CTweak<uint32_t> netMagic;

// The maximum number of allowed script operations (consensus param)
extern CTweakRef<uint64_t> maxSatoScriptOpsTweak;

// The maximum number of allowed script operations (consensus param)
extern CTweakRef<uint64_t> maxScriptTemplateOpsTweak;

// The maximum number of allowed sigcheck operations (consensus param)
extern CTweak<uint64_t> maxSigChecks;

// print out a configuration warning during initialization
// bool InitWarning(const std::string &str);

// Replace Core's ComputeBlockVersion
int32_t UnlimitedComputeBlockVersion(const CBlockIndex *pindexPrev, const Consensus::Params &params, uint32_t nTime);

// This API finds a near match to the specified IP address, for example you can
// leave the port off and it will find the first match to the IP.
// The function also allows * or ? wildcards.
// This is useful for the RPC calls.
// Returns the first node that matches.
extern CNodeRef FindLikelyNode(const std::string &addrName);

// Convert a list of client comments (typically BUcomments) and a custom comment into a string appropriate for the
// coinbase txn
// The coinbase size restriction is NOT enforced
extern std::string FormatCoinbaseMessage(const std::vector<std::string> &comments, const std::string &customComment);

extern void UnlimitedSetup(void);
extern void UnlimitedCleanup(void);
extern std::string UnlimitedCmdLineHelp();

// Called whenever a new block is accepted
extern void UnlimitedAcceptBlock(const CBlock &block,
    CValidationState &state,
    CBlockIndex *ppindex,
    CDiskBlockPos *dbp);

extern void UnlimitedLogBlock(const CBlock &block, const std::string &hash, uint64_t receiptTime);

// Given an invalid block, find all chains containing this block and mark all children invalid
void MarkAllContainingChainsInvalid(CBlockIndex *invalidBlock);


// RPC calls

// RPC Get a particular tweak
extern UniValue settweak(const UniValue &params, bool fHelp);
// RPC Set a particular tweak
extern UniValue gettweak(const UniValue &params, bool fHelp);

extern UniValue settrafficshaping(const UniValue &params, bool fHelp);
extern UniValue gettrafficshaping(const UniValue &params, bool fHelp);
extern UniValue pushtx(const UniValue &params, bool fHelp);

extern UniValue getminingmaxblock(const UniValue &params, bool fHelp);
extern UniValue setminingmaxblock(const UniValue &params, bool fHelp);

// Get and set the custom string that miners can place into the coinbase transaction
extern UniValue getminercomment(const UniValue &params, bool fHelp);
extern UniValue setminercomment(const UniValue &params, bool fHelp);

// Get and set the generated (mined) block version.  USE CAREFULLY!
extern UniValue getblockversion(const UniValue &params, bool fHelp);
extern UniValue setblockversion(const UniValue &params, bool fHelp);

// RPC Return a list of all available statistics
extern UniValue getstatlist(const UniValue &params, bool fHelp);
// RPC Get a particular statistic
extern UniValue getstat(const UniValue &params, bool fHelp);

// RPC debugging Get sizes of every data structure
extern UniValue getstructuresizes(const UniValue &params, bool fHelp);

// RPC Set a node to receive expedited blocks from
UniValue expedited(const UniValue &params, bool fHelp);
// RPC display all variant forms of an address
UniValue getaddressforms(const UniValue &params, bool fHelp);
// These variables for traffic shaping need to be globally scoped so the GUI and CLI can adjust the parameters
extern CLeakyBucket receiveShaper;
extern CLeakyBucket sendShaper;

// Test to determine if traffic shaping is enabled
extern bool IsTrafficShapingEnabled();

// Check whether we are doing an initial block download (synchronizing from disk or network)
extern bool IsInitialBlockDownload();
extern void IsInitialBlockDownloadInit(bool *fInit = nullptr);

// Check whether we are nearly sync'd.  Used primarily to determine whether an xthin can be retrieved.
extern bool IsChainNearlySyncd();
extern bool IsChainSyncd();
extern void IsChainNearlySyncdInit();
extern void IsChainNearlySyncdSet(bool fSync);

// BUIP010 Xtreme Thinblocks: begin
// Xpress Validation: begin
// Transactions that have already been accepted into the memory pool do not need to be
// re-verified and can avoid having to do a second and expensive CheckInputs() when
// processing a new block.  (Protected by cs_xval)
extern std::set<uint256> setPreVerifiedTxHash;

// Orphans that are added to the thinblock must be verifed since they have never been
// accepted into the memory pool.  (Protected by cs_xval)
extern std::set<uint256> setUnVerifiedOrphanTxHash;

extern CCriticalSection cs_xval;
// Xpress Validation: end

extern void LoadFilter(CNode *pfrom, CBloomFilter *filter);

extern CSemaphore *semOutboundAddNode;
extern CStatHistory<uint64_t> recvAmt;
extern CStatHistory<uint64_t> sendAmt;
extern CStatHistory<uint64_t> nTxValidationTime;
extern CStatHistory<uint64_t> nBlockValidationTime;
extern CCriticalSection cs_blockvalidationtime;

// Connection Slot mitigation - used to track connection attempts and evictions
struct ConnectionHistory
{
    double nConnections; // number of connection attempts made within 1 minute
    int64_t nLastConnectionTime; // the time the last connection attempt was made

    double nEvictions; // number of times a connection was de-prioritized and disconnected in last 30 minutes
    int64_t nLastEvictionTime; // the time the last eviction occurred.

    std::string userAgent;
};
extern std::map<CNetAddr, ConnectionHistory> mapInboundConnectionTracker;
extern CCriticalSection cs_mapInboundConnectionTracker;

// statistics
void UpdateSendStats(CNode *pfrom, const char *strCommand, int msgSize, int64_t nTime);

void UpdateRecvStats(CNode *pfrom, const std::string &strCommand, int msgSize, int64_t nStopwatchTimeReceived);
// txn mempool statistics
extern CStatHistory<unsigned int> txAdded;
extern CStatHistory<uint64_t, MinValMax<uint64_t> > poolSize;

// Configuration variable validators
std::string OutboundConnectionValidator(const int &value, int *item, bool validate);
std::string SubverValidator(const std::string &value, std::string *item, bool validate);
// validator for the voting tweak
std::string Bip135VoteValidator(const std::string &value, std::string *item, bool validate);
// ensure that only 1 fork is active
std::string ForkTimeValidator(const uint64_t &value, uint64_t *item, bool validate);

extern CTweak<uint64_t> coinbaseReserve;
extern CTweak<uint64_t> miningBlockSize;
extern CTweak<uint64_t> maxMiningCandidates;
extern CTweak<uint64_t> minMiningCandidateInterval;
extern CTweakRef<uint32_t> miningEnforceOpGroup;
extern CTweakRef<bool> miningForkOpGroupTweak;

extern std::list<CStatBase *> mallocedStats;

/**  Parallel Block Validation - begin **/

extern CCriticalSection cs_blockvalidationthread;
void InterruptBlockValidationThreads();


/** Convert a string to lowercase (in place) */
void makeLowercase(std::string &input);


// Fork configuration
/** This specifies the MTP time of the next fork */
extern CTweakRef<uint64_t> miningForkTime;

// Mining-Candidate start
/** Return a Merkle root given a Coinbase hash and Merkle proof */
uint256 CalculateMerkleRoot(uint256 &coinbase_hash, const std::vector<uint256> &merkleProof);
/** Return Merkle branches for a Block */
std::vector<uint256> GetMerkleProofBranches(CBlock *pblock);

/** Keep track of mining candidates */
class CMiningCandidate
{
public:
    bool localCoinbase = false; // Did this wallet produce the coinbase (is so we can reuse candidates)
    uint64_t creationTime = 0;
    uint64_t id = 0;
    CBlockRef block;
};
extern CCriticalSection csMiningCandidates;

extern std::map<int64_t, CMiningCandidate> miningCandidatesMap;

class MinerTracker
{
public:
    int64_t lastRequest = 0; // in epoch seconds

    MinerTracker() {}
    MinerTracker(int64_t lr) : lastRequest(lr) {}
};

extern CStatHistory<uint64_t> miningBlocks; //("mining/blocks");
extern CStatHistory<uint64_t> miningOrphanBlocks; //("mining/orphans");
extern CStatHistory<uint64_t, MinValMax<uint64_t> > miningNumMiners; //("mining/miners");
extern CCriticalSection csMinerTracker;
extern std::map<std::string, MinerTracker> minerTracker GUARDED_BY(csMinerTracker);


#endif
