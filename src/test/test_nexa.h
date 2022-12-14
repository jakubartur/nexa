// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NEXA_TEST_NEXA_H
#define NEXA_TEST_NEXA_H

#include "chainparamsbase.h"
#include "fs.h"
#include "key.h"
#include "net.h"
#include "pubkey.h"
#include "random.h"
#include "script/interpreter.h"
#include "txdb.h"
#include "txmempool.h"

#include <thread>

extern FastRandomContext insecure_rand_ctx;

static inline void SetConnected(CNode &dummyNode)
{
    dummyNode.nVersion = MIN_PEER_PROTO_VERSION;
    dummyNode.tVersionSent = GetTime();
    dummyNode.fSuccessfullyConnected = true;
}

static inline void SeedInsecureRand(bool deterministic = false)
{
    insecure_rand_ctx = FastRandomContext(deterministic);
}

static inline uint32_t InsecureRand32() { return insecure_rand_ctx.rand32(); }
static inline uint256 InsecureRand256() { return insecure_rand_ctx.rand256(); }
static inline uint64_t InsecureRandBits(int bits) { return insecure_rand_ctx.randbits(bits); }
static inline uint64_t InsecureRandRange(uint64_t range) { return insecure_rand_ctx.randrange(range); }
static inline bool InsecureRandBool() { return insecure_rand_ctx.randbool(); }
static inline std::vector<unsigned char> InsecureRandBytes(size_t len) { return insecure_rand_ctx.randbytes(len); }

// Used when sorting transactions for placement in a block
struct NumericallyLessTxHashComparator
{
public:
    bool operator()(const CTransactionRef &a, const CTransactionRef &b) const { return a->GetId() < b->GetId(); }
};

/** Basic testing setup.
 * This just configures logging and chain parameters.
 */
struct BasicTestingSetup
{
    ECCVerifyHandle globalVerifyHandle;

    BasicTestingSetup(const std::string &chainName = CBaseChainParams::NEXA);
    ~BasicTestingSetup();
};

/** Testing setup that configures a complete environment.
 * Included are data directory, coins database, script check threads setup.
 */
struct TestingSetup : public BasicTestingSetup
{
    CCoinsViewDB *pcoinsdbview;
    fs::path pathTemp;
    boost::thread_group threadGroup;

    TestingSetup(const std::string &chainName = CBaseChainParams::NEXA);
    ~TestingSetup();
};

class CBlock;
struct CMutableTransaction;
class CScript;

//
// Testing fixture that pre-creates a
// 100-block REGTEST-mode block chain
//
struct TestChain100Setup : public TestingSetup
{
    TestChain100Setup();

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction> &txns, const CScript &scriptPubKey);

    ~TestChain100Setup();

public:
    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

class CTxMemPoolEntry;
class CTxMemPool;

struct TestMemPoolEntryHelper
{
    // Default values
    CAmount nFee;
    int64_t nTime;
    double dPriority;
    unsigned int nHeight;
    bool hadNoDependencies;
    bool spendsCoinbase;
    unsigned int sigOpCount;
    LockPoints lp;
    std::string dbgName;

    TestMemPoolEntryHelper()
        : nFee(0), nTime(0), dPriority(0.0), nHeight(1), hadNoDependencies(false), spendsCoinbase(false), sigOpCount(1)
    {
    }

    CTxMemPoolEntry FromTx(const CMutableTransaction &tx, CTxMemPool *pool = nullptr);
    CTxMemPoolEntry FromTx(const CTransaction &tx, CTxMemPool *pool = nullptr);

    // Change the default value
    TestMemPoolEntryHelper &Name(const std::string &_name)
    {
        dbgName = _name;
        return *this;
    }
    TestMemPoolEntryHelper &Fee(CAmount _fee)
    {
        nFee = _fee;
        return *this;
    }
    TestMemPoolEntryHelper &Time(int64_t _time)
    {
        nTime = _time;
        return *this;
    }
    TestMemPoolEntryHelper &Priority(double _priority)
    {
        dPriority = _priority;
        return *this;
    }
    TestMemPoolEntryHelper &Height(unsigned int _height)
    {
        nHeight = _height;
        return *this;
    }
    TestMemPoolEntryHelper &HadNoDependencies(bool _hnd)
    {
        hadNoDependencies = _hnd;
        return *this;
    }
    TestMemPoolEntryHelper &SpendsCoinbase(bool _flag)
    {
        spendsCoinbase = _flag;
        return *this;
    }
    TestMemPoolEntryHelper &SigOps(unsigned int _sigops)
    {
        sigOpCount = _sigops;
        return *this;
    }
};

// define an implicit conversion here so that uint256 may be used directly in BOOST_CHECK_*
std::ostream &operator<<(std::ostream &os, const uint256 &num);

CService ipaddress(uint32_t i, uint32_t port);

// Has a signature checker that returns false
class FalseScriptImportedState : public ScriptImportedState
{
public:
    BaseSignatureChecker checker;
    FalseScriptImportedState() : ScriptImportedState(&checker) {}
};

extern FalseScriptImportedState fsis;

// test block for unit tests. This returns a real block from the NEXA mainnet blockchain.
CBlock TestBlock1();

#endif // NEXA_TEST_NEXA_H
