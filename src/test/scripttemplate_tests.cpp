#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sighashtype.h"
#include "script/sign.h"
#include "test/scriptflags.h"
#include "test/test_bitcoin.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>
#include <fstream>
#include <stdint.h>
#include <string>
#include <univalue.h>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(scripttemplate_tests, BasicTestingSetup)

class AlwaysGoodSignatureChecker : public BaseSignatureChecker
{
public:
    AlwaysGoodSignatureChecker(unsigned int flags = SCRIPT_ENABLE_SIGHASH_FORKID) { nFlags = flags; }

    //! Verifies a signature given the pubkey, signature and sighash
    virtual bool VerifySignature(const std::vector<uint8_t> &vchSig,
        const CPubKey &vchPubKey,
        const uint256 &sighash) const
    {
        if (vchSig.size() > 0)
            return true;
        return false;
    }

    //! Verifies a signature given the pubkey, signature, script, and transaction (member var)
    virtual bool CheckSig(const std::vector<unsigned char> &scriptSig,
        const std::vector<unsigned char> &vchPubKey,
        const CScript &scriptCode) const
    {
        if (scriptSig.size() > 0)
            return true;
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const { return true; }
    virtual bool CheckSequence(const CScriptNum &nSequence) const { return true; }
    virtual ~AlwaysGoodSignatureChecker() {}
};

static uint256 hash256(const CScript &script) { return Hash(script.begin(), script.end()); }

std::vector<unsigned char> vch(const CScript &script) { return ToByteVector(script); }


BOOST_AUTO_TEST_CASE(verifytemplate)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;

    auto nogroup = OP_0;
    bool ret;

    {
        CScript templat = CScript() << OP_FROMALTSTACK << OP_SUB << OP_VERIFY;
        CScript templat2 = CScript() << OP_FROMALTSTACK << OP_ADD;
        CScript constraint = CScript() << OP_9;
        CScript satisfier = CScript() << OP_10;

        CScript badSatisfier = CScript() << OP_9;
        CScript badConstraint = CScript() << OP_10;

        ret = VerifyTemplate(templat, constraint, satisfier, flags, 100, 0, sis, &error, &tracker);
        BOOST_CHECK(ret == true);
        ret = VerifyTemplate(templat, constraint, badSatisfier, flags, 100, 0, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        ret = VerifyTemplate(templat, badConstraint, satisfier, flags, 100, 0, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        // Now wrap these scripts into scriptSig and scriptPubKeys

        // No args commitment
        CScript tmplVisArgs = (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << OP_0) + constraint;
        // Args commitment
        CScript tmplCmtArgs = CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(constraint);

        CScript scriptSigVisArgs = (CScript() << vch(templat)) + satisfier;
        CScript scriptSigCmtArgs = (CScript() << vch(templat) << vch(constraint)) + satisfier;

        CScript badScriptSigTemplate = (CScript() << vch(templat2)) + satisfier;

        CScript badScriptPubKey = (CScript() << hash256(templat)) + badConstraint;
        CScript badScriptSig = (CScript() << vch(templat)) + badSatisfier;

        ret = VerifyScript(scriptSigVisArgs, tmplVisArgs, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret == true);
        ret = VerifyScript(scriptSigCmtArgs, tmplCmtArgs, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret == true);

        ret = VerifyScript(badScriptSig, tmplVisArgs, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        ret = VerifyScript(badScriptSigTemplate, tmplVisArgs, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }

    {
        // 2 hashed args, 1 public
        // Add 3 numbers from the alt stack (constraint) and compare to the top of the main stack (satisfier)
        CScript templat = CScript() << OP_FROMALTSTACK << OP_FROMALTSTACK << OP_ADD << OP_FROMALTSTACK << OP_ADD
                                    << OP_EQUALVERIFY;
        CScript satisfier = CScript() << OP_10;
        CScript hashedArgs = CScript() << OP_2 << OP_4;
        CScript visArgs = CScript() << OP_4;

        CScript txin = (CScript() << vch(templat) << vch(hashedArgs)) + satisfier;
        CScript txout = (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(hashedArgs)) + visArgs;
        ret = VerifyScript(txin, txout, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret);
        // random incorrect txin script (doesn't contain the preimages)
        ret = VerifyScript(satisfier, txout, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }
}

BOOST_AUTO_TEST_CASE(largetemplate)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;

    auto nogroup = OP_0;
    bool ret;

    {
        CScript bigT = CScript() << OP_FROMALTSTACK << OP_SUB << OP_VERIFY;
        VchType blah(499);
        for (unsigned int i = 0; i < blah.size(); i++)
            blah[i] = i;
        CScript data = CScript() << blah << OP_DROP;
        for (unsigned int i = 0; i < 18; i++)
        {
            bigT += data;
        }

        CScript constraint = CScript() << OP_9;
        CScript satisfier = CScript() << OP_10;

        ret = VerifyTemplate(bigT, constraint, satisfier, flags, 100, 0, sis, &error, &tracker);
        BOOST_CHECK(ret == true);
    }
}


// show how the holder "injects" script constraints into a template via opexec and scripts-as-args
BOOST_AUTO_TEST_CASE(opexectemplate)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;
    auto nogroup = OP_0;
    bool ret;

    {
        // template compares 2 numbers (from constraint and satisfier) and if equal,
        // execute another rule provided by the constraint, which is that the satisfier pushed 8 on the stack

        CScript templat = CScript() << OP_FROMALTSTACK << OP_EQUALVERIFY << OP_FROMALTSTACK << OP_SWAP << OP_1 << OP_0
                                    << OP_EXEC;
        CScript satisfier = CScript() << OP_8 << OP_2;
        CScript incorrectSatisfier = CScript() << OP_7 << OP_2;
        CScript scriptArg = CScript() << OP_8 << OP_EQUALVERIFY;
        CScript hashedArgs = CScript() << vch(scriptArg) << OP_2;
        CScript visArgs = CScript();

        {
            CScript txin = (CScript() << vch(templat) << vch(hashedArgs)) + satisfier;
            CScript txout =
                (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(hashedArgs)) + visArgs;
            ret = VerifyScript(txin, txout, flags, 100, sis, &error, &tracker);
            BOOST_CHECK(ret);
        }

        // Tests that a VERIFY operation inside an op_exec-ed constraint script arg fails the entire script
        {
            CScript txin = (CScript() << vch(templat) << vch(hashedArgs)) + incorrectSatisfier;
            CScript txout =
                (CScript(ScriptType::TEMPLATE) << nogroup << hash256(templat) << hash256(hashedArgs)) + visArgs;
            ret = VerifyScript(satisfier, txout, flags, 100, sis, &error, &tracker);
            BOOST_CHECK(!ret);
        }
    }
}

BOOST_AUTO_TEST_CASE(opexec)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    AlwaysGoodSignatureChecker ck(flags);
    ScriptImportedState sis(&ck);
    ScriptError error;
    ScriptMachineResourceTracker tracker;
    bool ret;

    {
        CScript execed = CScript() << OP_ADD;
        CScript scriptSig = CScript() << vch(execed) << OP_4 << OP_6;
        CScript scriptPubKey = CScript() << OP_2 << OP_1 << OP_EXEC << OP_10 << OP_EQUAL;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret);

        ret = VerifyScript(CScript() << vch(execed) << OP_5 << OP_6, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript() << vch(execed) << OP_5, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript() << vch(execed), scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript(), scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);

        ret = VerifyScript(CScript() << OP_FALSE << OP_5 << OP_5, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        ret = VerifyScript(CScript() << vch(CScript() << OP_CHECKSIGVERIFY) << OP_5 << OP_5, scriptPubKey, flags, 100,
            sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }

    // Verify op_exec.md:T.o2 (empty script is valid)
    {
        CScript execed = CScript();
        CScript scriptSig = CScript() << vch(execed);
        CScript scriptPubKey = CScript() << OP_0 << OP_0 << OP_EXEC << OP_1;
        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret);
    }

    // Verify op_exec.md:T.L4
    {
        // This script simply pushes the parameters needed for the next op_exec so that the constraint script
        // can be 20 OP_EXEC in a row.
        CScript execed = CScript() << OP_DUP << OP_1 << OP_4;
        CScript scriptSig = CScript() << vch(execed);
        CScript scriptPubKeyOk = CScript() << OP_DUP << OP_1 << OP_4 << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                           << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                           << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                           << OP_EXEC << OP_EXEC << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_1;
        CScript scriptPubKeyNok = CScript()
                                  << OP_DUP << OP_1 << OP_4 << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                  << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                  << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC << OP_EXEC
                                  << OP_EXEC << OP_EXEC << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_1;
        ret = VerifyScript(scriptSig, scriptPubKeyOk, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret);

        ret = VerifyScript(scriptSig, scriptPubKeyNok, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_COUNT_EXCEEDED);
    }


    {
        CScript execed = CScript() << OP_1;
        CScript execedFalse = CScript() << OP_0;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_0 << OP_1 << OP_EXEC;
        CScript scriptPubKeyF = CScript() << vch(execedFalse) << OP_0 << OP_1 << OP_EXEC;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret);
        // execed script returns OP_O so script should fail because that false is left on the stack
        ret = VerifyScript(scriptSig, scriptPubKeyF, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
    }

    {
        CScript execed = CScript();
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_0 << OP_0 << OP_EXEC << OP_TRUE;
        CScript scriptPubKeyRet1 = CScript() << vch(execed) << OP_0 << OP_1 << OP_EXEC << OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret);

        // Expecting more returned data than the subscript provides
        ret = VerifyScript(scriptSig, scriptPubKeyRet1, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    {
        CScript execed = CScript() << OP_DUP << OP_0 << OP_0 << OP_EXEC;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_DUP << OP_0 << OP_0 << OP_EXEC;

        // script was expecting 1 param
        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    {
        CScript execed = CScript() << OP_DUP << OP_1 << OP_0 << OP_EXEC;
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() << vch(execed) << OP_DUP << OP_1 << OP_0 << OP_EXEC;

        // test that a recursive script fails
        ret = VerifyScript(scriptSig, scriptPubKey, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_DEPTH_EXCEEDED);
    }

    {
        // This script recursively calls itself the number of times passed as a parameter, and ends by pushing true to
        // the stack.
        CScript execed = CScript() << OP_DUP << OP_IF << OP_1 << OP_SUB << OP_SWAP << OP_TUCK << OP_2 << OP_1 << OP_EXEC
                                   << OP_ELSE << OP_1 << OP_ENDIF;
        CScript scriptSig = CScript();
        CScript scriptPubKey2 = CScript() << vch(execed) << OP_DUP << OP_2 << OP_SWAP << OP_2 << OP_1 << OP_EXEC;
        CScript scriptPubKey3 = CScript() << vch(execed) << OP_DUP << OP_3 << OP_SWAP << OP_2 << OP_1 << OP_EXEC;

        // test that the max recursion depth succeeds
        tracker.clear();
        ret = VerifyScript(scriptSig, scriptPubKey2, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(ret);
        // test that 1+max recursion depth fails
        tracker.clear();
        ret = VerifyScript(scriptSig, scriptPubKey3, flags, 100, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EXEC_DEPTH_EXCEEDED);

        // test that max operations can be exceeded
        ret = VerifyScript(scriptSig, scriptPubKey2, flags, 25, sis, &error, &tracker);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_OP_COUNT);
    }
}

BOOST_AUTO_TEST_SUITE_END()
