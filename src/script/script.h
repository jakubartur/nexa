// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_SCRIPT_H
#define NEXA_SCRIPT_SCRIPT_H

#include "crypto/common.h"
#include "prevector.h"
#include "script/script_error.h"
#include "script/stackitem.h"
#include "uint256.h"

#include <assert.h>
#include <climits>
#include <limits>
#include <memory>
#include <stdexcept>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include <optional>

/* Notes on the limits of the script template system:

In the old style, the prevout holds the script, not the current tx. This allows an attack where a single transaction
"gathers" a huge number of large scripts from prevouts. What is the maximum executable script bytes per transaction
within the old style?

An old CTxIn is 32+4 (prevout) + 0 (script) + 4 + 8 = 48 bytes at a minimum. Worst case this means
(max tx size)/(TxIn size) or 1000000/48 = 20833 possible inputs.

The old max script size is 10000 bytes. Multiplying this by the possible inputs results in a maximum of 208,330,000
executed script bytes per tx. (Since a single 1MB transaction is the densest way to gather prevouts, this number is
also the densest script byte execution per MB of block).

Using script templates, executed script bytes are located in the transaction that executes them (caveat: with the
exception of the push-only constraint "scripts" which must be limited to 1000 pushes due to the max stack size, and
256 inputs due to the recently added max vin limitation. But for a tx that doesn't immediately fail, each push must
be accompanied by an op_drop in the script template due to the clean stack rule, so constraint script pushes still
must have a proportional consumption of bytes (a bunch of OP_DROP instructions) located in this transaction). This
means that the maximum executed script bytes is approximately the maximum transaction size, or 1,000,000 bytes.

In other words, the using the script template system, the maximum executable instructions per transaction is 0.5% of
the old way.

So no limits on script template size is really needed, since the transaction size limit is sufficient constraint.
A max size of 100000 bytes and 50000 non-push opcodes was chosen as an initial limit out of an abundance of caution.
*/

// Maximum number of bytes pushable to the stack
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;

// Maximum number of non-push operations per script
static const int MAX_OPS_PER_SCRIPT = 201;

// Maximum number of non-push operations per script
static const int MAX_OPS_PER_SCRIPT_TEMPLATE = 50000;

// 2020-05-15 sigchecks consensus rule
// Maximum number of signature check operations per transaction
static const int MAX_SIGOPS_PER_TRANSACTION = 3000;

// Maximum number of public keys per multisig
static const int MAX_PUBKEYS_PER_MULTISIG = 20;

// Maximum script length in bytes
static const int MAX_SCRIPT_SIZE = 10000;

// Maximum template script length in bytes
static const int MAX_SCRIPT_TEMPLATE_SIZE = 100000;

// Maximum number of values on script interpreter stack
static const int MAX_STACK_SIZE = 1000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

// Maximum OP_EXEC recursion level
const unsigned int MAX_EXEC_DEPTH = 3;
// Maximum OP_EXEC calls in a script execution (including in subscripts)
const unsigned int MAX_OP_EXEC = 20;


template <typename T>
std::vector<uint8_t> ToByteVector(const T &in)
{
    return std::vector<uint8_t>(in.begin(), in.end());
}

/** Script opcodes */
enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SPLIT = 0x7f, // after May 15, 2018 upgrade
    OP_NUM2BIN = 0x80, // after May 15, 2018 upgrade
    OP_BIN2NUM = 0x81, // after May 15, 2018 upgrade
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // More crypto
    OP_CHECKDATASIG = 0xba,
    OP_CHECKDATASIGVERIFY = 0xbb,

    // additional byte string operations
    OP_REVERSEBYTES = 0xbc,

    // gitlab.com/GeneralProtocols/research/chips/-/blob/master/CHIP-2021-02-Add-Native-Introspection-Opcodes.md (TODO:
    // link to reference.cash)
    // Transaction Introspection Opcodes: see https:

    // (192) Push the index of the input being evaluated to the stack as a Script Number
    OP_INPUTINDEX = 0xc0,
    // (193) Push the full bytecode currently being evaluated to the stack1. For Pay-to-Script-Hash (P2SH)
    // evaluations, this is the redeem bytecode of the Unspent Transaction Output (UTXO) being spent; for all
    // other evaluations, this is the locking bytecode of the UTXO being spent.  Note HASH160 this to get the
    // hash stored in the P2SH constraint script
    OP_ACTIVEBYTECODE = 0xc1,
    // (194) Push the version of the current transaction to the stack as a Script Number
    OP_TXVERSION = 0xc2,
    // (195) Push the count of inputs in the current transaction to the stack as a Script Number.
    OP_TXINPUTCOUNT = 0xc3,
    // (196) Push the count of outputs in the current transaction to the stack as a Script Number.
    OP_TXOUTPUTCOUNT = 0xc4,
    // (197) Push the locktime of the current transaction to the stack as a Script Number.
    OP_TXLOCKTIME = 0xc5,
    // (198) Pop the top item from the stack as an input index (Script Number). Push the value (in satoshis)
    // of the Unspent Transaction Output (UTXO) spent by that input to the stack as a Script Number.
    OP_UTXOVALUE = 0xc6,
    // (199) Pop the top item from the stack as an input index (Script Number). Push the full locking bytecode of the
    // Unspent Transaction Output (UTXO) spent by that input to the stack.
    OP_UTXOBYTECODE = 0xc7,
    // (200) Pop the top item from the stack as an input index (Script Number). From that input, push the outpoint
    // transaction hash - the hash of the transaction which created the Unspent Transaction Output (UTXO) which is being
    // spent - to the stack in OP_HASH256 byte order1.
    OP_OUTPOINTHASH = 0xc8,
    // (202) Pop the top item from the stack as an input index (Script Number). Push the unlocking bytecode of the input
    // at that index to the stack.
    OP_INPUTBYTECODE = 0xca,
    // (203) Pop the top item from the stack as an input index (Script Number). Push the sequence number of the input at
    // that index to the stack as a Script Number.
    OP_INPUTSEQUENCENUMBER = 0xcb,
    // (204) Pop the top item from the stack as an output index (Script Number). Push the value (in satoshis) of the
    // output at that index to the stack as a Script Number.
    OP_OUTPUTVALUE = 0xcc,
    // (205) Pop the top item from the stack as an output index (Script Number). Push the locking bytecode of the output
    // at that index to the stack.
    OP_OUTPUTBYTECODE = 0xcd,
    // 206
    OP_NATIVE_INTROSPECTION_RESERVED1 = 0xce,
    // 207
    OP_NATIVE_INTROSPECTION_RESERVED2 = 0xcf,

    // NEXA opcodes
    OP_PLACE = 0xe9,
    OP_PUSH_TX_STATE = 0xea,
    OP_SETBMD = 0xeb,
    OP_BIN2BIGNUM = 0xec,
    OP_EXEC = 0xed,
    // The first op_code value after all defined opcodes
    FIRST_UNDEFINED_OP_VALUE,

    OP_INVALIDOPCODE = 0xff,
};

const char *GetOpName(opcodetype opcode);

/**
 * Check whether the given stack element data would be minimally pushed using
 * the given opcode.
 */
bool CheckMinimalPush(const std::vector<uint8_t> &data, opcodetype opcode);

struct scriptnum_error : std::runtime_error
{
    ScriptError errNum;
    explicit scriptnum_error(ScriptError errnum, const std::string &str) : std::runtime_error(str), errNum(errnum) {}
};

class CScriptNum
{
    /**
     * Pre May2022 Hardfork semantics:
     * Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte
     * integers. The semantics are subtle, though: operands must be in the range
     * [-2^31 + 1, 2^31 - 1], but results may overflow (and are valid as long as
     * they are not used in a subsequent numeric operation). CScriptNum enforces
     * those semantics by storing results as an int64 and allowing out-of-range
     * values to be returned as a vector of bytes but throwing an exception if
     * arithmetic is done or the result is interpreted as an integer.
     *
     * Post May2022 Hardfork semantics:
     * Arithmetic opcodes (OP_1ADD, etc) are restricted to operating on 8-byte signed integers.
     * Negative integers are encoding using sign and magnitude, so operands must be in the range
     * [-2^63 + 1, 2^63 - 1].
     * Arithmetic operators throw an exception if overflow is detected.
     */
protected:
    int64_t _value;

public:
    static constexpr size_t MAXIMUM_ELEMENT_SIZE_32_BIT = 4;
    static constexpr size_t MAXIMUM_ELEMENT_SIZE_64_BIT = 8;

    typedef std::optional<CScriptNum> ScriptNumResult;

private:
    static int64_t set_vch(const std::vector<uint8_t> &vch)
    {
        if (vch.empty())
        {
            return 0;
        }
        int64_t result = 0;
        for (size_t i = 0; i != vch.size(); ++i)
        {
            result |= int64_t(vch[i]) << 8 * i;
        }
        // If the input vector's most significant byte is 0x80, remove it from
        // the result's msb and return a negative.
        if (vch.back() & 0x80)
        {
            return -int64_t(result & ~(0x80ULL << (8 * (vch.size() - 1))));
        }
        return result;
    }

protected:
    explicit constexpr CScriptNum(const int64_t &x) : _value(x) {}

    static constexpr bool valid64BitRange(int64_t x) { return x != std::numeric_limits<int64_t>::min(); }

public:
    explicit CScriptNum(const StackItem &vch, bool fRequireMinimal, const size_t nMaxNumSize)
        : CScriptNum(vch.data(), fRequireMinimal, nMaxNumSize)
    {
    }

    explicit CScriptNum(const std::vector<uint8_t> &vch, bool fRequireMinimal, const size_t nMaxNumSize)
    {
        if (vch.size() > nMaxNumSize)
        {
            throw scriptnum_error(SCRIPT_ERR_NUMBER_OVERFLOW, "script number overflow");
        }
        if (fRequireMinimal && !IsMinimallyEncoded(vch, nMaxNumSize))
        {
            throw scriptnum_error(SCRIPT_ERR_NUMBER_BAD_ENCODING, "non-minimally encoded script number");
        }
        _value = set_vch(vch);
    }

    /**
     * Factory method to safely construct an instance from a raw int64_t.
     *
     * Note the unusual enforcement of the rules regarding valid 64-bit
     * ranges. We enforce a strict range of [INT64_MIN+1, INT64_MAX].
     */
    static ScriptNumResult fromInt(int64_t x) noexcept
    {
        if (!valid64BitRange(x))
        {
            return std::nullopt;
        }
        return CScriptNum(x);
    }

    /// Performance/convenience optimization: Construct an instance from a raw
    /// int64_t where the caller already knows that the supplied value is in range.
    static constexpr CScriptNum fromIntUnchecked(int64_t x) noexcept { return CScriptNum(x); }

    static bool IsMinimallyEncoded(const std::vector<uint8_t> &vch, size_t maxIntegerSize);

    static bool MinimallyEncode(std::vector<uint8_t> &data);

    constexpr bool operator==(int64_t x) const noexcept { return _value == x; }
    constexpr bool operator!=(int64_t x) const noexcept { return _value != x; }
    constexpr bool operator<=(int64_t x) const noexcept { return _value <= x; }
    constexpr bool operator<(int64_t x) const noexcept { return _value < x; }
    constexpr bool operator>=(int64_t x) const noexcept { return _value >= x; }
    constexpr bool operator>(int64_t x) const noexcept { return _value > x; }
    constexpr bool operator==(CScriptNum const &x) const noexcept { return operator==(x._value); }
    constexpr bool operator!=(CScriptNum const &x) const noexcept { return operator!=(x._value); }
    constexpr bool operator<=(CScriptNum const &x) const noexcept { return operator<=(x._value); }
    constexpr bool operator<(CScriptNum const &x) const noexcept { return operator<(x._value); }
    constexpr bool operator>=(CScriptNum const &x) const noexcept { return operator>=(x._value); }
    constexpr bool operator>(CScriptNum const &x) const noexcept { return operator>(x._value); }

    // Arithmetic operations
    ScriptNumResult safeAdd(int64_t x) const noexcept
    {
        const bool overflow = __builtin_add_overflow(_value, x, &x);
        if (overflow)
        {
            return std::nullopt;
        }
        return fromInt(x);
    }

    ScriptNumResult safeAdd(CScriptNum const &x) const noexcept { return safeAdd(x._value); }

    ScriptNumResult safeSub(int64_t x) const noexcept
    {
        const bool overflow = __builtin_sub_overflow(_value, x, &x);
        if (overflow)
        {
            return std::nullopt;
        }
        return fromInt(x);
    }

    ScriptNumResult safeSub(CScriptNum const &x) const noexcept { return safeSub(x._value); }

    ScriptNumResult safeMul(int64_t x) const noexcept
    {
        const bool overflow = __builtin_mul_overflow(_value, x, &x);
        if (overflow)
        {
            return std::nullopt;
        }
        return fromInt(x);
    }

    ScriptNumResult safeMul(CScriptNum const &x) const noexcept { return safeMul(x._value); }

    constexpr CScriptNum operator/(int64_t x) const noexcept
    {
        if (x == -1 && !valid64BitRange(_value))
        {
            // Guard against overflow, which can't normally happen unless class is misused
            // by the fromIntUnchecked() factory method (may happen in tests).
            // This will return INT64_MIN which is what ARM & x86 does anyway for INT64_MIN / -1.
            return CScriptNum(_value);
        }
        return CScriptNum(_value / x);
    }

    constexpr CScriptNum operator/(CScriptNum const &x) const noexcept { return operator/(x._value); }

    constexpr CScriptNum operator%(int64_t x) const noexcept
    {
        if (x == -1 && !valid64BitRange(_value))
        {
            // INT64_MIN % -1 is UB in C++, but mathematically it would yield 0
            return CScriptNum(0);
        }
        return CScriptNum(_value % x);
    }

    constexpr CScriptNum operator%(CScriptNum const &x) const noexcept { return operator%(x._value); }

    // Bitwise operations
    ScriptNumResult safeBitwiseAnd(int64_t x) const noexcept
    {
        x = _value & x;
        return fromInt(x);
    }

    ScriptNumResult safeBitwiseAnd(CScriptNum const &x) const noexcept { return safeBitwiseAnd(x._value); }

    constexpr CScriptNum operator-() const noexcept
    {
        // Defensive programming: -INT64_MIN is undefined behaviour
        return CScriptNum(valid64BitRange(_value) ? -_value : _value);
    }

    constexpr int32_t getint32() const
    {
        if (_value > std::numeric_limits<int>::max())
        {
            return std::numeric_limits<int>::max();
        }
        else if (_value < std::numeric_limits<int>::min())
        {
            return std::numeric_limits<int>::min();
        }
        return _value;
    }
    constexpr int64_t getint64() const { return _value; }
    std::vector<uint8_t> getvch() const { return serialize(_value); }
    StackItem vchStackItem() const { return StackItem(serialize(_value)); }
    static std::vector<uint8_t> serialize(const int64_t &value)
    {
        if (value == 0)
        {
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> result;
        const bool neg = value < 0;
        uint64_t absvalue = neg && valid64BitRange(value) ? -value : value;

        while (absvalue)
        {
            result.push_back(absvalue & 0xff);
            absvalue >>= 8;
        }

        //    - If the most significant byte is >= 0x80 and the value is positive, push a
        //    new zero-byte to make the significant byte < 0x80 again.
        //    - If the most significant byte is >= 0x80 and the value is negative, push a
        //    new 0x80 byte that will be popped off when converting to an integral.
        //    - If the most significant byte is < 0x80 and the value is negative, add
        //    0x80 to it, since it will be subtracted and interpreted as a negative when
        //    converting to an integral.
        if (result.back() & 0x80)
        {
            result.push_back(neg ? 0x80 : 0);
        }
        else if (neg)
        {
            result.back() |= 0x80;
        }
        return result;
    }
};

/** wrapper class that serializes in an older way that is incompatible with current rules, but is used by the genesis
block */
class LegacyCScriptNum : public CScriptNum
{
public:
    explicit LegacyCScriptNum(const int64_t &n) : CScriptNum(n) {}
};

/**
 * We use a prevector for the script to reduce the considerable memory overhead
 *  of vectors in cases where they normally contain a small number of small elements.
 * Tests in October 2015 showed use of this reduced dbcache memory usage by 23%
 *  and made an initial sync 13% faster.
 */
typedef prevector<28, uint8_t> CScriptBase;

enum class ScriptType : uint8_t
{
    SATOSCRIPT = 0,
    TEMPLATE = 1,
    PUSH_ONLY = 2
};

/** Serialized script, used inside transaction inputs and outputs */
class CScript : public CScriptBase
{
protected:
    CScript &push_int64(int64_t n)
    {
        if (n == -1 || (n >= 1 && n <= 16))
        {
            push_back(n + (OP_1 - 1));
        }
        else if (n == 0)
        {
            push_back(OP_0);
        }
        else
        {
            *this << CScriptNum::serialize(n);
        }
        return *this;
    }

public:
    ScriptType type = ScriptType::SATOSCRIPT; // RAM only -- this type field is inferred by the container version.
    CScript() {}
    CScript(ScriptType typeIn) : type(typeIn) {}
    CScript(const_iterator pbegin, const_iterator pend) : CScriptBase(pbegin, pend) {}
    CScript(std::vector<uint8_t>::const_iterator pbegin, std::vector<uint8_t>::const_iterator pend)
        : CScriptBase(pbegin, pend)
    {
    }
    CScript(const uint8_t *pbegin, const uint8_t *pend) : CScriptBase(pbegin, pend) {}

    CScript(const StackItem &s) : CScriptBase(s.data().begin(), s.data().end())
    {
        // already called: s.requireType(StackElementType::VCH);
    }
    CScript &operator+=(const CScript &b)
    {
        reserve(size() + b.size());
        insert(end(), b.begin(), b.end());
        return *this;
    }

    friend CScript operator+(const CScript &a, const CScript &b)
    {
        CScript ret = a;
        ret += b;
        return ret;
    }

    CScript(int64_t b) { operator<<(b); }
    explicit CScript(opcodetype b) { operator<<(b); }
    explicit CScript(const CScriptNum &b) { operator<<(b); }
    explicit CScript(const std::vector<uint8_t> &b) { operator<<(b); }
    CScript &operator<<(int64_t b) { return push_int64(b); }
    CScript &operator<<(opcodetype opcode)
    {
        if (opcode < 0 || opcode > 0xff)
        {
            throw std::runtime_error("CScript::operator<<(): invalid opcode");
        }
        insert(end(), uint8_t(opcode));
        return *this;
    }

    CScript &operator<<(const CScriptNum &b)
    {
        *this << b.getvch();
        return *this;
    }

    void swap(CScript &other)
    {
        std::swap(type, other.type);
        CScriptBase::swap(other);
    }

    void serializeVector(const std::vector<uint8_t> &b)
    {
        if (b.size() < OP_PUSHDATA1)
        {
            insert(end(), (uint8_t)b.size());
        }
        else if (b.size() <= 0xff)
        {
            insert(end(), OP_PUSHDATA1);
            insert(end(), (uint8_t)b.size());
        }
        else if (b.size() <= 0xffff)
        {
            insert(end(), OP_PUSHDATA2);
            uint8_t data[2];
            WriteLE16(data, b.size());
            insert(end(), data, data + sizeof(data));
        }
        else
        {
            insert(end(), OP_PUSHDATA4);
            uint8_t data[4];
            WriteLE32(data, b.size());
            insert(end(), data, data + sizeof(data));
        }
        insert(end(), b.begin(), b.end());
    }

    CScript &operator<<(const LegacyCScriptNum &a)
    {
        auto b = a.getvch();
        serializeVector(b);
        return *this;
    }

    CScript &operator<<(const std::vector<uint8_t> &b)
    {
        if (b.size() == 0)
        {
            insert(end(), OP_0);
            return *this;
        }
        if ((b.size() == 1) && (b[0] >= 1 && b[0] <= 16))
        {
            insert(end(), OP_1 - 1 + b[0]);
            return *this;
        }
        else if ((b.size() == 1) && (b[0] == 0x81))
        {
            insert(end(), OP_1NEGATE);
            return *this;
        }

        serializeVector(b);
        return *this;
    }

    template <unsigned int BITS>
    CScript &operator<<(const base_blob<BITS> &data)
    {
        std::vector<unsigned char> v(data.begin(), data.end());
        *this << v;
        return *this;
    }

    bool GetOp(const_iterator &pcRet, opcodetype &opcodeRet, VchType &vchRet) const
    {
        StackItem data;
        const_iterator pc = pcRet;
        opcodeRet = OP_VER; // initialize this to something broken
        opcodetype opcode = opcodeRet;
        bool ret = GetOp2(pc, opcode, &data);
        vchRet = data.data(); // will throw if not a vch
        // If it didn't throw I can advance the pc
        pcRet = pc;
        opcodeRet = opcode;
        return ret;
    }

    bool GetOp(iterator &pc, opcodetype &opcodeRet, StackItem &vchRet)
    {
        // Wrapper so it can be called with either iterator or const_iterator
        const_iterator pc2 = pc;
        bool fRet = GetOp2(pc2, opcodeRet, &vchRet);
        pc = begin() + (pc2 - begin());
        return fRet;
    }

    bool GetOp(iterator &pc, opcodetype &opcodeRet)
    {
        const_iterator pc2 = pc;
        bool fRet = GetOp2(pc2, opcodeRet, nullptr);
        pc = begin() + (pc2 - begin());
        return fRet;
    }

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet, StackItem &vchRet) const
    {
        return GetOp2(pc, opcodeRet, &vchRet);
    }

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet) const { return GetOp2(pc, opcodeRet, nullptr); }
    bool GetOp2(const_iterator &pc, opcodetype &opcodeRet, StackItem *pvchRet) const
    {
        opcodeRet = OP_INVALIDOPCODE;
        if (pvchRet)
        {
            pvchRet->clear();
        }
        if (pc >= end())
        {
            return false;
        }

        // Read instruction
        if (end() - pc < 1)
        {
            return false;
        }
        uint32_t opcode = *pc++;

        // Immediate operand
        if (opcode <= OP_PUSHDATA4)
        {
            uint32_t nSize = 0;
            if (opcode < OP_PUSHDATA1)
            {
                nSize = opcode;
            }
            else if (opcode == OP_PUSHDATA1)
            {
                if (end() - pc < 1)
                {
                    return false;
                }
                nSize = *pc++;
            }
            else if (opcode == OP_PUSHDATA2)
            {
                if (end() - pc < 2)
                {
                    return false;
                }
                nSize = ReadLE16(&pc[0]);
                pc += 2;
            }
            else if (opcode == OP_PUSHDATA4)
            {
                if (end() - pc < 4)
                {
                    return false;
                }
                nSize = ReadLE32(&pc[0]);
                pc += 4;
            }
            if (end() - pc < 0 || uint32_t(end() - pc) < nSize)
            {
                return false;
            }
            if (pvchRet)
            {
                pvchRet->assign(pc, pc + nSize);
            }
            pc += nSize;
        }

        opcodeRet = (opcodetype)opcode;
        return true;
    }

    /** Encode/decode small integers: */
    static int DecodeOP_N(opcodetype opcode)
    {
        if (opcode == OP_0)
            return 0;
        assert(opcode >= OP_1 && opcode <= OP_16);
        return (int)opcode - (int)(OP_1 - 1);
    }
    static opcodetype EncodeOP_N(int n)
    {
        assert(n >= 0 && n <= 16);
        if (n == 0)
            return OP_0;
        return (opcodetype)(OP_1 + n - 1);
    }

    int FindAndDelete(const CScript &b)
    {
        int nFound = 0;
        if (b.empty())
            return nFound;
        CScript result;
        iterator pc = begin(), pc2 = begin();
        opcodetype opcode;
        do
        {
            result.insert(result.end(), pc2, pc);
            while (static_cast<size_t>(end() - pc) >= b.size() && std::equal(b.begin(), b.end(), pc))
            {
                pc = pc + b.size();
                ++nFound;
            }
            pc2 = pc;
        } while (GetOp(pc, opcode));

        if (nFound > 0)
        {
            result.insert(result.end(), pc2, end());
            *this = result;
        }

        return nFound;
    }
    /** Return the number of times this opcode is found in the script */
    int Find(opcodetype op) const
    {
        int nFound = 0;
        opcodetype opcode;
        for (const_iterator pc = begin(); pc != end() && GetOp(pc, opcode);)
            if (opcode == op)
                ++nFound;
        return nFound;
    }

    /**
     * Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
     * as 20 sigops. With pay-to-script-hash, that changed:
     * CHECKMULTISIGs serialized in scriptSigs are
     * counted more accurately, assuming they are of the form
     *  ... OP_N CHECKMULTISIG ...
     */
    unsigned int GetSigOpCount(const uint32_t flags, bool fAccurate) const;

    /**
     * Accurately count sigOps, including sigOps in
     * pay-to-script-hash transactions:
     */
    unsigned int GetSigOpCount(const uint32_t flags, const CScript &scriptSig) const;

    // if this is a p2sh then the script hash is filled into the passed param if its not null
    bool IsPayToScriptHash(std::vector<unsigned char> *hashBytes = nullptr) const;

    /** Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it consensus-critical). */
    bool IsPushOnly(const_iterator pc) const;
    bool IsPushOnly() const;

    /**
     * Returns whether the script is guaranteed to fail at execution,
     * regardless of the initial stack. This allows outputs to be pruned
     * instantly when entering the UTXO set.
     */
    bool IsUnspendable() const { return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE); }

    /** Set this script to a special value that is invalid -- any transaction including it will fail.
        This is used as a "false" return value, but it is better than (for instance) returning an empty script,
        since that is valid and spendable (by OP_1 as the satisfier).  */
    CScript &SetInvalid()
    {
        clear();
        *this << OP_INVALIDOPCODE;
        return *this;
    }

    /** Check whether this is the "canonical" invalid script */
    bool IsInvalid() { return *begin() == OP_INVALIDOPCODE; }

    /** Remove all instructions in this script. */
    void clear()
    {
        // The default prevector::clear() does not release memory
        CScriptBase::clear();
        shrink_to_fit();
    }

    std::string GetHex() const;
    std::string GetAsm() const;
};

class CReserveScript
{
public:
    CScript reserveScript;
    virtual void KeepScript() {}
    CReserveScript() {}
    virtual ~CReserveScript() {}
};

#endif // NEXA_SCRIPT_SCRIPT_H
