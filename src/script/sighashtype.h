// Copyright (c) 2017-2018 The Bitcoin developers
// Copyright (c) 2017-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIG_HASH_TYPE_H
#define BITCOIN_SIG_HASH_TYPE_H

#include "script/interpreter.h"
#include "serialize.h"

#include <cstdint>
#include <stdexcept>

/**
 * Base signature hash types
 * Base sig hash types not defined in this enum may be used, but they will be
 * represented as UNSUPPORTED.  See transaction
 * c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73 for an
 * example where an unsupported base sig hash of 0 was used.
 */
enum class BaseSigHashType : uint8_t
{
    UNSUPPORTED = 0,
    ALL = SIGHASH_ALL,
    NONE = SIGHASH_NONE,
    SINGLE = SIGHASH_SINGLE,
    BCH = SIGHASH_FORKID,
    ANYONECANPAY = SIGHASH_ANYONECANPAY
};

/** Signature hash type wrapper class */
class SigHashType
{
protected: // tests need direct access
    uint32_t sigHash;

public:
    /** The default constructor creates a sighash that is the most restrictive -- it signs all inputs and outputs */
    explicit SigHashType() : sigHash(SIGHASH_ALL) {}

    explicit SigHashType(BaseSigHashType sigHashIn) : sigHash((uint32_t)sigHashIn) {}
    explicit SigHashType(uint32_t sigHashIn) : sigHash(sigHashIn) {}

    explicit SigHashType(const std::vector<unsigned char> &sig) : sigHash(sig.back()) {}

    SigHashType withBaseType(BaseSigHashType baseSigHashType) const
    {
        return SigHashType((sigHash & ~0x1f) | uint32_t(baseSigHashType));
    }

    SigHashType withForkValue(uint32_t forkId) const { return SigHashType((forkId << 8) | (sigHash & 0xff)); }

    SigHashType withForkId(bool forkId = true) const
    {
        return SigHashType((sigHash & ~SIGHASH_FORKID) | (forkId ? SIGHASH_FORKID : 0));
    }

    SigHashType withAnyoneCanPay(bool anyoneCanPay = true) const
    {
        return SigHashType((sigHash & ~SIGHASH_ANYONECANPAY) | (anyoneCanPay ? SIGHASH_ANYONECANPAY : 0));
    }

    BaseSigHashType getBaseType() const { return BaseSigHashType(sigHash & 0x1f); }

    uint32_t getForkValue() const { return sigHash >> 8; }

    bool isDefined() const
    {
        auto baseType = BaseSigHashType(sigHash & ~(SIGHASH_FORKID | SIGHASH_ANYONECANPAY));
        return baseType >= BaseSigHashType::ALL && baseType <= BaseSigHashType::SINGLE;
    }

    bool isInvalid() const { return (sigHash == (uint32_t)BaseSigHashType::UNSUPPORTED); }

    bool isBch() const { return (sigHash & SIGHASH_FORKID) != 0; }

    // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
    bool hasAnyoneCanPay() const { return (sigHash & SIGHASH_ANYONECANPAY) != 0; }

    bool hasSingle() const { return ((sigHash & 0x1f) == SIGHASH_SINGLE) != 0; }
    bool hasNone() const { return ((sigHash & 0x1f) == SIGHASH_NONE) != 0; }

    uint32_t getRawSigHashType() const { return sigHash; }

    /** Returns the raw sighash character for BTC signatures.  Asserts if this sig hash is not meant for BTC */
    uint8_t btcSigHashType() const
    {
        // technically BTC can set this free bit... assert((sigHash & SIGHASH_FORKID) == 0);
        return sigHash;
    }

    /** Returns the raw sighash character for BCH signatures.  Asserts if this sig hash is not meant for BCH */
    uint8_t bchSigHashType() const
    {
        assert((sigHash & SIGHASH_FORKID) != 0);
        return sigHash;
    }

    /** append this hash type to a signature so that the resulting data describes what it signed */
    void appendToSig(std::vector<unsigned char> &sig) const { sig.push_back((unsigned char)sigHash); }

    /** load a human-readable representation of the sighash into an object.
        if flagStr is empty, or does not define a portion of the sighash, this object is unmodified in that portion.
        If the flagStr is incorrect, this object is set to in invalid sighash  */
    SigHashType &from(const std::string &flagStr);

    template <typename Stream>
    void Serialize(Stream &s) const
    {
        ::Serialize(s, sigHash);
    }
};


/** Calculate the hash that a signature of this transaction signs.  The algorithm depends on sigHashType,
    Both in determining whether to use the Bitcoin Cash or Bitcoin algorithm, and also the specific data and
    algorithm within those two families. */
uint256 SignatureHash(const CScript &scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    const CAmount &amount,
    size_t *nHashedOut = nullptr);

uint256 SignatureHashBitcoin(const CScript &scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    size_t *nHashedOut);

uint256 SignatureHashBitcoinCash(const CScript &scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    const SigHashType &sigHashType,
    const CAmount &amount,
    size_t *nHashedOut);

/** Extract the sighashtype from a signature */
SigHashType GetSigHashType(const std::vector<unsigned char> &vchSig);
/** remove the sighashtype data from a signature, in-place */
void RemoveSigHashType(std::vector<unsigned char> &vchSig);

extern const SigHashType defaultSigHashType;

#endif // BITCOIN_SCRIPT_HASH_TYPE_H
