// Copyright (c) 2017 The Bitcoin developers
// Copyright (c) 2017-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NEXA_DSTENCODE_H
#define NEXA_DSTENCODE_H

// key.h and pubkey.h are not used here, but gcc doesn't want to instantiate
// CTxDestination if types are unknown
#include "key.h"
#include "pubkey.h"
#include "script/standard.h"
#include <string>

class Config;
class CChainParams;

std::string EncodeDestination(const CTxDestination &, const CChainParams &, const Config &);
CTxDestination DecodeDestination(const std::string &addr, const CChainParams &);
bool IsValidDestinationString(const std::string &addr, const CChainParams &params);

// Temporary workaround. Don't rely on global state, pass all parameters in new
// code.
std::string EncodeDestination(const CTxDestination &);
CTxDestination DecodeDestination(const std::string &addr);
bool IsValidDestinationString(const std::string &addr);

#endif // NEXA_DSTENCODE_H
