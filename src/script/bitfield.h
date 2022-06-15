// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_SCRIPT_BITFIELD_H
#define NEXA_SCRIPT_BITFIELD_H

#include "script/script_error.h"

#include <cstdint>
#include <vector>

bool DecodeBitfield(const std::vector<uint8_t> &vch, unsigned size, uint32_t &bitfield, ScriptError *serror);

#endif // NEXA_SCRIPT_BITFIELD_H
