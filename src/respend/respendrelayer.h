// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NEXA_RESPEND_RESPENDRELAYER_H
#define NEXA_RESPEND_RESPENDRELAYER_H

#include "respend/respendaction.h"
#include "txmempool.h"

extern CTxMemPool mempool;

namespace respend
{
static const int64_t DEFAULT_LIMITRESPENDRELAY = 100;

// Relays double spends to other peers so they also may detect the doublespend.
class RespendRelayer : public RespendAction
{
public:
    RespendRelayer();

    bool AddOutpointConflict(const COutPoint &,
        const uint256 txId,
        const CTransactionRef pRespendTx,
        bool seenBefore,
        bool isEquivalent) override;

    bool IsInteresting() const override;
    void SetValid(bool v) override;

    void Trigger(CTxMemPool &pool) override;

private:
    bool interesting;
    bool valid;
    uint256 spendTxId;
    CTransactionRef pRespend;
};

} // namespace respend

#endif
