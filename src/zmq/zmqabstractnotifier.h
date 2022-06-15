// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_ZMQ_ZMQABSTRACTNOTIFIER_H
#define NEXA_ZMQ_ZMQABSTRACTNOTIFIER_H

#include "zmqconfig.h"

class CBlockIndex;
class CZMQAbstractNotifier;

typedef CZMQAbstractNotifier *(*CZMQNotifierFactory)();

class CZMQAbstractNotifier
{
public:
    CZMQAbstractNotifier() : psocket(nullptr) {}
    virtual ~CZMQAbstractNotifier();

    template <typename T>
    static CZMQAbstractNotifier *Create()
    {
        return new T();
    }

    std::string GetType() const { return type; }
    void SetType(const std::string &t) { type = t; }
    std::string GetAddress() const { return address; }
    void SetAddress(const std::string &a) { address = a; }
    virtual bool Initialize(void *pcontext) = 0;
    virtual void Shutdown() = 0;

    virtual bool NotifyBlock(const CBlockIndex *pindex);
    virtual bool NotifyTransaction(const CTransactionRef &ptx);
    virtual bool NotifyDoubleSpend(const CTransactionRef ptx);

protected:
    void *psocket;
    std::string type;
    std::string address;
};

#endif // NEXA_ZMQ_ZMQABSTRACTNOTIFIER_H
