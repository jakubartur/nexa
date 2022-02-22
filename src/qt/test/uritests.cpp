// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uritests.h"

#include "chainparams.h"
#include "config.h"
#include "guiutil.h"
#include "walletmodel.h"

#include <QUrl>

void URITests::uriTestsBase58()
{
    SendCoinsRecipient rv;
    QString scheme =
        QString::fromStdString(Params(CBaseChainParams::NEXTCHAIN).CashAddrPrefix());
    QUrl uri;
    uri.setUrl(QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=0.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 1);

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=100.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 10001);

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=10000&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.amount == 1000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI(scheme, "nex://175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?"
                                     "message=Wikipedia Example Address",
                                     &rv));
    QVERIFY(rv.address == QString("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));
}

void URITests::uriTestsCashAddr() {
    SendCoinsRecipient rv;
    QUrl uri;
    QString scheme =
        QString::fromStdString(Params(CBaseChainParams::NEXTCHAIN).CashAddrPrefix());

    uri.setUrl(QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?"
                       "req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?"
                       "dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(
        QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?label="
                "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString(
        "nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?amount=0.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 1);

    uri.setUrl(QString(
        "nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?amount=1.01"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 101);

    uri.setUrl(QString(
        "nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?amount=100&"
        "label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2"));
    QVERIFY(rv.amount == 10000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString(
        "nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?message="
        "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI(
        scheme, "nex://"
                "qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?"
                "message=Wikipedia Example Address",
        &rv));
    QVERIFY(rv.address ==
            QString("nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString(
        "nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?req-message="
        "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString(
        "nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?amount=1,"
        "000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString(
        "nex:qqp8s9pn3xr9sans224rredlqlj7fetknvr9h79ze2?amount=1,"
        "000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));
}

namespace {
class UriTestConfig : public DummyConfig {
public:
    UriTestConfig(bool _useCashAddr)
        : useCashAddr(_useCashAddr), net(CBaseChainParams::NEXTCHAIN) {}
    bool UseCashAddrEncoding() const override { return useCashAddr; }
    const CChainParams &GetChainParams() const override { return Params(net); }
    void SetChainParams(const std::string &n) { net = n; }

private:
    bool useCashAddr;
    std::string net;
};

} // anon ns

void URITests::uriTestFormatURI() {
    {
        UriTestConfig cfg(true);
        SendCoinsRecipient r;
        r.address = "nex:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
        r.message = "test";
        QString uri = GUIUtil::formatBitcoinURI(cfg, r);
        QVERIFY(uri == "nex:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a?"
                       "message=test");
    }

    {
        UriTestConfig cfg(false);
        SendCoinsRecipient r;
        r.address = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W";
        r.message = "test";
        QString uri = GUIUtil::formatBitcoinURI(cfg, r);
        QVERIFY(uri ==
                "nex:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?message=test");
    }
}

void URITests::uriTestScheme() {
    {
        // cashaddr - scheme depends on selected chain params
        UriTestConfig config(true);
        config.SetChainParams(CBaseChainParams::NEXTCHAIN);
        QVERIFY("nex" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::TESTNET);
        QVERIFY("test" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::REGTEST);
        QVERIFY("nexreg" == GUIUtil::bitcoinURIScheme(config));
    }
    {
        // legacy - scheme is "nex" regardless of chain params
        UriTestConfig config(false);
        config.SetChainParams(CBaseChainParams::NEXTCHAIN);
        QVERIFY("nex" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::TESTNET);
        QVERIFY("nex" == GUIUtil::bitcoinURIScheme(config));
        config.SetChainParams(CBaseChainParams::REGTEST);
        QVERIFY("nex" == GUIUtil::bitcoinURIScheme(config));
    }
}
