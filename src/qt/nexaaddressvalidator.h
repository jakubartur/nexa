// Copyright (c) 2011-2014 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_QT_NEXAADDRESSVALIDATOR_H
#define NEXA_QT_NEXAADDRESSVALIDATOR_H

#include <QValidator>

/**
 * Bitcoin address entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class BitcoinAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitcoinAddressEntryValidator(const std::string &cashaddrprefix, QObject *parent);

    State validate(QString &input, int &pos) const;

private:
    std::string cashaddrprefix;
};

/** Bitcoin address widget validator, checks for a valid bitcoin address.
 */
class BitcoinAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BitcoinAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // NEXA_QT_NEXAADDRESSVALIDATOR_H
