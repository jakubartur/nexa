// Copyright (c) 2019-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "test/test_nexa.h"
#include "test/testutil.h"
#include "txlookup.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(txlookup_tests, BasicTestingSetup);

BOOST_AUTO_TEST_CASE(ctor_lookup)
{
    CBlock block;
    for (size_t i = 0; i < 100; ++i)
    {
        block.vtx.push_back(MakeTransactionRef(CreateRandomTx()));
    }
    std::sort(
        begin(block.vtx) + 1, end(block.vtx), [](const auto &a, const auto &b) { return a->GetId() < b->GetId(); });

    for (size_t i = 0; i < 100; i += 10)
    {
        BOOST_CHECK_EQUAL(i, static_cast<size_t>(FindTxPosition(block, block.vtx[i]->GetId())));
    }
}

BOOST_AUTO_TEST_SUITE_END();
