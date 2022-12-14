// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "streams.h"
#include "support/allocators/zeroafterfree.h"
#include "test/test_nexa.h"

#include <boost/assert.hpp>
#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(streams_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(streams_serializedata_xor)
{
    std::vector<char> in;
    std::vector<char> expected_xor;
    std::vector<unsigned char> key;
    CDataStream ds(in, 0, 0);

    // Degenerate case

    key.emplace_back('\x00');
    key.emplace_back('\x00');
    ds.Xor(key);
    BOOST_CHECK_EQUAL(std::string(expected_xor.begin(), expected_xor.end()), std::string(ds.begin(), ds.end()));

    in.emplace_back('\x0f');
    in.emplace_back('\xf0');
    expected_xor.emplace_back('\xf0');
    expected_xor.emplace_back('\x0f');

    // Single character key

    ds.clear();
    ds.insert(ds.begin(), in.begin(), in.end());
    key.clear();

    key.emplace_back('\xff');
    ds.Xor(key);
    BOOST_CHECK_EQUAL(std::string(expected_xor.begin(), expected_xor.end()), std::string(ds.begin(), ds.end()));

    // Multi character key

    in.clear();
    expected_xor.clear();
    in.emplace_back('\xf0');
    in.emplace_back('\x0f');
    expected_xor.emplace_back('\x0f');
    expected_xor.emplace_back('\x00');

    ds.clear();
    ds.insert(ds.begin(), in.begin(), in.end());

    key.clear();
    key.emplace_back('\xff');
    key.emplace_back('\x0f');

    ds.Xor(key);
    BOOST_CHECK_EQUAL(std::string(expected_xor.begin(), expected_xor.end()), std::string(ds.begin(), ds.end()));
}

BOOST_AUTO_TEST_CASE(streams)
{
    // Smallest possible example
    CDataStream ssx(SER_DISK, CLIENT_VERSION);
    BOOST_CHECK_EQUAL(HexStr(ssx.begin(), ssx.end()), "");
}

BOOST_AUTO_TEST_SUITE_END()
