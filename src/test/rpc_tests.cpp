// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/client.h"
#include "rpc/server.h"

#include "base58.h"
#include "net.h"
#include "netbase.h"
#include "rpc/blockchain.h"
#include "unlimited.h"

#include "test/test_nexa.h"

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace std;

UniValue createArgs(int nRequired, const char *address1 = nullptr, const char *address2 = nullptr)
{
    UniValue result(UniValue::VARR);
    result.push_back(nRequired);
    UniValue addresses(UniValue::VARR);
    if (address1)
        addresses.push_back(address1);
    if (address2)
        addresses.push_back(address2);
    result.push_back(addresses);
    return result;
}

UniValue CallRPC(std::string args)
{
    vector<string> vArgs;
    boost::split(vArgs, args, boost::is_any_of(" \t"));
    string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    UniValue params = RPCConvertValues(strMethod, vArgs);
    // calling boost_check here sets the last checkpoint to a useless position
    if (!tableRPC[strMethod])
        BOOST_CHECK(tableRPC[strMethod]);
    rpcfn_type method = tableRPC[strMethod]->actor;
    try
    {
        UniValue result = (*method)(params, false);
        return result;
    }
    catch (const UniValue &objError)
    {
        throw runtime_error(find_value(objError, "message").get_str());
    }
}


BOOST_FIXTURE_TEST_SUITE(rpc_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), runtime_error);
    BOOST_CHECK_THROW(
        CallRPC("getrawtransaction a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"),
        runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] []"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [] {}"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {} extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), runtime_error);

#if 0 // TODO create a raw transaction
    string rawtx = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93"
                   "bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b06"
                   "9a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447"
                   "c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(string("decoderawtransaction ") + rawtx));
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "size").get_int(), 193);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "version").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "locktime").get_int(), 0);
    BOOST_CHECK_THROW(r = CallRPC(string("decoderawtransaction ") + rawtx + " extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("signrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction ff00"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ") + rawtx));
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ") + rawtx + " null null NONE|ANYONECANPAY"));
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ") + rawtx + " [] [] NONE|ANYONECANPAY"));
    BOOST_CHECK_THROW(CallRPC(string("signrawtransaction ") + rawtx + " null null badenum"), runtime_error);
#endif

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), runtime_error);
#if 0 // TODO create a raw transaction
    BOOST_CHECK_THROW(CallRPC(string("sendrawtransaction ") + rawtx + " extra"), runtime_error);
#endif
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    SelectParams(CBaseChainParams::LEGACY_UNIT_TESTS);

    UniValue r;
    // input is a 1-of-2 multisig (so is output):
    string prevout = "[{\"outpoint\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
                     "\"amount\":4,\"scriptPubKey\":\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
                     "\"redeemScript\":"
                     "\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f"
                     "9216ecefca5b94d6df834e77e108f68e66f126044c052ae\","
                     "\"amount\":3.14"
                     "}]";
    r = CallRPC(string("createrawtransaction ") + prevout + " " + "{\"3HqAe9LtNBjnsfM4CyYaWTnvCaUYT7v4oZ\":11}");
    string notsigned = r.get_str();
    string privkey1 = "\"KzsXybp9jX64P5ekX1KUxRQ79Jht9uzW7LorgwE65i5rWACL6LQe\"";
    string privkey2 = "\"Kyhdf5LuKTRx4ge69ybABsiUAWjVRK4XGxAKk2FQLp2HjGMy87Z4\"";
    r = CallRPC(string("signrawtransaction ") + notsigned + " " + prevout + " " + "[]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == false);
    r = CallRPC(
        string("signrawtransaction ") + notsigned + " " + prevout + " " + "[" + privkey1 + "," + privkey2 + "]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == true);
}

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction "
                                 "[{\"outpoint\":\"b3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\","
                                 "\"amount\":100}] {\"data\":\"68656c6c6f776f726c64\"}"));

    // Allow more than one data transaction output
    BOOST_CHECK_NO_THROW(
        CallRPC("createrawtransaction "
                "[{\"outpoint\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"amount\":100}] "
                "{\"data\":\"68656c6c6f776f726c64\",\"data\":\"68656c6c6f776f726c64\"}"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"outpoint\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\","
                              "\"amount\":100}] {\"somedata\":\"68656c6c6f776f726c64\"}"),
        runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"outpoint\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\","
                              "\"amount\":100}] {\"data\":\"12345\"}"),
        runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"outpoint\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\","
                              "\"amount\":100}] {\"data\":\"12345g\"}"),
        runtime_error);

    // No amount
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"outpoint\":\"z3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\"}] "
                              "{\"data\":\"12345g\"}"),
        runtime_error);
    // Negative amount
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"outpoint\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\","
                              "\"amount\":-100 }] {\"data\":\"12345g\"}"),
        runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(
        CallRPC("createrawtransaction "
                "[{\"outpoint\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"amount\":100}] "
                "{\"data\":"
                "\"0102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950"
                "51525354555657585960616263646566676869707172737475767778798081\"}"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).write() == "0.00");
    BOOST_CHECK(ValueFromAmount(1LL).write() == "0.01");
    BOOST_CHECK(ValueFromAmount(17622195LL).write() == "176221.95");
    BOOST_CHECK(ValueFromAmount(50000000LL).write() == "500000.00");
    BOOST_CHECK(ValueFromAmount(89898989LL).write() == "898989.89");
    BOOST_CHECK(ValueFromAmount(100000000LL).write() == "1000000.00");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).write() == "20999999999999.90");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).write() == "20999999999999.99");

    BOOST_CHECK_EQUAL(ValueFromAmount(0).write(), "0.00");
    BOOST_CHECK_EQUAL(ValueFromAmount((COIN / 100) * 123456789).write(), "1234567.89");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN).write(), "-1.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN / 10).write(), "-0.10");

    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 100000000).write(), "100000000.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 10000000).write(), "10000000.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 1000000).write(), "1000000.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 100000).write(), "100000.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 10000).write(), "10000.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 1000).write(), "1000.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 100).write(), "100.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN * 10).write(), "10.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 10).write(), "0.10");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 100).write(), "0.01");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 1000).write(), "0.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 10000).write(), "0.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 100000).write(), "0.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 1000000).write(), "0.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 10000000).write(), "0.00");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 100000000).write(), "0.00");
}

static UniValue ValueFromString(const std::string &str)
{
    UniValue value;
    BOOST_CHECK(value.setNumStr(str));
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.01")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01")), 1LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.17")), 17LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), 50LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.50")), 50LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.89")), 89LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.00000000")), 100LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.99")), 2099999999LL);

    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-2")), COIN / 100);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-1")), COIN / 100);
    BOOST_CHECK_EQUAL(
        AmountFromValue(ValueFromString("0.00000000000000000000000000000000000000000000000000000000000000000001e+68")),
        COIN);
    BOOST_CHECK_EQUAL(
        AmountFromValue(ValueFromString("10000000000000000000000000000000000000000000000000000000000000000e-64")),
        COIN);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0."
                                                      "0000000000000000000000000000000000000000000000000000000000000001"
                                                      "00000000000000000000000000000000000000000000000000000e64")),
        COIN);

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e-9")), UniValue); // should fail
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("0.0019")), UniValue); // should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01000000")), 1LL); // should pass, cut trailing 0
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("19e-9")), UniValue); // should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19")), 19); // should pass, leading 0 is present
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.9e-1")), 19); // should pass

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("92233720368.54775808")), UniValue); // overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e+17")), UniValue); // overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e17")), UniValue); // overflow error signless
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("93e+15")), UniValue); // overflow error
}

BOOST_AUTO_TEST_CASE(json_parse_errors)
{
    // Valid
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0").get_real(), 1.0);
    // Valid, with leading or trailing whitespace
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue(" 1.0").get_real(), 1.0);
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0 ").get_real(), 1.0);

    // should fail, missing leading 0, therefore invalid JSON
    BOOST_CHECK_THROW(AmountFromValue(ParseNonRFCJSONValue(".19e-6")), std::runtime_error);
    BOOST_CHECK_EQUAL(AmountFromValue(ParseNonRFCJSONValue("0.000000000000000000000000000001e+30 ")), COIN);
    // Invalid, initial garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("[1.0"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("a1.0"), std::runtime_error);
    // Invalid, trailing garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0sds"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0]"), std::runtime_error);
    // BCH addresses should fail parsing
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));

    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0 add")));
    // portnumber for setban not allowed
    BOOST_CHECK_THROW(r = CallRPC(string("setban 127.0.0.0:8334")), runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(string("setban 127.0.0.0 remove")));
    ;
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0UL);

    // check setting a bantime in the past
    BOOST_CHECK_THROW(r = CallRPC(string("setban 127.0.0.0/24 add 1607000000 true")), runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0UL);

    // check setting a bantime in the future
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0/24 add 3000000000 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    UniValue banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until.get_int64(), 3000000000); // absolute time check

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));

    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0/24 add 200")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    int64_t now = GetTime();
    BOOST_CHECK(banned_until.get_int64() > now);
    BOOST_CHECK(banned_until.get_int64() - now <= 200);

    // must throw an exception because 127.0.0.1 is in already banned suubnet range
    BOOST_CHECK_THROW(r = CallRPC(string("setban 127.0.0.1 add")), runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(string("setban 127.0.0.0/24 remove")));
    ;
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0UL);

    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(string("setban 127.0.1.1 add")), runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0UL);


    BOOST_CHECK_THROW(r = CallRPC(string("setban test add")), runtime_error); // invalid IP

    // IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(findlikelynode)
{
    CAddress addr1(CService("169.254.1.2"));
    CNode n1(INVALID_SOCKET, addr1, "", true);
    CAddress addr2(CService("169.254.2.3"));
    CNode n2(INVALID_SOCKET, addr2, "", true);
    assert(vNodes.size() == 0);
    vNodes.push_back(&n1);
    vNodes.push_back(&n2);

    // Test prefix matching
    BOOST_CHECK(FindLikelyNode("169.254.1.2").get() == &n1);
    BOOST_CHECK(FindLikelyNode("169.254.1.2:1234").get() == nullptr);
    BOOST_CHECK(FindLikelyNode("169.254.1").get() == &n1);

    // Test wildcard matching
    BOOST_CHECK(FindLikelyNode("169.254.1*").get() == &n1);
    BOOST_CHECK(FindLikelyNode("169.254.2*").get() == &n2);
    BOOST_CHECK(FindLikelyNode("169.254.2.3*").get() == &n2);
    BOOST_CHECK(FindLikelyNode("169.254.2.?:?").get() == &n2);
    BOOST_CHECK(FindLikelyNode("169.254.1.?:*").get() == &n1);

    vNodes.clear();
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_generatetoaddress)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");

    BOOST_CHECK_NO_THROW(
        result = RPCConvertValues("generatetoaddress", {"1", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a", "9"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");
    BOOST_CHECK_EQUAL(result[2].get_int(), 9);

    BOOST_CHECK_NO_THROW(
        result = RPCConvertValues("generatetoaddress", {"1", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU", "9"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");
    BOOST_CHECK_EQUAL(result[2].get_int(), 9);
}

BOOST_AUTO_TEST_CASE(rpc_help)
{
    const string s = tableRPC.help("");
    // check sorting by category (exactly one entry named 'Mining')
    size_t p = s.find("== Mining ==");
    BOOST_CHECK(p != string::npos);
    BOOST_CHECK(s.substr(p + 1).find("== Mining ==") == string::npos);
}

BOOST_AUTO_TEST_CASE(rpc_setlog)
{
    CallRPC("log all on");
    BOOST_CHECK_EQUAL(ALL, Logging::categoriesEnabled);
    CallRPC("log all off");
    BOOST_CHECK_EQUAL(NONE, Logging::categoriesEnabled);
    CallRPC("log tor");
    BOOST_CHECK_EQUAL(NONE, Logging::categoriesEnabled);
    CallRPC("log tor on");
    BOOST_CHECK_EQUAL(TOR, Logging::categoriesEnabled);
    CallRPC("log tor off");
    BOOST_CHECK_EQUAL(NONE, Logging::categoriesEnabled);
    BOOST_CHECK_THROW(CallRPC("log tor bad-arg"), std::invalid_argument);
    BOOST_CHECK_EQUAL(NONE, Logging::categoriesEnabled);
    BOOST_CHECK_THROW(CallRPC("log badcategory on"), std::invalid_argument);
    BOOST_CHECK_EQUAL(NONE, Logging::categoriesEnabled);
}

BOOST_AUTO_TEST_CASE(rpc_getblockstats_calculate_percentiles_by_size)
{
    int64_t total_size = 200;
    std::vector<std::pair<CAmount, int64_t> > feerates;
    CAmount result[NUM_GETBLOCKSTATS_PERCENTILES] = {0};

    for (int64_t i = 0; i < 100; i++)
    {
        feerates.emplace_back(std::make_pair(1, 1));
    }

    for (int64_t i = 0; i < 100; i++)
    {
        feerates.emplace_back(std::make_pair(2, 1));
    }

    CalculatePercentilesBySize(result, feerates, total_size);
    BOOST_CHECK_EQUAL(result[0], 1);
    BOOST_CHECK_EQUAL(result[1], 1);
    BOOST_CHECK_EQUAL(result[2], 1);
    BOOST_CHECK_EQUAL(result[3], 2);
    BOOST_CHECK_EQUAL(result[4], 2);

    // Test with more pairs, and two pairs overlapping 2 percentiles.
    total_size = 100;
    CAmount result2[NUM_GETBLOCKSTATS_PERCENTILES] = {0};
    feerates.clear();

    feerates.emplace_back(std::make_pair(1, 9));
    feerates.emplace_back(std::make_pair(2, 16)); // 10th + 25th percentile
    feerates.emplace_back(std::make_pair(4, 50)); // 50th + 75th percentile
    feerates.emplace_back(std::make_pair(5, 10));
    feerates.emplace_back(std::make_pair(9, 15)); // 90th percentile

    CalculatePercentilesBySize(result2, feerates, total_size);

    BOOST_CHECK_EQUAL(result2[0], 2);
    BOOST_CHECK_EQUAL(result2[1], 2);
    BOOST_CHECK_EQUAL(result2[2], 4);
    BOOST_CHECK_EQUAL(result2[3], 4);
    BOOST_CHECK_EQUAL(result2[4], 9);

    // Same test as above, but one of the percentile-overlapping pairs is split in 2.
    total_size = 100;
    CAmount result3[NUM_GETBLOCKSTATS_PERCENTILES] = {0};
    feerates.clear();

    feerates.emplace_back(std::make_pair(1, 9));
    feerates.emplace_back(std::make_pair(2, 11)); // 10th percentile
    feerates.emplace_back(std::make_pair(2, 5)); // 25th percentile
    feerates.emplace_back(std::make_pair(4, 50)); // 50th + 75th percentile
    feerates.emplace_back(std::make_pair(5, 10));
    feerates.emplace_back(std::make_pair(9, 15)); // 90th percentile

    CalculatePercentilesBySize(result3, feerates, total_size);

    BOOST_CHECK_EQUAL(result3[0], 2);
    BOOST_CHECK_EQUAL(result3[1], 2);
    BOOST_CHECK_EQUAL(result3[2], 4);
    BOOST_CHECK_EQUAL(result3[3], 4);
    BOOST_CHECK_EQUAL(result3[4], 9);

    // Test with one transaction spanning all percentiles.
    total_size = 104;
    CAmount result4[NUM_GETBLOCKSTATS_PERCENTILES] = {0};
    feerates.clear();

    feerates.emplace_back(std::make_pair(1, 100));
    feerates.emplace_back(std::make_pair(2, 1));
    feerates.emplace_back(std::make_pair(3, 1));
    feerates.emplace_back(std::make_pair(3, 1));
    feerates.emplace_back(std::make_pair(999999, 1));

    CalculatePercentilesBySize(result4, feerates, total_size);

    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++)
    {
        BOOST_CHECK_EQUAL(result4[i], 1);
    }
}

BOOST_AUTO_TEST_SUITE_END()
