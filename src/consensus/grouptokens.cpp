// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "grouptokens.h"
#include "base58.h"
#include "cashaddrenc.h"
#ifndef ANDROID // limit dependencies
#include "coincontrol.h"
#include "coins.h"
#endif
#include "consensus/validation.h"
#include "dstencode.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "random.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/scripttemplate.h"
#include "script/standard.h"
#include "streams.h"
#include "unlimited.h"
#include "utilmoneystr.h"
#include <algorithm>

bool IsAnyTxOutputGrouped(const CTransaction &tx)
{
    for (const CTxOut &txout : tx.vout)
    {
        CGroupTokenInfo grp(txout.scriptPubKey);
        if (grp.invalid)
            return true; // Its still grouped even if invalid
        if (grp.associatedGroup != NoGroup)
            return true;
    }

    return false;
}

#if 0 // TBD
bool IsAnyTxOutputGroupedCreation(const CTransaction &tx, const GroupTokenIdFlags tokenGroupIdFlags)
{
    for (const CTxOut& txout : tx.vout) {
        CGroupTokenInfo grp(txout.scriptPubKey);
        if (grp.invalid)
            return false;
        if (grp.isGroupCreation(tokenGroupIdFlags))
            return true;
    }
    return false;
}
#endif

std::vector<unsigned char> SerializeAmount(CAmount num)
{
    CDataStream strm(SER_NETWORK, CLIENT_VERSION);
    if (num < 0) // negative numbers are serialized at full length
    {
        ser_writedata64(strm, num);
    }
    /* Disallow amounts to be encoded as a single byte because these may need to have special encodings if
       the SCRIPT_VERIFY_MINIMALDATA flag is set
    else if (num < 256)
    {
        ser_writedata8(strm, num);
    }
    */
    else if (num <= std::numeric_limits<unsigned short>::max())
    {
        ser_writedata16(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata32(strm, num);
    }
    else
    {
        ser_writedata64(strm, num);
    }
    return std::vector<unsigned char>(strm.begin(), strm.end());
}

#if 0
CGroupTokenID ExtractControllingGroup(const CScript &scriptPubKey)
{
    txnouttype whichType;
    typedef std::vector<unsigned char> valtype;
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichType, vSolutions))
        return CGroupTokenID();

    // only certain well known script types are allowed to mint or melt
    if ((whichType == TX_PUBKEYHASH) || (whichType == TX_GRP_PUBKEYHASH) || (whichType == TX_SCRIPTHASH) ||
        (whichType == TX_GRP_SCRIPTHASH))
    {
        return CGroupTokenID(uint160(vSolutions[0]));
    }
    return CGroupTokenID();
}
#endif

CGroupTokenInfo::CGroupTokenInfo(const CScript &script)
    : associatedGroup(), controllingGroupFlags(GroupAuthorityFlags::NONE), quantity(0), invalid(false)
{
    IsScriptGrouped(script, nullptr, this);
}

CGroupTokenInfo::CGroupTokenInfo(const CTxOut &output)
    : associatedGroup(), controllingGroupFlags(GroupAuthorityFlags::NONE), quantity(0), invalid(false)
{
    // Make sure that the script type was set properly based on the utxo type
    DbgAssert(output.scriptPubKey.type == CTxOut::ScriptTypeOf(output.type), );
    IsScriptGrouped(output.scriptPubKey, nullptr, this);
}

#ifndef ANDROID // limit dependencies (CCoinsViewCache)
bool CheckGroupTokens(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &view)
{
    GroupBalanceMapRef gBalanceState = MakeGroupBalanceMapRef();
    // For simple syntax grab a c++ style reference to the shared entity
    GroupBalanceMap &gBalance = *gBalanceState.get();
    CScript firstOpReturn;

    // Iterate through all the outputs constructing the final balances of every group.
    for (const auto &outp : tx.vout)
    {
        const CScript &scriptPubKey = outp.scriptPubKey;
        CGroupTokenInfo tokenGrp(scriptPubKey);
        if ((outp.nValue == 0) && (firstOpReturn.size() == 0) && (outp.scriptPubKey[0] == OP_RETURN))
        {
            firstOpReturn = outp.scriptPubKey; // Used later if this is a group creation transaction
        }
        if (tokenGrp.invalid)
            return state.Invalid(false, REJECT_INVALID, "bad GROUP");
        if (tokenGrp.associatedGroup != NoGroup)
        {
            gBalance[tokenGrp.associatedGroup].numOutputs += 1;
            if (tokenGrp.associatedGroup.hasFlag(GroupTokenIdFlags::HOLDS_NEX))
            {
                // If a group holds NEX, its quantity MUST be 0 (or be an authority so < 0)
                if (tokenGrp.quantity > 0)
                    return state.Invalid(false, REJECT_INVALID, "fenced groups must hold 0 tokens");
                // Set the NEX group quantity to the NEX amount so subsequent logic uses NEX.
                tokenGrp.quantity = outp.nValue;
            }
            if (tokenGrp.isAuthority()) // this is an authority output
            {
                gBalance[tokenGrp.associatedGroup].ctrlOutputPerms |=
                    (GroupAuthorityFlags)tokenGrp.controllingGroupFlags;
                // anyOutputControlGroups = true;
            }
            else
            {
                if (tokenGrp.quantity > 0)
                {
                    if (std::numeric_limits<CAmount>::max() - gBalance[tokenGrp.associatedGroup].output <
                        tokenGrp.quantity)
                        return state.Invalid(false, REJECT_INVALID, "token overflow");
                    gBalance[tokenGrp.associatedGroup].output += tokenGrp.quantity;
                    // anyOutputGroups = true;
                }
                else if (tokenGrp.quantity == 0)
                {
                    return state.Invalid(false, REJECT_INVALID, "GROUP quantity is zero");
                }
            }
        }
    }

    // Now iterate through the inputs applying them to match outputs.
    // If any input utxo address matches a non-bitcoin group address, defer since this could be a mint or burn
    for (const auto &inp : tx.vin)
    {
        const COutPoint &prevout = inp.prevout;
        CoinAccessor coin(view, prevout);
        if (coin->IsSpent()) // should never happen because you've already CheckInputs(tx,...)
        {
            DbgAssert(!"Checking token group for spent coin", );
            return state.Invalid(false, REJECT_INVALID, "already-spent");
        }
        const CScript &script = coin->out.scriptPubKey;
        const ScriptType scriptType = CTxOut::ScriptTypeOf(coin->out.type);
        DbgAssert(scriptType == script.type, );
        CGroupTokenInfo tokenGrp(script);
        // The prevout should never be invalid because that would mean that this node accepted a block with an
        // invalid OP_GROUP tx in it.
        if (tokenGrp.invalid)
            continue;

        if (tokenGrp.associatedGroup.hasFlag(GroupTokenIdFlags::HOLDS_NEX))
        {
            // Set the NEX group quantity to the NEX amount so subsequent logic uses NEX.
            tokenGrp.quantity = coin->out.nValue;
        }

        CAmount amount = tokenGrp.quantity;
        if (tokenGrp.controllingGroupFlags != GroupAuthorityFlags::NONE)
        {
            auto temp = tokenGrp.controllingGroupFlags;
            // outputs can have all the permissions of inputs, except for 1 special case
            // If BATON is not set, no outputs can be authorities (so unset the AUTHORITY flag)
            if (hasCapability(temp, GroupAuthorityFlags::BATON))
            {
                gBalance[tokenGrp.associatedGroup].allowedCtrlOutputPerms |= temp;
                if (hasCapability(temp, GroupAuthorityFlags::SUBGROUP))
                    gBalance[tokenGrp.associatedGroup].allowedSubgroupCtrlOutputPerms |= temp;
            }
            // Track what permissions this transaction has
            gBalance[tokenGrp.associatedGroup].ctrlPerms |= temp;
        }

        // If the group is covenanted and we haven't found the covenant, get it. (REQ3.2.4.1)
        if (!tokenGrp.isAuthority() && tokenGrp.associatedGroup.hasFlag(GroupTokenIdFlags::COVENANT) &&
            gBalance[tokenGrp.associatedGroup].covenant.size() == 0)
        {
            if (scriptType == ScriptType::TEMPLATE)
            {
                VchType contractId;
                ScriptTemplateError error = GetScriptTemplate(script, nullptr, &contractId);

                // The first grouped input is the covenant for this group (if group is covenanted).
                if (error == ScriptTemplateError::INVALID)
                {
                    return state.Invalid(false, REJECT_INVALID, "bad general txout");
                }
                if (error == ScriptTemplateError::OK)
                    gBalance[tokenGrp.associatedGroup].covenant = contractId;
            }
        }

        if ((tokenGrp.associatedGroup != NoGroup) && !tokenGrp.isAuthority())
        {
            if (std::numeric_limits<CAmount>::max() - gBalance[tokenGrp.associatedGroup].input < amount)
                return state.Invalid(false, REJECT_INVALID, "token overflow");
            gBalance[tokenGrp.associatedGroup].input += amount;
        }
        gBalance[tokenGrp.associatedGroup].numInputs += 1;
    }

    // Now pass thru the outputs applying parent group capabilities to any subgroups
    for (auto &grp : gBalance)
    {
        CGroupTokenID group = grp.first;
        GroupBalance &bal = grp.second;
        if (group.isSubgroup())
        {
            CGroupTokenID parentgrp = group.parentGroup();
            auto parentSearch = gBalance.find(parentgrp);
            if (parentSearch != gBalance.end()) // The parent group is part of the inputs
            {
                GroupBalance &parentData = parentSearch->second;
                if (hasCapability(parentData.ctrlPerms, GroupAuthorityFlags::SUBGROUP))
                {
                    // Give the subgroup has all the capabilities the parent group had,
                    // except no recursive subgroups so remove the subgrp authority bit.
                    bal.ctrlPerms |= parentData.ctrlPerms & ~(GroupAuthorityFlags::SUBGROUP);
                }

                // Give the subgroup authority printing permissions as specified by the parent group
                bal.allowedCtrlOutputPerms |=
                    parentData.allowedSubgroupCtrlOutputPerms & ~(GroupAuthorityFlags::SUBGROUP);
            }
        }
    }

    // Now pass thru the outputs ensuring balance or mint/melt permission
    for (auto &grp : gBalance)
    {
        GroupBalance &bal = grp.second;
        // If it has an authority, with no input authority, check mint
        if (hasCapability(bal.ctrlOutputPerms, GroupAuthorityFlags::AUTHORITY) &&
            (bal.ctrlPerms == GroupAuthorityFlags::NONE))
        {
            CHashWriter mintGrp(SER_GETHASH, PROTOCOL_VERSION);
            mintGrp << tx.vin[0].prevout;
            if (firstOpReturn.size())
            {
                std::vector<unsigned char> data(firstOpReturn.begin(), firstOpReturn.end());
                mintGrp << data;
            }
            mintGrp << (uint64_t)bal.ctrlOutputPerms; // REQ3.2.1.5
            CGroupTokenID newGrpId(mintGrp.GetHash());

            if (newGrpId == grp.first) // This IS new group because id matches hash, so allow all authority.
            {
                uint32_t groupFlags = (newGrpId.bytes()[30] << 8) | newGrpId.bytes()[31];
                if ((groupFlags & (uint32_t)GroupTokenIdFlags::GROUP_RESERVED_BITS) != 0) // REQ3.2.1.4
                    return state.Invalid(
                        false, REJECT_GROUP_IMBALANCE, "grp-invalid-create", "Nonzero group reserved bits");
                // REQ3.2.1.3
                if (((uint64_t)bal.ctrlOutputPerms & ((uint64_t)GroupAuthorityFlags::RESERVED_FLAG_BITS)) != 0)
                    return state.Invalid(
                        false, REJECT_GROUP_IMBALANCE, "grp-invalid-create", "Nonzero authority reserved bits");

                if (bal.numOutputs != 1) // only allow the single authority tx during a create
                    return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-create",
                        "Multiple grouped outputs created during group creation transaction");
                bal.allowedCtrlOutputPerms = bal.ctrlPerms = GroupAuthorityFlags::ACTIVE_FLAG_BITS;
            }
            else
            {
                // REQ3.2.2.2
                if (((uint64_t)bal.ctrlOutputPerms & (uint64_t)~GroupAuthorityFlags::ALL_FLAG_BITS) != 0)
                {
                    return state.Invalid(
                        false, REJECT_INVALID, "grp-invalid-tx", "Only genesis transactions can have a nonce");
                }
            }
        }

        if ((bal.input > bal.output) && !hasCapability(bal.ctrlPerms, GroupAuthorityFlags::MELT))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-melt",
                "Group input exceeds output, but no melt permission");
        }
        if ((bal.input < bal.output) && !hasCapability(bal.ctrlPerms, GroupAuthorityFlags::MINT))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-mint",
                "Group output exceeds input, but no mint permission");
        }
        // Some output permissions are set that are not in the inputs
        if (((uint64_t)(bal.ctrlOutputPerms & GroupAuthorityFlags::ACTIVE_FLAG_BITS)) &
            ~((uint64_t)(bal.allowedCtrlOutputPerms & GroupAuthorityFlags::ACTIVE_FLAG_BITS)))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-perm",
                "Group output permissions exceeds input permissions");
        }
    }

    // Now pass thru the outputs ensuring group covenants, and that any templates are valid.
    for (const auto &outp : tx.vout)
    {
        const CScript &script = outp.scriptPubKey;
        CGroupTokenInfo grp(script);

        VchType contractId;
        ScriptTemplateError error = GetScriptTemplate(script, nullptr, &contractId);

        if (error == ScriptTemplateError::INVALID)
        {
            return state.Invalid(false, REJECT_INVALID, "template-invalid", "invalid template in constraint script");
        }

        // If this output's group is covenanted, enforce it. (REQ3.2.4.1)
        if (grp.associatedGroup.hasFlag(GroupTokenIdFlags::COVENANT))
        {
            GroupBalance &grpData = gBalance[grp.associatedGroup];

            // Changed to accept both templates and arbitrary scripts with the GROUP prefix chopped off

            // All covenanted groups must use templates
            // if (error == ScriptTemplateError::NOT_A_TEMPLATE)
            //{
            //    return state.Invalid(
            //        false, REJECT_INVALID, "grp-covenant-no-template", "covenanted group output is not a template");
            //}

            // If no inputs have the authority to change the covenant, then this output must match the covenant
            if (!hasCapability(grpData.ctrlPerms, GroupAuthorityFlags::RESCRIPT))
            {
                if (contractId != grpData.covenant)
                {
                    return state.Invalid(false, REJECT_INVALID, "grp-covenant-bad-template",
                        "covenant group has incorrect output template");
                }
            }
        }
    }
    state.groupState = gBalanceState;
    return true;
}
#endif

bool CGroupTokenID::isUserGroup(void) const { return (!data.empty()); }
bool CGroupTokenID::isSubgroup(void) const { return (data.size() > PARENT_GROUP_ID_SIZE); }
CGroupTokenID CGroupTokenID::parentGroup(void) const
{
    if (data.size() <= PARENT_GROUP_ID_SIZE)
        return CGroupTokenID(data);
    return CGroupTokenID(std::vector<unsigned char>(data.begin(), data.begin() + PARENT_GROUP_ID_SIZE));
}

bool CGroupTokenID::hasFlag(GroupTokenIdFlags flag) const
{
    return data.size() >= PARENT_GROUP_ID_SIZE ?
               hasGroupTokenIdFlag((GroupTokenIdFlags)((data[30] << 8) | data[31]), flag) :
               false;
}

std::string EncodeGroupToken(const CGroupTokenID &grp, const CChainParams &params)
{
    return EncodeCashAddr(grp.bytes(), CashAddrType::GROUP_TYPE, params);
}

CGroupTokenID DecodeGroupToken(const std::string &addr, const CChainParams &params)
{
    CashAddrContent cac = DecodeCashAddrContent(addr, params);
    if (cac.type == CashAddrType::GROUP_TYPE)
        return CGroupTokenID(cac.hash);
    // otherwise it becomes NoGroup (i.e. data is size 0)
    return CGroupTokenID();
}
