// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCRIPT_TEMPLATE_H
#define SCRIPT_TEMPLATE_H

#include <vector>

/** Get the script's template hash if this script is a template.  If the template hash is a "well-known" number, it is
    returned as that number (not converted to a hash, but the number in vector form).  Use
    ConvertWellKnownTemplateHash() to convert well-known templates value to a hash, and get the actual script it refers
    to.  Pass nullptr for any output parameters that you are not interested in.
    @param[in] script The "script" (the output of a transaction) containing all the info.
    @param[out] groupInfo Group token information
    @param[out] templateHash Hash of the script template
    @param[out] argsHash Hash of the template arguments
    @param[out] pcout  Iterator pointing to the next unused bytes in the script (these are unblinded arguments).

    @return error Whether the script is a template, is not a template, or is an invalid template.
 */
ScriptTemplateError GetScriptTemplate(const CScript &script,
    CGroupTokenInfo *groupInfo,
    std::vector<unsigned char> *templateHash,
    std::vector<unsigned char> *argsHash = nullptr,
    CScript::const_iterator *pcout = nullptr);


/** Convert well-known templates value to a hash, and get the actual script it refers to.
    The templateHash argument MUST be within the correct size range for well-known templates (1 or 2 bytes), unless
    ignored due to an numeric opcode.
    @param[in/out] templateHash  Pass in the well-known ID, get the actual hash out.
    @param[in/out] templateScript The actual script

    @return error SCRIPT_ERR_OK if this is a valid well-known template, otherwise SCRIPT_ERR_TEMPLATE.
 */
ScriptError ConvertWellKnownTemplateHash(VchType &templateHash, CScript &templateScript);


/** This function looks at the input script and templateHash, extracts the template script, and verifies that the
   template hash is a proper size and that the template script is the proper preimage for the hash.

   @param[in] satisfier  The satisfier script (used to extract the template script, if needed)
   @param[in/out] satisfierIter  Grab the scriptTemplate (if needed) from here.  Since scriptTemplates are the first
       item in satisfier script, this MUST be satisfier.begin().  If this function is successful, the satisfierIter
       will be moved past the script template hash (if it exists).
   @param[in/out] templateHash The templateHash is updated to an actual hash if it encodes a well-known shorthand.
   @param[in/out] templateScript The script, either extracted from the satisfier or copied from the list of well-known
       scripts.
*/
ScriptError LoadCheckTemplateHash(const CScript &satisfier, CScript::const_iterator &satisfierIter, VchType &templateHash, CScript &templateScript);

void NumericOpcodeToVector(opcodetype opcode, VchType &templateHash);

/** Well-known script templates */

/** p2pkt - pay-to-public key template */
extern const CScript p2pkt;
extern const std::vector<unsigned char> p2pktId;  // Push will convert this vector to OP_1

#endif
