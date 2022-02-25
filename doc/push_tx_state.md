<div class="cwikmeta">  
{  
"title": "OP_PUSH_TX_STATE"  
} </div>

# OP_PUSH_TX_STATE
*Place information about the current transaction onto the stack*

This opcode pushes state data to the stack that is generated during transaction consensus rules checks.  This is a different data set than the introspection opcodes.  The introspection opcodes make data accessible from the raw transaction and its prevouts easily accessible.  This opcode offers data synthesized from analysis of the transaction.  While this data is in theory calculable from the introspection opcodes, in practice the absence of loops makes implementation difficult.  Additionally, such calculation would be expensive in both script size and interpreter time, especially when it has already been calculated.

## Syntax and Stack
*dataSpecifier* **OP_PUSH_TX_STATE** => ret<sup>*[?](opcodeSyntax.md)*</sup>

- *dataSpecifier*: An array of bytes describing what state to be pushed
- *ret*: The data you asked for.  

### Binary representation
OP_PUSH_TX_STATE is represented by the single byte 0xea.

## Operation

### Data Specifiers

Note, this list is incomplete; new specifiers will be added as needed.  Please see [2] for a more comprehensive list.  The data specifier is a sequence of bytes (a single stack item) that begins with the 1 byte specifier id and then contains any additional fields (as described in "parameters" below).

Since the data specifier is push on the stack, scripts have the options as to how to build data specifiers that contain parameters.  The simplest method is to push the raw data specifier as hard-coded bytes.  But scripts can also construct a data specifier out of individual stack items using OP_CAT. 

| Name | Number | Parameters | Description |
|--------|-----------|---------------|----------|
| TX_ID | 0x2 | none | Pushes the 32 byte transaction id onto the stack.
| TX_IDEM | 0x3 | none | Pushes the 32 byte transaction idem onto the stack.
| TX_INCOMING_AMOUNT | 0x5 | none | Pushes the total incoming native cryptocurrency in its finest unit as a minimally encoded CScriptNum with a maximum of 8 bytes.
| TX_OUTGOING_AMOUNT | 0x6 | none | Pushes the total outcoing native cryptocurrency in its finest unit as a minimally encoded CScriptNum with a maximum of 8 bytes.
| GROUP_INCOMING_AMOUNT | 0x7 | GroupId (32 bytes) | Pushes the total incoming tokens of this group as a minimally encoded CScriptNum with a maximum of 8 bytes.  Overflows wrap, but may FAIL the transaction in the future.
| GROUP_OUTGOING_AMOUNT | 0x8 | GroupId (32 bytes) | Pushes the total outgoing tokens of this group as a minimally encoded CScriptNum with a maximum of 8 bytes.  Overflows wrap, but may FAIL the transaction in the future.
| GROUP_INCOMING_COUNT | 0x9 | GroupId (32 bytes) | Pushes the number of inputs using this group as a minimally encoded CScriptNum.  This includes authorities.
| GROUP_OUTGOING_COUNT | 0xA | GroupId (32 bytes) | Pushes the number of outputs using this group as a minimally encoded CScriptNum.  This includes authorities.
| GROUP_NTH_INPUT | 0xB | index (2 bytes), GroupId (32 bytes) | Pushes the index of the Nth (0-based) this-grouped input (an input is "grouped" if its prevout is grouped).  Scripts can use this index with introspection opcodes to access data from that input or prevout.
| GROUP_NTH_OUTPUT | 0xC | index (2 bytes), GroupId (32 bytes) | Pushes the index of the Nth (0-based) this-grouped output.  Scripts can use this index with introspection opcodes to access data from that output.

## Errors

** Non-existent group ** If a group does not exist (in this transaction) the "_AMOUNT" and "_COUNT" opcodes push 0 onto the stack.

**Non-existent group index** For NTH_INPUT and NTH_OUTPUT opcodes, if the script requests a non-existent Nth, the script fails.  By implication then, if the group does not exist (in this transaction), the script fails.  Scripts that do not want to fail can use the _COUNT opcodes to determine the total number of inputs/outputs that need to be queried.

** Invalid specifier **  If a specifier does not exist, or its parameters are incorrectly formatted, the script fails.

## References

1. Group Tokenization. Stone. 2018. https://docs.google.com/document/d/1X-yrqBJNj6oGPku49krZqTMGNNEWnUJBRFjX7fJXvTs/edit?usp=sharing (PUSH_TX_DATA, page 31-)

2. CHIP-2021-02: Native Introspection Opcodes. https://gitlab.com/GeneralProtocols/research/chips/-/blob/master/CHIP-2021-02-Add-Native-Introspection-Opcodes.md

3. eltoo: A Simple Layer2 Protocol for Bitcoin. Decker, Russell, Osuntokun. 2018. https://blockstream.com/eltoo.pdf.
