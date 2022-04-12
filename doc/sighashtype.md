# Nexa Signature Hash Type

A Nexa signature consists of a Schnorr signature and additional bytes called the signature hash type (sighashtype).  As with all secure Schnorr signature schemes, the signature does not sign the message bytes (in this case the transaction) directly; it signs a cryptographic hash of some subset of the transaction data.  The "signature hash type" identifies what data within the transaction is passed to which cryptographic hash algorithm to generate the actual data signed by the Schnorr signature algorithm.

# Identifying Sighashtype Bytes

A Schnorr signature is 64 bytes.  The sighashtype bytes therefore start at zero-based byte 64.  Parsing the sighashtype determines how many bytes it comprises.

Consensus validating implementations MUST enforce that the full signature contains no additional bytes.  Non-validating implementations MAY choose to be tolerant of extra bytes, as this may make them robust in the face of consensus upgrades (that may add additional data to the signature).

# Empty SigHash

Since a Schnorr signature must be 64 bytes, it is therefore possible to determine that no sighash bytes are included in a signature.  In this case, the sighash bytes are the single byte 0.

Most normal payments use a sighash of 0 (sign all inputs and outputs), so this will save a byte in this common signature format.

# Sighashtype Flag Byte

The only cryptographic hashing algorithm defined is the double SHA256, so no bits are used to specify the algorithm at this time.

The first byte of the sighash is the sighashtype flag byte.  It is divided into 2 parts, the upper (most significant) 4 bits, and the lower (least significant) 4 bits.  The upper bits define what data within the inputs used, and the lower bits determine the data in the outputs.  If additional bytes are needed, the input bytes come first, then the outputs.

## Input type flags

0: All inputs
 *no inputs can be added, removed, or modified*
 
1: First N inputs (where N is specified as 1 subsequent byte).
*Allows additional inputs to be added, so the transaction can be extended by other parties.  Note that if you want to sign 256 inputs, choose type 0*

2: This input
*Prevents signature prevout reuse by signing this input (and its outpoint hash).  Other inputs can be added, removed, or modified*

1,0: No inputs
*Note that the special case of no inputs is implementable via type 2 where N=0.  This signature can potentially be maliciously reused to sign other prevouts constrained by the same pubkey!!*

## Output type flags

0: All outputs
 *no inputs can be added, removed, or modified*

1: First N outputs (index N is specified as 1 subsequent byte)
*Allows additional outputs to be added, so the transaction can be extended by other parties.  Note that if you want to sign 256 outputs, choose type 0*
 
2: Two outputs N, M (index N and M are specified as 2 subsequent byte. To sign just 1 output, pass the same number twice)
*Note that this is an extremely common use case -- receiving something and paying yourself change.  All other outputs can be removed or modified, and additional outputs can be included*


1, 0: No outputs
*Note that the special case of no outputs is implementable via type 2 where N=0.  This is very dangerous -- whoever has this transaction can rewrite the outputs to take all of the money brought into the transaction, unless the outputs are secured by some other input, and that input is signed.*
