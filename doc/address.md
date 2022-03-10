
# Nexa Addressing

## Bech32

Nexa uses Bech32 addressing.  It follows the [CashAddr](https://reference.cash/protocol/blockchain/encoding/cashaddr) format, with a few modifications as described below.  

For succinctness, this specification does not stand alone -- it defines a change set to CashAddr.

### Address Lengths

All length restrictions are removed.

### Version Byte

The CashAddr version byte (first byte) section should be replaced with this information:

The first byte MUST be 152.  This begins each address with "n", and defines the contents as specified below.

## Base58

Base58 encoding is not recommended.  It is not necessary to for services to accept Base58 encoded addresses.  However, if used, the prefix should be the 1 byte value "8", and the contents as specified below.

## Address Contents

The contents of an address is a serialized output script.  All such scripts are assumed to be script templates.  If the script defines a group (tokens) but not a token quantity, use OP_0 as the quantity.  This will render the output script illegal until the sender modifies the script with their desired token quantity.  Addresses MAY also specify a desired quantity by including the field... which, of course, may be overridden by the sender or not as the sender chooses.

The following sections apply the above description to clarify the address contents for common use cases (but do not add any additional info).

*Note that since script template formatted output scripts are easily distinguishable from most other output scripts, this restriction may be selectively eased for other script types.*

See dstencode_tests.cpp for test vectors.

### Ungrouped Pay-to-public-key-template (P2PKT) Form

OP_0  # No group
OP_1  # Well known template 1
PUSH Hash160(Script(PUSH pubkey))
[Optional: TBD additional data (do not rely on the size to identify this address form)]

**Example**
nexa:nqtsq5g5w6syq5aa5z5ghkj3w7ux59wrk204txrn64e2gs92

### Grouped, Unspecified Token Amount, Pay-to-public-key-template (GP2PKT) Form  
  
PUSH GroupId
OP_0  # Unspecified token amount
OP_1  # Well known template 1  
PUSH Hash160(Script(PUSH pubkey))
[Optional: TBD additional data (do not rely on the size to identify this address form)]

**Example**
nexa:nqazqy3uqsp4j0zyyufqzy65qc2u9vvm2jthyqgzqvzq2ps8pqys5zcvqgqqq5g5w6syq5aa5z5ghkj3w7ux59wrk204txrn92xzqzsu

### Ungrouped Pay-To-Contract-Args-Template (P2CAT) Form  
  
OP_0  # No group  
PUSH Hash160/256(Script(... your contract...))
PUSH Hash160/256(Script(PUSH your args ...))
[Optional: PUSH visible args]...
[Optional: TBD additional data]...

**Example**
nexa:nq4sq9rk5pq980dq4z9a55thhp4ptsajna2esuc5zg7qgq6e83zzwyspzd2qv9wzkxd4f9mjwp6hsdfn

### Grouped, Pay-To-Contract-Args-Template (GP2CAT) Form   
 
PUSH GroupId  
OP_0  # Unspecified token amount  
PUSH Hash160/256(Script(... your contract...))  
PUSH Hash160/256(Script(PUSH your args ...))  
[Optional: PUSH visible args]...  
[Optional: TBD additional data]...

**Example**
nexa:np9sq9rk5pq980dq4z9a55thhp4ptsajna2esuc5zg7qgq6e83zzwyspzd2qv9wzkxd4f9mjzg7qgq6e83zzwyspzd2qv9wzkxd4f9mjqypqxpq9qcrsszg2pvxq3p2q9kaa

### Ungrouped Pay-To-Contract-Template (P2CT) Form  (no args)
  
OP_0  # No group  
PUSH Hash160/256(Script(... your contract...))
OP_0 # No args
[Optional: PUSH visible args]...
[Optional: TBD additional data]...

nexa:nqtsq9rk5pq980dq4z9a55thhp4ptsajna2esucqqj42vk56
