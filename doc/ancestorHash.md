# Block Ancestor Hash
*Miners commit to an ancestor on this blockchain*

## Overview

Blocks commit to the hash of the previous block in order to form the blockchain.  This creates a linear chain.  So functions like determining whether a block is part of the chain that begins at a particular genesis block, or whether 2 blocks are on the same fork, or the oldest common ancestor of 2 blocks, requires iterating backwards through many block headers.  In practice this means that the block header must be cached locally.  Yet this operation can still take a lot of time, especially if the headers are not all stored in RAM.  To expedite these kinds of queries, full nodes and clients commonly build their own ancestor references as headers arrive.

By requiring that miners commit to ancestor headers, light clients (clients that choose to trust the validity of blocks that have a cumulative (the block and its descendants) proof of work greater than some chosen value) do not need to create and maintain these ancestor references.  This means that they do not need to access every block in the blockchain.

## Implementation

The ancestor hash field of the genesis block is 0.  The ancestor hash field of block at height "blockHeight" (>0) MUST contain the hash of the ancestor block at the height specified by the following algorithm:

if (blockHeight is even) return ZeroLeastSignificantSetBit(blockHeight)
if (blockHeight is odd) return max(0, height - 5040)

where:

ZeroLeastSignificantSetBit(blockHeight) = blockHeight & (blockHeight - 1)

### Rationale

 * First line:  By zeroing the least significant set bit, the height jumps backwards by a variable and exponentially increasing amount.  Additionally, ancestors of ancestors (recursively) of arbitrary blocks "funnel" to the same ancestor set.  This allows light clients to only keep the headers of a very few old blocks, yet still have the entire ancestor tree.

 * Second line: If the block height is odd, the algorithm in the first line produces the previous block as the ancestor.  This is redundant with the prevBlockHash field.  So instead, a linear ancestor is chosen with a nontrivial, but humanly useful backwards hop amount.  In this case, 5040 blocks is 1 week of Nexa's 2 minute average block interval.
 
These two different hop algorithms allow code to go backwards by either linear or exponential hops.  If the code is "at" a block with an undesirable hop algorithm, just follow the hashPrevBlock pointer to get to a block with the desired algorithm.


