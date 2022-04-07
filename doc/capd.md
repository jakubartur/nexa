# Counterparty and Protocol Discovery (CAPD)

*A transient decentralized anonymous content-addressable messaging service that allows participants to to discover transaction partners and execute protocols with them. Proof of work is used to discourage spam.*

## Problem Statement

Counterparty discovery is currently a barrier to using many crypto-financial protocols in a trustless, anonymous, p2p manner. Unlike the entry of a long running node into a peer-to-peer network, these protocols are often of short duration, with selective discovery. In this context, selective discovery refers to the need to find a partner that fits very specific criteria rather than any of a large group of potential partners. Given the short duration of many crypto-financial protocols, discovery is a critical but often unspecified part of the full user experience. Coin mixing, atomic cross chain swaps, an;d any form of trade or bet are examples of short participation duration protocols that would benefit from a counterparty discovery service. Note also that any other form of service discovery (e.g. find a server implementing some protocol) could also benefit since service discovery can be thought of as counterparty discovery with very broad criteria.

One valuable "degenerate case" of this protocol is to enable discovery of, or low bandwidth peer-to-peer-like communications between, 2 specific entities that are both behind firewalls and have dynamic IP addresses.

We propose a counterparty and protocol discovery service (CAPD) running on Nexa nodes, taking advantage of existing P2P and blockchain features.

## Related Work

### Service Discovery

This protocol is similar to a class of protocols termed "service discovery". DNS and DHCP are notable examples of service discovery. But, service discovery tends to be focused on long lasting or local services, is not selective, and often has long update latency. It is therefore unusable for counterparty discovery.

wikipedia.org/wiki/Service_discovery

### Decentralized Exchange

Counterparty discovery protocols are a part of decentralized exchanges. Work on these protocols have occurred within the context of Ethereum. These protocols tend to be specifically tailored for exchange of tokens (typically ERC20 compliant) on Ethereum. They also are part of a larger protocol that completes a decentralized exchange. This makes them unusable or awkward to use for generalized counterparty discovery.

## Architecture

The network architecture consists of a set of anonymous, permissionless, IP accessible peer-to-peer nodes (called "peers") that store messages, and a set of "clients" that communicate with any peer to submit, retrieve, or search for messages, but do not store messages themselves. This is a semantic, not architectural distinction. A single node may behave as both peer and client. Nexa "full" nodes are leveraged to provide the peer nodes of this network (but it would be possible to make specialized CAPD-only nodes), and clients are typically light cryptocurrency wallets but actually may be any application. Leveraging the existing P2P bitcoin architecture makes implementing this functionality much simpler since it amounts to the addition of a few new P2P messages types and CAPD message storage.

### Message Pool

Peer nodes contain a configurable size memory buffer (typically a few hundred MB) containing arbitrary messages (called the msgPool).  Note that these "messages" are different from bitcoin P2P messages, where unclear this document will use CAPD message or P2P message to distinguish.

New CAPD messages are received from peers or clients and inserted into a peer's msgPool. If the pool is full, new messages knock out old messages based on priority (see section Message Priority). More formally, if the pool is full and the incoming message's priority is higher than the N lowest priority messages in the pool whose cumulative length is greater than or equal to the new message length, then the incoming message will replace these messages.

Messages are relayed to nodes if the message's priority is greater than a cutoff set by the destination node.

Although message priority is dynamic -- based on message age, priority declines uniformly as time progresses.  So it is not hard to maintain a priority based heap of all messages in the msgPool, since the relative priority of 2 CAPD messages will never change.

Messages can also be removed from the pool based on an expiration timestamp specified in the message, or via an explicit rescind message.

Ideally, Clients could query announcements through a ternary content-addressable memory (TCAM) of the first 16 bytes of the message's "payload" data. In review, a TCAM allows one to find matches based on a bitmask that indicates relevant bits and their value. In practice the first version will be limited to lookups on the first 2, 4, 8 or 16 bytes. Although this qualification significantly limits the theoretical possibilities, in practical communications the announcer generally knows the subset of its message that clients may want to select upon, and can zero-pad this data to the next 2,4,8, or 16 byte boundary.

However, it is possible to achieve full generality and tremendous performance by using hardware TCAMs. TCAM chips are an essential part of network routers and 20Mbit capacity cascadable TCAM chips that are capable of 320 million lookups per second are available (Renseas) today. There is every indication that these chips will be needed for networking routers for the foreseeable future, and will grow in capacity as silicon process technology allows.

Since the first 16 bytes of each message are TCAM addressable, these bytes are used to allow peers to find messages of interest. The exact content of these bytes is application specific, but for example, the first 2 bytes could define a "protocol id", and the next 6 client constraints. If "atomic swap" was implemented as protocol id 1, then 3 bytes of offer ticker, and 3 of ask ticker then "01BCHNEX" could request a Bitcoin Cash to Nexa cryptocurrency trade. The end client would then be presented with every open trade offer, and would use additional message bytes to determine the offer details (ask price for example). If different message types have a collision in these bytes, service degradation is graceful. Peers receive some useless messages.

By convention, message replies are addressed to the original sender by setting the 16 TCAM bytes of the reply to the last bytes (the opposite bytes as used for POW) of the hash of the original message.

It is difficult for an attacker to personally flood a message originator with reply spam due to the proof-of-work that is part of a message's priority (see Message Format section).

It is also hard for an attacker to entice other clients to flood a message originator with replies by creating other, "enticing" messages (atomic trade for BTC at $1) with the same reply address. Such a message must both match the 10 byte TCAM address, and contain sufficient POW (which are different bits) to pass the priority cutoff. This means that an attacker must "grind" hashes to find 80 + message POW matching bits.

### Message Format

Messages semantically come in 2 types: "global" and "local", but this distinction is not explicit in the message format.

Messages have an attribute called "priority" that is calculated as a function of message proof-of-work, message proof-of-age, and message length. When the msgPool is filled, existing messages are replaced by new messages based on priority. Nodes communicate desirable messages to other peers via 3 values:

The minimum forwarding priority defines the lowest priority message that this node will forward to other nodes.

The minimum insertion priority defines the lowest priority message that this node will place into its message pool.

The ban priority defines the lowest priority message that this node will accept and not ban the peer or client node.

As described above, a message will not be forwarded if it is below either the minimum forwarding priority of this node, and that of the remote node. Peer nodes will typically specify this minimum forwarding priority to be greater than the bottom ¼ to ½ of its msgPool. This allows a client to place a "local" message into a node's msgPool by searching for proof-of-work that is lower than the minimum forwarding priority but higher than the ban priority.  It also minimizes message pool turnover and makes spam attacks more difficult. 

The minimum insertion priority is simply the lowest priority message in the message pool.

The ban priority ensures that a network DoS attack by sending the node low priority messages is harder to accomplish. However, it should be well below the minimum insertion priority because the minimum insertion priority is dynamic and the message priority decreases over time. It is recommended that the ban priority be ½ or less of the minimum insertion priority.

#### Message Contents

*creation time*: the time the message was created in seconds since the epoch. Message priority declines as the message gets older, but messages that claim a future creation time are rejected. Lying about this number is not useful, because making it older simply means the creator will need to generate more proof of work to keep the message in the pool for the same time, and making it younger means the message will be rejected until that time.

*expiration*: (optional) expiration time in seconds since the epoch. Nodes mark this message as expired after this time. Messages marked expired will not be relayed to any peers. The reason these messages are not removed is to stop a DoS attack during low use (and therefore low POW) periods. At these times, if expired messages were deleted, a malicious peer could cheaply flood the network with short-lived messages without raising the POW required for admission. To further mitigate DoS attacks, messages are not recommended to be relayed if they expire within 5 minutes.

*rescind hash*: (optional) hash of a secret chosen by the issuer. Publishing the secret instructs all participants to mark this message as expired in the msgPool. Messages marked expired will not be relayed to any peers or clients. As above, the reason these messages are not immediately removed from the msgPool is to stop DoS attacks during low POW periods.

Respecting the rescind messages is not strictly necessary for proper operation; it is offered as a convenience to minimize responses to a message where only one responder is needed.

*payload data*: arbitrary bytes of user data.

16 byte TCAM: The first 16 bytes are special in that they can be used by clients to filter interesting messages.

Reply to peer IP Address/port (optional): This allows an efficient reply (and resulting conversation) with some loss of anonymity. A client has the option to connect directly to the node indicated here and issue "local" priority messages to be heard by the other node. Of course, a client that wants to preserve anonymity can choose not to do so by sending a "global" priority message to any peer node.

Any other data (optional): Additional conversation-specific data that may be used to narrow the peer search down further than the TCAM, to implement a protocol, or to contain connection information using a protocol beyond the scope of this document.

*nonce*: a byte vector used in calculating proof of work, containing between 1 and 8 bytes, inclusive

*difficultyBits*: (uint32) Message proof of work must meet or exceed this target.  This field is specified in the same format as Bitcoin's "nBits" field (eg. nBits as 0xSSVVVVVV becomes VVVVVV << ((SS-3)*8))

#### Message Proof of Work

Messages contain proof of work which is calculated as:

SHA256(SHA256(nonce ++ SHA256(data ++ create time ++ rescind hash ++ expiration ++ difficultyBits)))

where ++ denotes binary string concatenation of bitcoin-style serialized objects. Use 0s for any unpopulated optional field (e.g. rescind hash or expiration).

Note that the innermost SHA256 reduces the message to a 32 byte data object to "grind" against the nonce. The outer two SHA256 are how proof-of-work is calculated. Like Bitcoin proof-of-work, it is necessary to use a double SHA256 so that an algorithm cannot save intermediate states of the SHA256 operation to check a nonce in less time than 1 SHA256.

To eliminate spam, message creators must generate proof-of-work before forwarding a message to nodes, and this proof-of-work is used to calculate the message priority. Nodes calculate the minimum acceptable forwarding and ban priority by looking at the contents of their msgPool, and forward these values to peer nodes. The forwarding priority minimum is implementation defined, but generally calculated so that at least ¼ to 1/2 of the messages in the msgPool contain a lower priority. If a message is in the lower tier, it is no longer announced, but is available to clients via query requests.

Peer nodes that forward messages lower than the ban priority are considered "misbehaving". Nodes with enough misbehavior are banned. However, note that the receiving node must keep track of the ban priority that it communicated to the sending node rather than banning based on a message's instantaneous msgPool insertion position.

#### Message Priority

The priority algorithm converts a CAPD message into a number that determines the ordering of message removal from the message pool (the lowest priority messages are removed first).

Priority(msgContentLength, ageInSeconds, proofOfWorkTarget) -> Integer

First divide the min difficulty (0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) by the hash target.
x = min_difficulty/proofOfWorkTarget

Next, if the message is greater than the "nominal message size" (100 bytes), divide that by the message content length and multiple by the nominal message size:
if (msgContentLength > 100) x = (x/msgContentLength)*100.0

Subtract the age penalty which is calculated by as (x/600)*age.  This linear relation causes the message priority to cross 0 after 10 minutes (10*60 seconds), regardless of its initial priority.
x = x - (x/600)*age

Return x as the priority.


### Message Replies

Message replies are not distinguishable from other messages, except that they are prefixed with 16 bytes of the original message's hash. So message replies need to calculate POW, etc, as described above. The message is then either sent directly to a destination IP (if desired by both parties), or forwarded to any node.

## Node Protocol

Nodes follow the Nexa P2P protocol, which is beyond the scope of this specification.  The information provided here is sufficient to allow anyone already familiar with the Bitcoin P2P node protocol to add the CAPD specific messages.

### CAPD message serialization

P2P messages that serialize a CAPD message use the following format:

**fields** (1 byte) -- set bit 0 if an expiration is provided, set bit 1 if a rescind hash is provided
**createTime** (uint64) -- When this message was created (seconds since epoch)
**difficultyBits** (uint32) -- The message's proof of work target
**nonce** (byte vector) -- arbitrary data between 1 and 8 bytes inclusive
**expiration** (uint16) -- expiration time in seconds since createTime (0xFFFF or not providing the field means never expire).
**rescindHash** (20 bytes) -- rescind this message if the preimage of this hash is provided (0 or not providing the field means never rescind)
**data** (byte vector) -- CAPD message payload

### ExtVersion / XUpdate:

Send CAPD protocol version to peers.

CAPD support is signaled with key 0x000000020000000e.  The current protocol version is 1.

### CAPD Get Info
*Message ID: capdgetinfo*

Requests a CAPD info message from a peer.

### CAPD Info
*Message ID: capdinfo*

Inform peers of this node's CAPD state, including the minimum local priority, the relay priority, and the highest priority message in the message pool.

Each field is serialized as a 64 bit double in the following order:
local priority, relay priority, highest priority

### CAPD Inventory
*Message ID: capdinv*

Nodes pass bloom filters hashes, or hash prefixes of newly arrived messages.

### CAPD Get Message
*Message ID: capdgetmsg*
Request messages by hash or hash prefix (generally announced via inventory).

### CAPD Message
*Message ID: capdmsg*
Provide a message to a peer.  If the provided message passes validity and relay checks, the remote node will notify all peers of its existence via CAPD inventory messages.

### CAPD Query, QueryNotify
*Message ID: capdquery*

Request data on messages that match certain bits, either immediately or ongoing.

### CAPD Query Reply
*Message ID: capdqreply*

Reply with messages or message hashes that match the provided query pattern.

### CAPD RemoveQueryNotify:

TBD

Stop notifying (undo a prior query that has notification set) a peer of query matches.


## HTTP JSON Client Protocol

To enable access from javascript browser plugins and programatically simple access from high level languages, nodes will also support a json-formatted protocol running over http.

# Future Directions

### Payment

The first version of this protocol assumes that this service is offered for free. However, most conceived uses eventually involve transactions on the Nexa network, so this "free" service will create additional fee paying transactions, and creates use and adoption of the Nexa cryptocurrency. Therefore it may be reasonable to expect that this service will be offered for free by miners and holders of BCH for some time.

However, it is possible to introduce a micropayments system to pay for the use of certain aspects of the protocol, namely the filtering service provided through the Query and QueryNotify messages.

It is expected that if this service becomes quite popular the POW required for a message may exceed the capabilities of some clients. In this case, the client could pay a service to solve messages, either via a micropayment channel or a trust relationship (i.e. the wallet pays for 100 "solves" in advance and trusts the hash provider to provide 100 solves at some later date). Clearly, paying in the form of 1 transaction per solved message defeats the purpose of the message pool, unless the message is extremely large.

### Persistent Messages

This first version acts as a communication medium for active agents -- connecting two entities that would like to interact right now. However, it can be easily extended into a message system with storage (i.e. messages persist).

In its basic operation, wallets open a payment channel to one or several full nodes and send the full node micropayments, message retention duration, and filter information. Note that perhaps the service is offered for free, but this opens a storage-exhaustion attack where wallets request storage on every network node — so some effort or identity is required to be given by the wallet. Full nodes store all messages that match the filter until the wallet retrieves them, or the purchased duration is exceeded. Full nodes could drop messages and lie about it, but wallets can subscribe to multiple full nodes. So this service ultimately still acts like email as a "best effort" delivery.

Guaranteed provably delivered messages are already solved as OP_RETURN data inside a blockchain transaction.

If these guaranteed provably delivered messages become quite popular, a merkle-tree commitment on the blockchain to an independently-created "message block" and bloom or columb-rice filter (to support a "neutrino" like query protocol) can be used to commit to any number of messages in a single blockchain transaction. Unlike blockchain blocks, the network participants by convention "agree" to retain and serve this message block for a minimum well known but limited time, for example, 1 week (note, different message blocks could have different retention times). Entities who use this service and require "proof-of-send" independently retain a merkle-proof path to the message they must prove. The proof consists of the blockchain block headers, the merkle proof to the commitment transaction (in the blockchain block) and the merkle proof to the message in the message block.

The combination of a merkle-tree and bloom filter commitment is quite powerful. Bloom filters are insecure in the sense that if a server wants to hide a transaction, it can create and feed to a client a series of other transactions (not in the original block) that "explain" the bloom filter's value without including the hidden transaction. This effort can be made arbitrarily hard by reducing the bloom filter false positive error rate, but this increases the bloom filter size. Instead of increasing the bloom filter size, a merkle-tree commitment means that the client can force the server to prove inclusion of the transactions used to explain the bloom filter.

Therefore, to hide a transaction, the server would have to create these transactions before the block is committed, so that they are actually included in the block. Note that there is a chance, controlled by the bloom false positive rate, that a set of independently created transaction would accidentally explain the bloom filter bits.

Therefore the only solution (to be absolutely certain of a false positive) is to request the entire block when the filter matches (as per the "neutrino" protocol).

### Sharding
This proposal currently forwards every "global" message that meets a certain priority to every peer. But if the size of all active, "useful" messages is much larger than the msgPool size on all nodes, the system will gracefully degrade from a platform where message POW is used to block DOS attacks but everybody gets service into a platform where service is essentially purchased by calculating POW, and only the highest bidders get service. This is a problem because higher message POW only wastes energy; it does not provide value to any recipient so there is both no intrinsic reason for this scarcity, and its "payment" does not create surplus that can be used to expand service.

In such a situation, it would be possible to make micropayments for local message storage. It would also be possible to pay a peer to grind POW on your behalf.

However, unlike a blockchain, it is possible for the network as a whole to store many more messages than any particular node by sharding the stored messages.

One simple implementation is for each node to store a subset of the messages based on a bit mask of the message's TCAM content. Since messages generally identify their protocol via type bytes inside the TCAM, this allows nodes to handle a subset of protocols or even a subset of messages within a protocol. But this requires a protocol where clients are able to discover nodes that are handling specific content. CAPD itself could be used to advertise peers that handle TCAM subsets, and additional message priority levels could be created per node for messages that contain a particular TCAM pattern. For now, no such sharding will be implemented.

### End-to-end Encryption, Onion Routing and Homomorphic Encryption
This proposal allows end-to-end encryption via any application-defined protocol, but putting a standard in place may help implementations. Additionally, filter criteria is exposed from the client to the peer. A subsequent version may do better in regards to anonymity and security both in this protocol and by defining an end-to-end standard, but likely with a large performance penalty.
