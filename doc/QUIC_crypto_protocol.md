# QUIC Crypto Protocol

Extracts from official __QUIC Crypto__ document:  
[https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g](https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g)

---------------------

## Table of Contents

* [Overview](#overview)
    * [Source-address Token](#token)
    * [Handshake costs](#handshakecosts)
* [Handshake message format](#handshakemessage)
* [Client Handshake](#clienthandshake)
    * [Client Hello message(CHLO)](#chlo)
    * [Rejection message (REJ)](#rej)
    * [Server Hello message (SHLO)](#shlo)
* [Key Derivation](#keyderivation)
* [Client Encrypted Tag Values (CETV)](#cetv)
* [Certificate Compression](#certificatecompression)
* [ANNEX A: Tag list](#taglist)

## <A name="overview"></A> Overview

### <A name="token"></A> Source-address Token

The goal of Source-address Token is to handle IP address spoofing: a QUIC Client must proves on each crypto request that it owns  its IP address by sending the Source-address token given by the QUIC Server on each requests.

A QUIC Client must first obtain a valid Token from the server:

* For the client a Source-address Token is just an opaque byte string
* For the server a Source-address Token is an authenticated-encryption block (ex: AES-GCM) created by the server that contains:
    * Client's IP address
    * Token's timestamp

Token duration validation is the responsability of the server:

* source_address_token_future = 3600 seconds (=1h)
* source_address_token_lifetime = 86.400 seconds (=24h)

### <A name="handshakecosts"></A> Handshake cost

In QUIC, the server's preference are fully enumerated and static. They are bundled, along with Diffie-Hellman public values into a "server config". This server config has an expiry and is signed by the server's private key. __Because the server config is static, a signing operation is not needed for each connection__, rather a single signature suffices for many connections.

The keys for a connection are agreed using Diffie-Hellman. The server's Diffie Hellman value is found in the server config and the client provides one in its first handshake message. Because the server config must be kept for some time (several days) in order to allow 0-RTT handshakes (leak risk), immediately upon receiving the connection, the server replies with an ephemeral Diffie-Hellman value and the connection is rekeyed.

The server needs only the following to process QUIC connections:

* The static server config value (server don't need the private key for the certificate)
* The Diffie-Hellman private value

__The private key for the certificate need never be placed on the server.__

A form of short-lived certificates can be implemented by signing short-lived server configs and installing only on those server.

## <A name="handshakemessage"></A> Handshake message format

The crypto protocol consist of arbitrary sized messages send over a dedicated stream in QUIC (__STREAM ID=1__). These messages have a uniform, key-value format.

The keys are opaque 32-bit tags:

* All values are little-endian
* example: '__EXMP__' key --> __0x504d5845__ (little-endian)
* If a tag is written in ASCII but is less than 4 characters then it's as if the remaining characters were NUL:
    * example: '__EXP__' --> __0x505845__
* If the tag value contains bytes outside of the ASCII range, they'll be written in hex

A Handshake message consists of:

1. Tag of the message (uint32)
2. The number of tag-value pairs (uint16)
3. Two byte of padding which should be zero (uint16 = 0x0000)
4. Series of tags (uint32) and end offsets (uint32), one for each tag value pair:
    * Tags must be strictly monotonically increasing
    * End-offsets must be monotonic non-deccreasing
    * End-offset gives the offset, from the start of the value data, to a byte one beyond the end of the data for that tag
5. The value data, concatenated without padding

The tag value format allows for an efficient binary search for a tag after only a small fraction of the data has been validated.
The requirement that the tags be strictly monotonic also removes any ambiguity around duplicate tags.

## <A name="clienthandshake"></A> Client Handshake

Initially the client knows nothing about the server. Before a handshake can be attempted the client will send inchoate client hello messages to elicit a server config and proof of authenticity from the server.

To perform 0-RTT handshake, the client needs to have a server config that has been verified to be authentic.

### <A name="chlo"></A> Client hello message (CHLO)

Client Hello messages have the message tag __CHLO__ and, in their inchoate form, contain the following tag/value pairs:

* __SNI__ (optional) Server Name Indication
* __STK__ (optional) Source-address Token
* __PDMD__ (optional) Proof demand: list of tags describing the types of proof acceptable to the client, in preference order (X509)
* __CCS__ (optional) Common Certificate Sets: list of 64-bit FNV-1A hashes of sets of common certificates that the client possesses
* __CCRT__ (optional) Cached Certificates: series of 64-bit FNV-1A hashes of cached certificates for this server
* __VERS__ (MANDATORY) Version: single tag that mirrors the protocol version advertised by the client in each QUIC packet

In response to a client hello (__CHLO__) the server will either send a rejection message (__REJ__), or a server hello (__SHLO__):

* __REJ__ message contain information that the client can use to perform a better handshake attempt subsequently.
* __SHLO__ message indicates a successfull handshake and can never result from an inchoate CHLO as it doesn't contain enough information to perform a handshake.

### <A name="rej"></A> Rejection message (REJ)

Rejection message have the tag __REJ__ and contain the following tag/value pairs:

* __SCFG__ (optional) Server's Serialized Config
* __STK__ (optional) opaque byte string that the client must echo in future hello messages
* __SNO__ (optional) Server Nonce that the client should echo in any future (full) CHLO message
* __??__ (optional) Certificate Chain
* __PROF__ (optional) Proof of Authenticity, in cas of X509, a signature of the server config by the public key in the leaf certificate. The format of the signature is currently fixed by the type of public key:
    * __RSA__ RSA-PSS-SHA256
    * __ECDSA__ ECDSA-SHA256
    * The signature is calculated over:
        1. The label "QUIC server config signature"
        2. An 0x00 byte
        3. The serialised server config

Although all the elements of the rejection message are optional, the server must allow the client to make progress.

### <A name="shlo"></A> Server Hello message (SHLO)

## <A name="keyderivation"></A> Key derivation

## <A name="cetv"></A> Client Encrypted Tag Values (CETV)

## <A name="certificatecompression"></A> Certificate Compression

## <A name="taglist"></A> ANNEX A: Tag list

### Special tags

These tags have a special form so that they appear either at the beginning or the end of a handshake message. Since handshake messages are sorted by tag value, the tags with 0 at the end will sort first and those with 255 at the end will sort last.

The certificate chain should have a tag that will cause it to be sorted at the end of any handshake messages because it's likely to be large and the client might be able to get everything that it needs from the small values at the beginning.

Likewise tags with random values should be towards the beginning of the message because the server mightn't hold state for a rejected client hello and therefore the client may have issues reassembling the rejection message in the event that it sent two client hellos.

* __SNO (+ 0x00)__ The server's nonce
* __STK (+ 0x00)__ Source-address token
* __CRT (+ 0xFF)__ Certificate chain

### Message tags

* __CHLO__ Client hello
* __SHLO__ Server hello
* __SCFG__ Server config
* __REJ__ Reject
* __CETV__ Client encrypted tag-value pairs
* __PRST__ Public reset
* __SCUP__ Server config update

### Key exchange methods

* __P256__ ECDH, Curve P-256
* __C255__ ECDH, Curve25519

### AEAD algorithms

* __NULL__ null algorithm
* __AESG__ AES128 + GCM-12
* __CC12__ ChaCha20 + Poly1305

### Socket receive buffer

* __SRBF__ Socket receive buffer

### Congestion control feedback types

* __QBIC__ TCP cubic

### Connection options (COPT) values

* __TBBR__ Reduced Buffer Bloat TCP
* __RENO__ Reno Congestion Control
* __BYTE__ TCP cubic or reno in bytes
* __IW10__ Force ICWND to 10
* __PACE__ Paced TCP cubic
* __1CON__ Emulate a single connection
* __NTLP__ No tail loss probe
* __NCON__ N Connection Congestion Ctrl
* __NRTO__ CWND reduction on loss
* __TIME__ Time based
* __MIN1__ Min CWND of 1 packet

### Optional support of truncated Connection IDs

* __TCID__ Connection ID truncation

If sent by a peer, the value is the minimum number of bytes allowed for the connection ID sent to the peer.

### FEC options

* __FHDR__ FEC protect headers

### Enable bandwidth resumption experiment

* __BWRE__ Bandwidth resumption
* __BWMX__ Max bandwidth resumption

### Proof types (i.e. certificate types)

* __X509__ X.509 certificate, all key types
* __X59R__ X.509 certificate, RSA keys only
* __CHID__ Channel ID

Although it would be silly to do so, specifying both __X509__ and __X59R__ is allowed and is equivalent to specifying only __X509__.

### Client hello tags

* __VER__ Version (new)
* __NONC__ The client's nonce
* __KEXS__ Key exchange methods
* __AEAD__ Authenticated encryption algorithms
* __CGST__ Congestion control feedback types
* __COPT__ Connection options
* __ICSL__ Idle connection state lifetime
* __SCLS__ Silently close on timeout
* __MSPC__ Max streams per connection
* __IRTT__ Estimated initial RTT in us
* __SWND__ Server's Initial congestion window
* __SNI__ Server name indication
* __PUBS__ Public key values
* __SCID__ Server config id
* __ORBT__ Server orbit
* __PDMD__ Proof demand
* __PROF__ Proof (signature)
* __CCS__ Common certificate set
* __CCRT__ Cached certificate
* __EXPY__ Expiry
* __SFCW__ Initial stream flow control receive window
* __CFCW__ Initial session/connection flow control receive window
* __UAID__ Client's User Agent ID

### Rejection tags
* __RREJ__ Reasons for server sending rejection message tag

### Server hello tags
* __CADR__ Client IP address and port

### CETV tags
* __CIDK__ ChannelID key
* __CIDS__ ChannelID signature

### Public reset tags
* __RNON__ Public reset nonce proof
* __RSEQ__ Rejected sequence number

### Universal tags
* __PAD__ Padding

