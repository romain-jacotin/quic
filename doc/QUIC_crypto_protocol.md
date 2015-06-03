# QUIC Crypto Protocol

---------------------

## Table of Contents

* [Overview](#overview)
    * [Source-address Token](#token)
* [Wire Protocol](#wireprotocol)
* [Client Handshake](#clienthandshake)
    * [Client Hello message(CHLO)](#chlo)
    * [Rejection message (REJ)](#rej)
    * [Server Hello message (SHLO)](#shlo)
* [Key Derivation](#keyderivation)
* [Client Encrypted Tag Values (CETV)](#cetv)
* [Certificate Compression](#certificatecompression)

## <A name="overview"></A> Overview

### <A name="token"></A> Source-address Token

The goal of Source-address Token is to handle IP address spoofing: a QUIC Client must proves on each crypto request that it owns  its IP address by sending the Source-address token given by the QUIC Server on each requests.

A QUIC Client must first obtain a valid Token from the server:

* For the client a Source-address Token is just an opaque byte string
* For the server a Source-address Token is an authenticated-encryption block (ex: AES-GCM) created by the server that contains:
    * Client's IP address
    * A Timestamp

* source_address_token_future = 3600 seconds (=1h)
* source_address_token_lifetime = 86.400 seconds (=24h)

## <A name="wireprotocol"></A> Wire Protocol


## <A name="clienthandshake"></A> CLient Handshake

### <A name="chlo"></A> Client hello message (CHLO)

### <A name="rej"></A> Rejection message (REJ)

### <A name="shlo"></A> Server Hello message

## <A name="keyderivation"></A> Key derivation

## <A name="cetv"></A> Client Encrypted Tag Values (CETV)

## <A name="certificatecompression"></A> Certificate Compression


