[![GoDoc](https://godoc.org/github.com/romain-jacotin/quic/crypto?status.svg)](https://godoc.org/github.com/romain-jacotin/quic/crypto)

# QUIC Crypto Protocol in Go language

Work in progress on the crypto protocol and crypto handshake in Golang.

**For official Google information about QUIC protocol, please consult the following website:**

* Official QUIC information at chromium.org :
    * [https://www.chromium.org/quic](https://www.chromium.org/quic)
* Chromium QUIC source code:
    * [https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/](https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/)
* QUIC Forum:
    * [https://groups.google.com/a/chromium.org/forum/#!forum/proto-quic](https://groups.google.com/a/chromium.org/forum/#!forum/proto-quic)

----------------------

## Table of Contents

* [Overview](#overview)
* [Parsing crypto message](#parsing)
* [The Crypto Handshake](#handshake)
* [ANNEX A: Extracts from QUIC Crypto Protocol](../doc/QUIC_crypto_protocol.md)

## <A name="overview"></A> Overview

## <A name="parsing"></A> Parsing crypto message

## <A name="handshake"></A> The Crypto handshake

The crypto protocol on Stream Id=1 must be handle with the following constraints:

* During the crypto handshake phase:
    * __QUIC Client__
        * must only send one message type, and only once
            * __CHLO message__ : must fit into a single QUIC packet
    * __QUIC Server__
        * must respond only to unique __CHLO__ message with the following crypto message:
            * __REJ message__ : this is a stateless answer from the server, so QUIC Client must retry a new QUIC Connection with the new informations provided in the REJ response to move forward.
                * Violation to the following rules causes a REJ response from the QUIC server:
                    * __CHLO__ does not fit into a single QUIC packet
                    * QUIC version not supported
                    * Source-address Token is missing (__STK__)
                    * Bad Source-address Token (__STK__)
                    * Authenticated encryption algorithms not supported (__AEAD__)
                    * Key Exchange algorithms not supported (__KEXS__)
                    * Client nonce is missing (__NONC__)
                    * Bad client nonce (__NONC__)
                    * Server nonce is missing, if advertised by the server (__SNO__)
                    * Client’s public value is missing (__PUBS__)
                    * Bad client’s public value (__PUBS__)
                    * Bad client encrypted tag-values, if provided (__CETV__)
            * __SHLO message__ :
* After crypto handshahe complete:
    * __QUIC Client__
        * CAN'T send any crypto message: any single byte of data on Stream ID=1 cause QUIC Connection termination
    * __QUIC Server__
        * can only send one message type
            * __SCUP message__ : to notify the Client about the Server config update
