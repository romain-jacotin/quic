[![GoDoc](https://godoc.org/github.com/romain-jacotin/quic?status.svg)](https://godoc.org/github.com/romain-jacotin/quic)

# QUIC Protocol in Go language

Work in progress on the High-Level API definition for QUIC programs in Golang.

**For official Google information about QUIC protocol, please consult the following website:**

* Official QUIC information at chromium.org :
    * [https://www.chromium.org/quic](https://www.chromium.org/quic)
* Chromium QUIC source code:
    * [https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/](https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/)
* QUIC Forum:
    * [https://groups.google.com/a/chromium.org/forum/#!forum/proto-quic](https://groups.google.com/a/chromium.org/forum/#!forum/proto-quic)

----------------------

## Table of contents:

* [Introduction](#introduction)
* [QUIC Session management](#quicsessionmngt)
    * [Initialization](#sessioninitialization)
        * [Client side](#clientside)
        * [Server side](#serverside)
    * [Termination](#sessiontermination)
        * [Close](#sessionclose)
        * [GoAway](#sessiongoaway)
        * [Reset](#sessionreset)
    * [Keep Alive](#sessionkeepalive)
        * [Timeout](#sessiontimeout)
        * [Ping](#sessionping)
    * [Pacing](#pacing)
        * [Auto-pacing](#autopacing)
        * [Minimum pacing](#minimumpacing)
* [Stream management](#streammngt)
    * [Creation](#streamcreation)
    * [Read](#streamread)
    * [Write](#streamwrite)
        * [Write (standard)](#standardwrite)
        * [Write with FEC](#fecwrite)
        * [Write with Duplicate QUIC packets](*duplicatewrite)
    * [Close (half)](#streamclose)
    * [Reset](#streamreset)
* [ANNEX A: Extracts from RFC793 - TCP](./doc/TCP.md)
* [ANNEX B: Extracts from RFC5681 _ TCP Congestion Control](./doc/TCPCongestionControl.md)
* [ANNEX C: Extracts from RFC6298 - Computing TCP's Retransmission Timer](./doc/TCPRetransmissionTimer.md)
* [ANNEX D: Extracts from draft-rhee-tcpm-cubic-02 - CUBIC Congestion Control for Fast Long-Distance Networks](./doc/CUBIC.md)

## <A name="introduction"></A> Introduction

## <A name="quicsessionmngt"></A> QUIC Session management

TBD

### <A name="sessioninitialization"></A> Initialization

TBD

#### <A name="clientside"></A> Client side

TBD

#### <A name="serverside"></A> Server side

TBD

### <A name="sessiontermination"></A> Termination

TBD

#### <A name="sessionclose"></A> Close

TBD

#### <A name="sessiongoaway"></A> GoAway

TBD

#### <A name="sessionreset"></A> Reset

TBD

## <A name="pacing"></A>Pacing

TBD

### <A name="autopacing"></A> Auto-pacing

TBD

### <A name="minimumpacing"></A> Minimum pacing

TBD

### <A name="sessionkeepalive"></A> Keep Alive

TBD

#### <A name="sessiontimeout"></A> Timeout

TBD

#### <A name="sessionping"></A> Ping

TBD

## <A name="streammngt"></A> Stream management

TBD

### <A name="streamcreation"></A> Creation

TBD

### <A name="streamread"></A> Read

TBD

### <A name="streamwrite"></A> Write

TBD

#### <A name="classicwrite"></A> Write (standard)

TBD

#### <A name="fecwrite"></A> Write with Forward Error Correction

TBD

#### <A name="duplicatewrite"></A> Write with Duplicate QUIC packets

TBD

### <A name="streamclose"></A> Close (half)

TBD

### <A name="streamreset"></A> Reset

TBD

### <A name="streampriority"></A> Priority

TBD

