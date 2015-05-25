[![GoDoc](https://godoc.org/github.com/romain-jacotin/quic?status.svg)](https://godoc.org/github.com/romain-jacotin/quic)

# QUIC Protocol in Go language

Work in progress on the High-Level API definition for QUIC programs in Golang.

**For official Google information about QUIC protocol, please consult the following website:**

* Official QUIC information at chromium.org :
    * https://www.chromium.org/quic
* QUIC Forum:
    * https://groups.google.com/a/chromium.org/forum/#!forum/proto-quic

----------------------

## Table of contents:

* [QUIC Session management](#quicsessionmngt)
    * [Initialization](#sessioninitialization)
        * [Client side](#clientside)
        * [Server side](#serverside)
    * [Termination](#sessiontermination)
        * [Close](#sessionclose)
        * [GoAway](#sessiongoaway)
        * [Reset](#sessionionreset)
        * [Public Reset](#sessionpublicreset)
* [Stream management](#streammngt)
    * [Creation](#streamcreation)
    * [Read](#streamread)
    * [Write](#streamwrite)
        * [Write (standard)](#standardwrite)
        * [Write with FEC](#fecwrite)
        * [Write with Duplicate QUIC packet](*duplicatewrite)
    * [Close](#streamclose)
    * [Reset](#streamreset)


## <A name="quicsessionmngt"></A> QUIC Session management

### <A name="sessioninitialization"></A> Initialization

#### <A name="clientside"></A> Client side

#### <A name="serverside"></A> Server side

### <A name="sessiontermination"></A> Termination

#### <A name="connectionclose"></A> Close

#### <A name="publicreset"></A> Reset

## <A name="streammngt"></A> Stream management

### <A name="streamcreation"></A> Creation

### <A name="streamread"></A> Read

### <A name="streamwrite"></A> Write

#### <A name="classicwrite"></A> Write (standard)

#### <A name="fecwrite"></A> Write with Forward Error Correction

#### <A name="duplicatewrite"></A> Write with Duplicate QUIC packet

### <A name="streamclose"></A> Close

### <A name="streamreset"></A> Reset

There are 4 ways that streams can be terminated

* Normal termination: STREAM_FRAME received with FIN bit
* Abrupt termination: RESET_FRAME received
* QUIC connection teardown: CONNECTION_CLOSE_FRAME received
* Implicit timeout: (default idle timeout is 10 minutes)

