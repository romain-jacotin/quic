[![GoDoc](https://godoc.org/github.com/romain-jacotin/quic/protocol?status.svg)](https://godoc.org/github.com/romain-jacotin/quic/protocol)

# QUIC Protocol in Go language

Work in progress on the QUIC protocol in Golang.

**For official Google information about QUIC protocol, please consult the following website:**

* Official QUIC information at chromium.org :
    * [https://www.chromium.org/quic](https://www.chromium.org/quic)
* Chromium QUIC source code:
    * [https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/](https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/)
* QUIC Forum:
    * [https://groups.google.com/a/chromium.org/forum/#!forum/proto-quic](https://groups.google.com/a/chromium.org/forum/#!forum/proto-quic)

----------------------

## Table of Contents

* [RingBuffer](#ringbuffer)

## <A name="ringbuffer"></A> RingBuffer

__RingBuffer__ is a FIFO buffer with a fixed size in bytes (data copy is handled as a circular buffer):
* Read() method extract data from the RingBuffer by copying them
* Write() method copy new data into the RingBuffer

It is safe to have concurrent Read() and Write(). But it is not safe to use it as is with more than one Reader, or more than one Writer on the same RingBuffer: in this case a synchronization mechanism is needed to serialize Readings and Writings.


