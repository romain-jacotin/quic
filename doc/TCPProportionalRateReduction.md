# Proportional Rate Reduction for TCP

Extracts from __rfc6937__ : [http://tools.ietf.org/html/rfc6937](http://tools.ietf.org/html/rfc6937)

-----------------------

## Table of Contents:

* [Overview](#overview)
* [Definitions](#definitions)

## <A name="overview"></A> Overview

Proportional Rate Reduction (PRR) algorithm is an experimental alternative to the widely deployed Fast Recovery and Rate-Halving algorithms. The goal is to improve the accuracy of the amount of data sent by TCP during loss recovery.

These algorithms determine the amount of data sent by TCP during loss recovery. PRR minimizes excess window adjustments, and the actual window size at the end of recovery will be as close as possible to the __ssthresh__, as determined by the congestion control algorithm.

## <A name="definitions"></A> Definitions

* __SND.UNA__ :
    * Oldest unacknowledged sequence number
* __duplicate ACK__ :
* __FlightSize__ :
    * The amount of data that has been sent but not yet cumulatively acknowledged
* __SMSS__ :
    * Sender Maximum Segment Size
* __Voluntary window reductions__ :
    * Choosing not to send data in response to some ACKs, for the purpose of reducing the sending window size and data rate

We define some additional variables:

* __SACKd__
    * The total number of bytes that the scoreboard indicates have been delivered to the receiver. This can be computed by scanning the scoreboard and counting the total number of bytes covered by all SACK blocks.  If SACK is not in use, SACKd is not defined.
* __DeliveredData__ :
    * is the total number of bytes that the current ACK indicates have been delivered to the receiver
    * When not in recovery:
        * __DeliveredData = SND.UNA + SACKd__
    * In recovery without SACK:
        * On duplicate acknowledgements:
            * __DeliveredData = 1 * SMSS__
        * On a subsequent partial or full ACK:
            * __DeliveredData = SND.UNA - 1 * SMSS__ for each preceding duplicate ACK

Note that DeliveredData is robust; for TCP using SACK, DeliveredData can be precisely computed anywhere in the network just by inspecting the returning ACKs.  The consequence of missing ACKs is that later ACKs will show a larger DeliveredData.  Furthermore, for any TCP (with or without SACK), the sum of DeliveredData must agree with the forward progress over the same time interval.

We introduce a local variable "sndcnt", which indicates exactly how many bytes should be sent in response to each ACK.  Note that the decision of which data to send (e.g., retransmit missing data or send more new data) is out of scope for this document.

## Algorithms

* At the beginning of recovery, initialize PRR state. This assumes a modern congestion control algorithm, <CODE>CongCtrlAlg()</CODE>, that might set __ssthresh__ to something other than __FlightSize/2__:

```
ssthresh = CongCtrlAlg()  // Target cwnd after recovery
prr_delivered = 0         // Total bytes delivered during recovery
prr_out = 0               // Total bytes sent during recovery
RecoverFS = snd.nxt-snd.una // FlightSize at the start of recovery
```

* On every ACK during recovery compute:

```
DeliveredData = change_in(snd.una) + change_in(SACKd)
prr_delivered += DeliveredData
pipe = (RFC 6675 pipe algorithm)
if (pipe > ssthresh) {
    // Proportional Rate Reduction
    sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
} else {
    // Two versions of the Reduction Bound
    if (conservative) {    // PRR-CRB
        limit = prr_delivered - prr_out
    } else {               // PRR-SSRB
        limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
    }
        // Attempt to catch up, as permitted by limit
        sndcnt = MIN(ssthresh - pipe, limit)
}
```

* On any data transmission or retransmission:

```
prr_out += (data sent) // strictly less than or equal to sndcnt
```



