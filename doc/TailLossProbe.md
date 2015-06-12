# Tail Loss Probe

Extracts from __draft-dukkipati-tcpm-tcp-loss-probe-01__ : [https://tools.ietf.org/html/draft-dukkipati-tcpm-tcp-loss-probe-01](https://tools.ietf.org/html/draft-dukkipati-tcpm-tcp-loss-probe-01)

-----------------------

## Table of Contents

* [Overview](#overview)
* [Loss Probe algorithm](#algo)
    * [Pseudocode](#pseudocode)
    * [Example](#example)
    * [FACK threshold based recovery](#fack)

## <A name="overview"></A> Overview

Retransmission timeouts are detrimental to application latency, especially for short transfers such as Web transactions where timeouts can often take longer than all of the rest of a transaction.

__The primary cause of retransmission timeouts are lost segments at the tail of transactions.__

This document describes an experimental algorithm for TCP to quickly recover lost segments at the end of transactions or when an entire window of data or acknowledgments are lost.

__Tail Loss Probe (TLP) is a sender-only algorithm that allows the transport to recover tail losses through fast recovery as opposed to lengthy retransmission timeouts:__

* If a connection is not receiving any acknowledgments for a certain period of time, TLP transmits the last unacknowledged segment (loss probe).
* In the event of a tail loss in the original transmissions, the acknowledgment from the loss probe triggers SACK/FACK based fast recovery.

TLP effectively avoids long timeouts and thereby improves TCP performance.

## <A name="algo"></A> Loss probe algorithm

__The Loss probe algorithm is designed for a sender to quickly detect tail losses without waiting for an RTO.__

We will henceforth use tail loss to generally refer to either drops at the tail end of transactions or a loss of an entire window of data/ACKs.

* TLP works for senders with SACK enabled and in Open state, i.e. the sender has so far received in-sequence ACKs with no SACK blocks.

The risk of a sender incurring a timeout is high when the sender has not received any ACKs for a certain portion of time but is unable to transmit any further data either because it is application limited (out of new data to send), receiver window (rwnd) limited, or congestion window (cwnd) limited. For these circumstances, the basic idea of TLP is to transmit probe segments for the specific purpose of eliciting additional ACKs from the receiver.

The initial idea was to send some form of zero window probe (ZWP) with one byte of new or old data.
The ACK from the ZWP would provide an additional opportunity for a SACK block to detect loss without an RTO.
Additional losses can be detected subsequently and repaired as SACK based fast recovery proceeds.
However, in practice sending a single byte of data turned out to be problematic to implement and more fragile than necessary.
Instead we use a full segment to probe but have to add complexity to compensate for the probe itself masking losses.

Define probe timeout (__PTO__) to be a timer event indicating that an ACK is overdue on a connection:

* __SRTT__ = smoothed RTT
* __PTO = max(2 * SRTT, 10ms)__
* __PTO__ value is adjusted to account for delayed ACK timer when there is only one outstanding segment.

The basic version of the TLP algorithm transmits one probe segment after a probe timeout if the connection has outstanding unacknowledged data but is otherwise idle, i.e. not receiving any ACKs or is cwnd/rwnd/application limited.

* The transmitted segment, aka loss probe, can be either a new segment if available and the receive window permits, or a retransmission of the most recently sent segment, i.e., the segment with the highest sequence number.
* When there is tail loss, the ACK from the probe triggers fast recovery.
* In the absence of loss, there is no change in the congestion control or loss recovery state of the connection, apart from any state related to TLP itself.

__TLP MUST NOT be used for non-SACK connections:__

* SACK feedback allows senders to use the algorithm described in section 3 to infer whether any segments were lost.

### <A name="pseudocode"></A> Pseudocode

* __FlightSize__: amount of outstanding data in the network as defined in [RFC5681](#https://tools.ietf.org/html/rfc5681)
* __RTO__: The transport's retransmission timeout ( RTO ) is based on measured round-trip times ( RTT ) between the sender and receiver, as specified in [RFC6298](https://tools.ietf.org/html/rfc6298) for TCP
* __PTO__: Probe timeout is a timer event indicating that an ACK is overdue ( PTO <= RTO )
* __SRTT__: smoothed round-trip time computed like in [RFC6298](https://tools.ietf.org/html/rfc6298)
* __Open state__: the sender has so far received in-sequence ACKs with no SACK blocks, and no other indications (such as retransmission timeout) that a loss may have occurred
* __Consecutive PTOs__: back-to-back PTOs all scheduled for the same tail packets in a flight
    * The ( N+1 )st PTO is scheduled after transmitting the probe segment for Nth PTO

The TLP algorithm works as follows:

* __(1)__ Schedule PTO after transmission of new data in Open state:
    * Check for conditions to schedule PTO outlined in step __2__ below.
    * If __FlightSize > 1__
        * then schedule __PTO__ in __max( 2*SRTT, 10ms )__
    * If __FlightSize == 1__
        * __WCDelAckT = 200 ms__, the worst case delayed ACK timer
        * then schedule __PTO__ in __max( 2*SRTT, 1.5 * SRTT + WCDelAckT )__
    * If __RTO__ is earlier
        * then schedule __PTO__ in __min( RTO, PTO )__

A PTO value of 2*SRTT allows a sender to wait long enough to know that an ACK is overdue. Under normal circumstances, i.e. no losses, an ACK typically arrives in one RTT. But choosing PTO to be exactly an RTT is likely to generate spurious probes given that even end-system timings can easily push an ACK to be above an RTT. We chose PTO to be the next integral value of RTT. If RTO is smaller than the computed value for PTO, then a probe is scheduled to be sent at the RTO time.  The RTO timer is rearmed at the time of sending the probe, as is shown in Step (__3__) below. This ensures that a PTO is always sent prior to a connection experiencing an RTO.

* __(2)__ Conditions for scheduling PTO:
    * Connection is in Open state.
    * Connection is either cwnd limited or application limited.
    * Number of consecutive PTOs <= 2.
    * Connection is SACK enabled.

Implementations MAY use one or two consecutive PTOs.

* __(3)__ When PTO fires:

    * If a new previously unsent segment exists:
        * Transmit new segment.
        * __FlightSize += SMSS__ ( __cwnd__ remains unchanged )
    * If no new segment exists:
        * Retransmit the last segment.
    * Increment statistics counter for loss probes.
    * If conditions in (__2__) are satisfied:
        * Reschedule next __PTO__
    * Else:
        * Rearm __RTO__ to fire at epoch __now+RTO__

The reason for retransmitting the last segment is so that the ACK will carry SACK blocks and trigger either SACK-based loss recovery [RFC6675](https://tools.ietf.org/html/rfc6675) or FACK threshold based fast recovery [FACK](http://conferences.sigcomm.org/sigcomm/1996/papers/mathis.pdf). On transmission of a TLP, a MIB counter is incremented to keep track of the total number of loss probes sent.

* __(4)__ During ACK processing:
    * Cancel any existing __PTO__
        * If conditions in (__2__) allow:
            * Reschedule __PTO__ relative to the ACK receipt time.

### <A name="example"></A> Example

Following is an example of TLP. All events listed are at a TCP sender.

1. Sender transmits segments 1-10: 1, 2, 3, ..., 8, 9, 10
    * There is no more new data to transmit.
    * A PTO is scheduled to fire in 2 RTTs, after the transmission of the 10th segment.
2. Receives acknowledgements (ACKs) for segments 1-5; segments 6-10 are lost and no ACKs are received
    * Note that the sender (re)schedules its PTO timer relative to the last received ACK, which is the ACK for segment 5 in this case.
    * The sender sets the PTO interval using the calculation described in step (__1__) of the algorithm.
3. When PTO fires, sender retransmits segment 10
4. After an RTT, SACK for packet 10 arrives
    * The ACK also carries SACK holes for segments 6, 7, 8 and 9.
    * This triggers FACK threshold based recovery.
5. Connection enters fast recovery and retransmits remaining lost segments.

### <A name="fack"></A> FACK threshold based recovery

At the core of TLP is its reliance on FACK threshold based algorithm to invoke Fast Recovery.

Section 3.1 of the Forward Acknowledgement (FACK) Paper [FACK](http://conferences.sigcomm.org/sigcomm/1996/papers/mathis.pdf) describes an alternate algorithm for triggering fast retransmit, based on the extent of the SACK scoreboard.  Its goal is to trigger fast retransmit as soon as the receiver's reassembly queue is larger than the dupack threshold, as indicated by the difference between the forward most SACK block edge and SND.UNA. This algorithm quickly and reliably triggers fast retransmit in the presence of burst losses -- often on the first SACK following such a loss. Such a threshold based algorithm also triggers fast retransmit immediately in the presence of any reordering with extent greater than the dupack threshold.

FACK threshold based recovery works by introducing a new TCP state variable at the sender called __SND.FACK__.

* __SND.FACK__ reflects the forward-most data held by the receiver and is updated when a SACK block is received acknowledging data with a higher sequence number than the current value of __SND.FACK__.
* __SND.FACK__ reflects the highest sequence number known to have been received plus one. Note that in non-recovery states, __SND.FACK__ is the same as __SND.UNA__.

The following snippet is the pseudocode for FACK threshold based recovery.

* If ( __SND.FACK - SND.UNA__ ) > dupack threshold:
    * Invoke Fast Retransmit and Fast Recovery

