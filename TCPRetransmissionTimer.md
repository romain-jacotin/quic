# Computing TCP's Retransmission Timer

Extracts from __RFC6298__: [https://tools.ietf.org/html/rfc6298](https://tools.ietf.org/html/rfc6298)

---------------------

## Table of Content

* [The Basic Algorithm](#basicalgo)
* [Taking RTT Samples](#rttsamples)
* [Clock Granularity](#clock)
* [Managing the RTO Timer](#rtotimer)

## <A name="basicalgo"></A> The Basic Algorithm

To compute the current __RTO__, a TCP sender maintains two state variables:

* __SRTT__ (smoothed round-trip time)
* __RTTVAR__ (round-trip time variation).

In addition, we assume a clock granularity of G seconds.

The rules governing the computation of __SRTT__, __RTTVAR__, and __RTO__ are as follows:

1. Until a round-trip time (RTT) measurement has been made for a segment sent between the sender and receiver, the sender SHOULD set __RTO = 1 second__, though the "backing off" on repeated retransmission discussed in the ["Managing the RTO Timer"](#rtotimer) section still applies.
2. When the first RTT measurement __R__ is made (where __K = 4__):
    * __SRTT = R__
    * __RTTVAR = R/2__
    * __RTO = SRTT + max( G, K * RTTVAR )__
3. When a subsequent RTT measurement __R'__ is made (using __alpha=1/8__ and __beta=1/4__) :
    * __RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|__
    * __SRTT = (1 - alpha) * SRTT + alpha * R'__
    * __RTO = SRTT + max( G, K * RTTVAR )__
4. __if RTO is less than 1 second, then the RTO SHOULD be rounded up to 1 second__.
5. __A maximum value MAY be placed on RTO provided it is at least 60 seconds__.

## <A name="rttsamples"></A> Taking RTT Samples

TCP MUST use Karn's algorithm for taking RTT samples.
That is, RTT samples MUST NOT be made using segments that were retransmitted (and thus for which it is ambiguous whether the reply was for the first instance of the packet or a later instance).
The only case when TCP can safely take RTT samples from retransmitted segments is when the TCP timestamp option is employed, since the timestamp option removes the ambiguity regarding which instance of the data segment triggered the acknowledgment.

Traditionally, TCP implementations have taken one RTT measurement at a time (typically, once per RTT).
However, when using the timestamp option, each ACK can be used as an RTT sample.
RFC 1323 suggests that TCP connections utilizing large congestion windows should take many RTT samples per window of data to avoid aliasing effects in the estimated RTT.
A TCP implementation MUST take at least one RTT measurement per RTT (unless that is not possible per Karn's algorithm).

For fairly modest congestion window sizes, research suggests that timing each segment does not lead to a better RTT estimator.
Additionally, when multiple samples are taken per RTT, the alpha and beta defined may keep an inadequate RTT history.

## <A name="clock"></A> Clock Granularity

There is no requirement for the clock granularity G used for computing RTT measurements and the different state variables. However, if the K * RTTVAR term in the RTO calculation equals zero, the variance term MUST be rounded to G seconds.

* __RTO = SRTT + max( G, K * RTTVAR )__

Experience has shown that finer clock granularities (<= 100 msec) perform somewhat better than coarser granularities.

## <A name="rtotimer"></A> Managing the RTO Timer

An implementation MUST manage the retransmission timer(s) in such a way that a segment is never retransmitted too early, i.e., less than one RTO after the previous transmission of that segment.

The following is the RECOMMENDED algorithm for managing the retransmission timer:

1. Every time a packet containing data is sent (including a retransmission), if the timer is not running, start it running so that it will expire after RTO seconds (for the current value of RTO).
2. When all outstanding data has been acknowledged, turn off the retransmission timer.
3. When an ACK is received that acknowledges new data, restart the retransmission timer so that it will expire after RTO seconds (for the current value of RTO).

When the retransmission timer expires, do the following:

1. Retransmit the earliest segment that has not been acknowledged by the TCP receiver.
2. __RTO = RTO * 2__ ("back off the timer"), a maximum value MAY be placed on RTO provided it is at least 60 seconds.
3. Start the retransmission timer, such that it expires after RTO seconds.
4. If the timer expires awaiting the ACK of a SYN segment and the TCP implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to 3 seconds when data transmission begins (i.e., after the three-way handshake completes).

Note that after retransmitting, once a new RTT measurement is obtained (which can only happen when new data has been sent and acknowledged), the computations outlined in ["The Basic Algorithm"](#basicalgo) section are performed, including the computation of RTO, which may result in "collapsing" RTO back down after it has been subject to exponential back off (RTO = RTO*2).

Note that a TCP implementation MAY clear SRTT and RTTVAR after backing off the timer multiple times as it is likely that the current SRTT and RTTVAR are bogus in this situation.  Once SRTT and RTTVAR are cleared, they should be initialized with the next RTT sample taken like step 2 of ["The Basic Algorithm"](#basicalgo):

* __SRTT = R__
* __RTTVAR = R/2__
* __RTO = SRTT + max( G, K * RTTVAR )__
