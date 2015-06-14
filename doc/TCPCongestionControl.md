# TCP Congestion Control

Extracts from __RFC5681__: [http://tools.ietf.org/html/rfc5681](http://tools.ietf.org/html/rfc5681)

------------------

Table of Contents

* [Definitions](#definitions)
* [Congestion Control Algorithms](#algo)
    * [Slow Start and Congestion Avoidance](#slow)
    * [Fast Retransmit/Fast Recovery](#fast)
* [Additional Considerations](#considerations)
    * [Restarting Idle Connections](#idle)
    * [Generating Acknowledgments](#ack)
    * [Loss Recovery Mechanisms](#loss)

## <A name="definitions"></A> Definitions

* __SEGMENT__:
    * A segment is ANY TCP/IP data or acknowledgment packet (or both)
* __SMSS__ (Sender Maximum Segment Size):
    * The SMSS is the size of the largest segment that the sender can transmit. This value can be based on the maximum transmission unit of the network, the path MTU discovery ( [RFC1191](http://tools.ietf.org/html/rfc1191), [RFC4821](http://tools.ietf.org/html/rfc4821) ) algorithm, RMSS (see next item), or other factors. The size does not include the TCP/IP headers and options.
* __RMSS__ (Receiver Maximum Segment Size):
    * The RMSS is the size of the largest segment the receiver is willing to accept. This is the value specified in the MSS option sent by the receiver during connection startup. Or, if the MSS option is not used, it is 536 bytes ( [RFC1122](http://tools.ietf.org/html/rfc1122) ). The size does not include the TCP/IP headers and options.
* __FULL-SIZED SEGMENT__:
    * A segment that contains the maximum number of data bytes permitted (i.e., a segment containing SMSS bytes of data).
* __rwnd__ (Receiver Window):
    * The most recently advertised receiver window.
* __cwnd__ (Congestion Winwow):
    * A TCP state variable that limits the amount of data a TCP can send. At any given time, a TCP MUST NOT send       data with a sequence number higher than the sum of the highest acknowledged sequence number and the minimum of cwnd and rwnd.
* __IW__ (Initial Window):
    * The initial window is the size of the sender's congestion window after the three-way handshake is completed.
* __LW__ (Low Window):
    * The loss window is the size of the congestion window after a TCP sender detects loss using its retransmission timer.
* __RW__ (Restart Window):
    * The restart window is the size of the congestion window after a TCP restarts transmission after an idle period (if the slow start algorithm is used; see section 4.1 for more discussion).
* __FLIGHT SIZE__:
    * The amount of data that has been sent but not yet cumulatively acknowledged.
* __DUPLICATE ACKNOWLEDGMENT__:
    * An acknowledgment is considered a "duplicate" in the following algorithms when (a) the receiver of the ACK has outstanding data, (b) the incoming acknowledgment carries no data, (c) the SYN and FIN bits are both off, (d) the acknowledgment number is equal to the greatest acknowledgment received on the given connection (TCP.UNA from [RFC793](http://tools.ietf.org/html/rfc793)) and (e) the advertised window in the incoming acknowledgment equals the advertised window in the last incoming acknowledgment.

Alternatively, a TCP that utilizes selective acknowledgments (SACKs) ([RFC2018](http://tools.ietf.org/html/rfc2018), [RFC2883](http://tools.ietf.org/html/rfc2883)) can leverage the SACK information to determine when an incoming ACK is a "duplicate" (e.g., if the ACK contains previously unknown SACK information).

## <A name="algo"></A> Congestion Control Algorithms

This section defines the four congestion control algorithms developed in [Jac88] and [Jac90]:

1. Slow start
2. Congestion avoidance
3. Fast retransmit
4. Fast recovery

In some situations, it may be beneficial for a TCP sender to be more conservative than the algorithms allow; however, a TCP MUST NOT be more aggressive than the following algorithms allow (that is, MUST NOT send data when the value of cwnd computed by the following algorithms would not allow the data to be sent).

Also, note that the algorithms specified in this document work in terms of using loss as the signal of congestion.  Explicit Congestion Notification (ECN) could also be used as specified in [RFC3168](http://tools.ietf.org/html/rfc3168).

* [Jac88](ftp://ftp.ee.lbl.gov/papers/congavoid.ps.Z): Jacobson, V., "Congestion Avoidance and Control", Aug. 1988.
* [Jac90](ftp://ftp.isi.edu/end2end/end2end-interest-1990.mail): Jacobson, V., "Modified TCP Congestion Avoidance Algorithm", April 30, 1990.

### <A name="slow"></A> Slow Start and Congestion Avoidance

The slow start and congestion avoidance algorithms MUST be used by a TCP sender to control the amount of outstanding data being injected into the network.

To implement these algorithms, three variables are added to the TCP per-connection state.

* __cwnd__
    * The congestion window is a sender-side limit on the amount of data the sender can transmit into the network before receiving an acknowledgment (ACK),
* __rwnd__
    * The receiver's advertised window is a receiver-side limit on the amount of outstanding data.
    * The minimum of __cwnd__ and __rwnd__ governs data transmission.
* __ssthresh__
    * The Slow Start Threshold is used to determine whether the slow start or congestion avoidance algorithm is used to control data transmission, as discussed below.

Beginning transmission into a network with unknown conditions requires TCP to slowly probe the network to determine the available capacity, in order to avoid congesting the network with an inappropriately large burst of data. The slow start algorithm is used for this purpose at the beginning of a transfer, or after repairing loss detected by the retransmission timer. Slow start additionally serves to start the "ACK clock" used by the TCP sender to release data into the network in the slow start, congestion avoidance, and loss recovery algorithms.

__IW__, the initial value of cwnd, MUST be set using the following guidelines as an upper bound.

* If __SMSS__ > 2190 bytes:
    * __IW__ = 2 * __SMSS__ bytes and MUST NOT be more than 2 segments
* If ( __SMSS__ > 1095 bytes ) and ( __SMSS__ <= 2190 bytes ):
    * __IW__ = 3 * __SMSS__ bytes and MUST NOT be more than 3 segments
* if __SMSS__ <= 1095 bytes:
    * __IW__ = 4 * __SMSS__ bytes and MUST NOT be more than 4 segments

As specified in [RFC3390](http://tools.ietf.org/html/rfc3390), the SYN/ACK and the acknowledgment of the SYN/ACK MUST NOT increase the size of the congestion window. Further, if the SYN or SYN/ACK is lost, the initial window used by a sender after a correctly transmitted SYN MUST be one segment consisting of at most __SMSS__ bytes.

A detailed rationale and discussion of the __IW__ setting is provided in [RFC3390](http://tools.ietf.org/html/rfc3390).

When initial congestion windows of more than one segment are implemented along with Path MTU Discovery [RFC1191](http://tools.ietf.org/html/rfc1191), and the __MSS__ being used is found to be too large, the congestion window __cwnd__ SHOULD be reduced to prevent large bursts of smaller segments. Specifically, __cwnd__ SHOULD be reduced by the ratio of the old segment size to the new segment size.

The initial value of __ssthresh__ SHOULD be set arbitrarily high (e.g., to the size of the largest possible advertised window), but __ssthresh__ MUST be reduced in response to congestion.  Setting __ssthresh__ as high as possible allows the network conditions, rather than some arbitrary host limit, to dictate the sending rate.  In cases where the end systems have a solid understanding of the network path, more carefully setting the initial __ssthresh__ value may have merit (e.g., such that the end host does not create congestion along the path).

* The slow start algorithm is used when __cwnd__ < __ssthresh__
* While the congestion avoidance algorithm is used when __cwnd__ > __ssthresh__
* When cwnd and __ssthresh__ are equal, the sender may use either slow start or congestion avoidance

During slow start, a TCP increments cwnd by at most __SMSS__ bytes for each ACK received that cumulatively acknowledges new data.  Slow start ends when cwnd exceeds __ssthresh__ (or, optionally, when it reaches it, as noted above) or when congestion is observed.  While traditionally TCP implementations have increased cwnd by precisely __SMSS__ bytes upon receipt of an ACK covering new data, we RECOMMEND that TCP implementations increase __cwnd__, per:

* _Equation 2_
    * __N__ is the number of previously unacknowledged bytes acknowledged in the incoming ACK
    * __cwnd += min( N, SMSS )__

This adjustment is part of Appropriate Byte Counting ( [RFC3465](http://tools.ietf.org/html/rfc3465) ) and provides robustness against misbehaving receivers that may attempt to induce a sender to artificially inflate cwnd using a mechanism known as "ACK Division" [SCWA99].  ACK Division consists of a receiver sending multiple ACKs for a single TCP data segment, each acknowledging only a portion of its data. A TCP that increments cwnd by SMSS for each such ACK will inappropriately inflate the amount of data injected into the network.

During congestion avoidance, __cwnd__ is incremented by roughly 1 full-sized segment per round-trip time (RTT).  Congestion avoidance continues until congestion is detected.  The basic guidelines for incrementing cwnd during congestion avoidance are:

* MAY increment __cwnd__ by __SMSS__ bytes
* SHOULD increment __cwnd__ per _equation 2_ once per RTT
* MUST NOT increment __cwnd__ by more than __SMSS__ bytes

We note that [RFC3465](http://tools.ietf.org/html/rfc3465) allows for __cwnd__ increases of more than __SMSS__ bytes for incoming acknowledgments during slow start on an experimental basis; however, such behavior is not allowed as part of the standard.

The RECOMMENDED way to increase __cwnd__ during congestion avoidance is to count the number of bytes that have been acknowledged by ACKs for new data.  (A drawback of this implementation is that it requires maintaining an additional state variable.)  When the number of bytes acknowledged reaches __cwnd__, then __cwnd__ can be incremented by up to __SMSS__ bytes.  Note that during congestion avoidance, __cwnd__ MUST NOT be increased by more than __SMSS__ bytes per RTT.  This method both allows TCPs to increase cwnd by one segment per RTT in the face of delayed ACKs and provides robustness against ACK Division attacks.

Another common formula that a TCP MAY use to update cwnd during congestion avoidance is given in _equation 3_:

* _Equation 3_
    * __cwnd += SMSS * SMSS / cwnd__
    * This adjustment is executed on every incoming ACK that acknowledges new data.

_Equation 3_ provides an acceptable approximation to the underlying principle of increasing __cwnd__ by 1 full-sized segment per RTT. (Note that for a connection in which the receiver is acknowledging every-other packet, _equation 3_ is less aggressive than allowed -- roughly increasing __cwnd__ every second RTT.)

* _Implementation Notes:_
    * Since integer arithmetic is usually used in TCP implementations, the formula given in _equation 3_ can fail to increase __cwnd__ when the congestion window is larger than __SMSS * SMSS__. If the above formula yields 0, the result SHOULD be rounded up to 1 byte.
    * Older implementations have an additional additive constant on the right-hand side of _equation 3_.  This is incorrect and can actually lead to diminished performance [RFC2525](http://tools.ietf.org/html/rfc2525).
    * Some implementations maintain cwnd in units of bytes, while others in units of full-sized segments.  The latter will find _equation 3_ difficult to use, and may prefer to use the counting approach discussed in the previous paragraph.

When a TCP sender detects segment loss using the retransmission timer and the given segment has not yet been resent by way of the retransmission timer, the value of __ssthresh__ MUST be set to no more than the value given in _equation 4_:

* _Equation 4:_
    * __ssthresh = max( FlightSize / 2, 2 * SMSS )__

where, as discussed above, FlightSize is the amount of outstanding data in the network.

On the other hand, when a TCP sender detects segment loss using the retransmission timer and the given segment has already been retransmitted by way of the retransmission timer at least once, the value of __ssthresh__ is held constant.

* _Implementation Note:_
    * An easy mistake to make is to simply use __cwnd__, rather than __FlightSize__, which in some implementations may incidentally increase well beyond __rwnd__.

Furthermore, upon a timeout (as specified in [RFC2988](http://tools.ietf.org/html/rfc2988)) __cwnd__ MUST be set to no more than the loss window, __LW__, which equals 1 full-sized segment (regardless of the value of __IW__). Therefore, after retransmitting the dropped segment the TCP sender uses the slow start algorithm to increase the window from 1 full-sized segment to the new value of __ssthresh__, at which point congestion avoidance again takes over.

As shown in [FF96] and [RFC3782](http://tools.ietf.org/html/rfc3782), slow-start-based loss recovery after a timeout can cause spurious retransmissions that trigger duplicate acknowledgments. The reaction to the arrival of these duplicate ACKs in TCP implementations varies widely.  This document does not specify how to treat such acknowledgments, but does note this as an area that may benefit from additional attention, experimentation and specification.

* [FF96](ftp://ftp.ee.lbl.gov/papers/sacks.ps.Z) Fall, K. and S. Floyd, "Simulation-based Comparisons of Tahoe, Reno and SACK TCP", July 1996.

### <A name="fast"></A> Fast Retransmit/Fast Recovery

A TCP receiver SHOULD send an immediate duplicate ACK when an out-of-order segment arrives.  The purpose of this ACK is to inform the sender that a segment was received out-of-order and which sequence number is expected.  From the sender's perspective, duplicate ACKs can be caused by a number of network problems.  First, they can be caused by dropped segments.  In this case, all segments after the dropped segment will trigger duplicate ACKs until the loss is repaired.  Second, duplicate ACKs can be caused by the re-ordering of data segments by the network (not a rare event along some network paths [Pax97]).  Finally, duplicate ACKs can be caused by replication of ACK or data segments by the network.  In addition, a TCP receiver SHOULD send an immediate ACK when the incoming segment fills in all or part of a gap in the sequence space.  This will generate more timely information for a sender recovering from a loss through a retransmission timeout, a fast retransmit, or an advanced loss recovery algorithm, as outlined in section 4.3.

The TCP sender SHOULD use the "fast retransmit" algorithm to detect and repair loss, based on incoming duplicate ACKs.  The fast retransmit algorithm uses the arrival of 3 duplicate ACKs (as defined in section 2, without any intervening ACKs which move SND.UNA) as an indication that a segment has been lost.  After receiving 3 duplicate ACKs, TCP performs a retransmission of what appears to be the missing segment, without waiting for the retransmission timer to expire.

After the fast retransmit algorithm sends what appears to be the missing segment, the "fast recovery" algorithm governs the transmission of new data until a non-duplicate ACK arrives.  The reason for not performing slow start is that the receipt of the duplicate ACKs not only indicates that a segment has been lost, but also that segments are most likely leaving the network (although a massive segment duplication by the network can invalidate this conclusion).  In other words, since the receiver can only generate a duplicate ACK when a segment has arrived, that segment has left the network and is in the receiver's buffer, so we know it is no longer consuming network resources.  Furthermore, since the ACK "clock" [Jac88] is preserved, the TCP sender can continue to transmit new segments (although transmission must continue using a reduced cwnd, since loss is an indication of congestion).

The fast retransmit and fast recovery algorithms are implemented together as follows.

* __1.__
    * On the first and second duplicate ACKs received at a sender, a TCP SHOULD send a segment of previously unsent data per [RFC3042](http://tools.ietf.org/html/rfc3042) provided that the receiver's advertised window allows, the total FlightSize would remain less than or equal to cwnd plus 2*SMSS, and that new data is available for transmission.  Further, the TCP sender MUST NOT change cwnd to reflect these two segments [RFC3042](http://tools.ietf.org/html/rfc3042).  Note that a sender using SACK [RFC2018](http://tools.ietf.org/html/rfc2018) MUST NOT send new data unless the incoming duplicate acknowledgment contains new SACK information.
* __2.__
    * When the third duplicate ACK is received, a TCP MUST set __ssthresh__ to no more than the value given in _equation 4_. When [RFC3042] is in use, additional data sent in limited transmit MUST NOT be included in this calculation.
* __3.__
    * The lost segment starting at SND.UNA MUST be retransmitted and __cwnd__ set to __ssthresh__ plus __3*SMSS__. This artificially "inflates" the congestion window by the number of segments (three) that have left the network and which the receiver has buffered.
* __4.__
    * For each additional duplicate ACK received (after the third), __cwnd__ MUST be incremented by __SMSS__. This artificially inflates the congestion window in order to reflect the additional segment that has left the network.
    * _Notes:_
        * [SCWA99] discusses a receiver-based attack whereby many bogus duplicate ACKs are sent to the data sender in order to artificially inflate cwnd and cause a higher than appropriate sending rate to be used.  A TCP MAY therefore limit the number of times cwnd is artificially inflated during loss recovery to the number of outstanding segments (or, an approximation thereof).
        * When an advanced loss recovery mechanism (such as outlined in section 4.3) is not in use, this increase in FlightSize can cause equation (4) to slightly inflate cwnd and ssthresh, as some of the segments between SND.UNA and SND.NXT are assumed to have left the network but are still reflected in FlightSize.

* __5.__
    * When previously unsent data is available and the new value of cwnd and the receiver's advertised window allow, a TCP SHOULD send 1*SMSS bytes of previously unsent data.
* __6.__
    * When the next ACK arrives that acknowledges previously unacknowledged data, a TCP MUST set cwnd to __ssthresh__ (the value set in step 2).  This is termed "deflating" the window.
    * This ACK should be the acknowledgment elicited by the retransmission from step 3, one RTT after the retransmission (though it may arrive sooner in the presence of significant out-of-order delivery of data segments at the receiver). Additionally, this ACK should acknowledge all the intermediate segments sent between the lost segment and the receipt of the third duplicate ACK, if none of these were lost.

_Note:_ This algorithm is known to generally not recover efficiently from multiple losses in a single flight of packets [FF96].

* [Pax97](#)
    * Paxson, V., "End-to-End Internet Packet Dynamics", Proceedings of SIGCOMM '97, Cannes, France, Sep. 1997
* [SCWA99](#)
    * Savage, S., Cardwell, N., Wetherall, D., and T. Anderson, "TCP Congestion Control With a Misbehaving Receiver", ACM, October 1999
* [FF96](ftp://ftp.ee.lbl.gov/papers/sacks.ps.Z)
    * Fall, K. and S. Floyd, "Simulation-based Comparisons of Tahoe, Reno and SACK TCP", July 1996

## <A name="considerations"></A> Additional Considerations

### <A name="idle"></A> Restarting Idle Connections

A known problem with the TCP congestion control algorithms described above is that they allow a potentially inappropriate burst of traffic to be transmitted after TCP has been idle for a relatively long period of time.  After an idle period, TCP cannot use the ACK clock to strobe new segments into the network, as all the ACKs have drained from the network.  Therefore, as specified above, TCP can potentially send a cwnd-size line-rate burst into the network after an idle period.  In addition, changing network conditions may have rendered TCP's notion of the available end-to-end network capacity between two endpoints, as estimated by cwnd, inaccurate during the course of a long idle period.

[Jac88] recommends that a TCP use slow start to restart transmission after a relatively long idle period.  Slow start serves to restart the ACK clock, just as it does at the beginning of a transfer.  This mechanism has been widely deployed in the following manner.  When TCP has not received a segment for more than one retransmission timeout, __cwnd__ is reduced to the value of the restart window (__RW__) before transmission begins.

For the purposes of this standard, we define:

* __RW = min( IW, cwnd )__

Using the last time a segment was received to determine whether or not to decrease __cwnd__ can fail to deflate __cwnd__ in the common case of persistent HTTP connections [HTH98].  In this case, a Web server receives a request before transmitting data to the Web client.  The reception of the request makes the test for an idle connection fail, and allows the TCP to begin transmission with a possibly inappropriately large __cwnd__.

Therefore, a TCP SHOULD set __cwnd__ to no more than __RW__ before beginning transmission if the TCP has not sent data in an interval exceeding the retransmission timeout.

### <A name="ack"></A> Generating Acknowledgments

* The delayed ACK algorithm specified in [RFC1122](http://tools.ietf.org/html/rfc1122) SHOULD be used by a TCP receiver.
    * When using delayed ACKs, a TCP receiver MUST NOT excessively delay acknowledgments. Specifically, an ACK SHOULD be generated for at least every second full-sized segment, and MUST be generated within 500 ms of the arrival of the first unacknowledged packet.
* The requirement that an ACK "SHOULD" be generated for at least every second full-sized segment is listed in [RFC1122](http://tools.ietf.org/html/rfc1122) in one place as a SHOULD and another as a MUST.
    * Here we unambiguously state it is a SHOULD.  We also emphasize that this is a SHOULD, meaning that an implementor should indeed only deviate from this requirement after careful consideration of the implications.  See the discussion of "Stretch ACK violation" in [RFC2525](http://tools.ietf.org/html/rfc2525) and the references therein for a discussion of the possible performance problems with generating ACKs less frequently than every second full-sized segment.
    * In some cases, the sender and receiver may not agree on what constitutes a full-sized segment.  An implementation is deemed to comply with this requirement if it sends at least one acknowledgment every time it receives __2 * RMSS__ bytes of new data from the sender, where RMSS is the Maximum Segment Size specified by the receiver to the sender (or the default value of 536 bytes, per [RFC1122](http://tools.ietf.org/html/rfc1122), if the receiver does not specify an MSS option during connection establishment).  The sender may be forced to use a segment size less than RMSS due to the maximum transmission unit (MTU), the path MTU discovery algorithm or other factors.  For instance, consider the case when the receiver announces an RMSS of X bytes but the sender ends up using a segment size of Y bytes (Y < X) due to path MTU discovery (or the sender's MTU size).  The receiver will generate stretch ACKs if it waits for 2*X bytes to arrive before an ACK is sent.  Clearly this will take more than 2 segments of size Y bytes. Therefore, while a specific algorithm is not defined, it is desirable for receivers to attempt to prevent this situation, for example, by acknowledging at least every second segment, regardless of size. Finally, we repeat that an ACK MUST NOT be delayed for more than 500 ms waiting on a second full-sized segment to arrive.
* Out-of-order data segments SHOULD be acknowledged immediately, in order to accelerate loss recovery.
* To trigger the fast retransmit algorithm, the receiver SHOULD send an immediate duplicate ACK when it receives a data segment above a gap in the sequence space.
* To provide feedback to senders recovering from losses, the receiver SHOULD send an immediate ACK when it receives a data segment that fills in all or part of a gap in the sequence space.
* A TCP receiver MUST NOT generate more than one ACK for every incoming segment, other than to update the offered window as the receiving application consumes new data ( see [RFC813](http://tools.ietf.org/html/rfc813) and page 42 of [RFC793](http://tools.ietf.org/html/rfc793) ).

### <A name="loss"></A> Loss Recovery Mechanisms

A number of loss recovery algorithms that augment fast retransmit and fast recovery have been suggested by TCP researchers and specified in the RFC series.  While some of these algorithms are based on the TCP selective acknowledgment (SACK) option [RFC2018](http://tools.ietf.org/html/rfc2018), such as [FF96], [MM96a], [MM96b], and [RFC3517](http://tools.ietf.org/html/rfc3517), others do not require SACKs, such as [Hoe96], [FF96], and [RFC3782](http://tools.ietf.org/html/rfc3782).

The non-SACK algorithms use "partial acknowledgments" (ACKs that cover previously unacknowledged data, but not all the data outstanding when loss was detected) to trigger retransmissions.  While this document does not standardize any of the specific algorithms that may improve fast retransmit/fast recovery, these enhanced algorithms are implicitly allowed, as long as they follow the general principles of the basic four algorithms outlined above.

* When the first loss in a window of data is detected, __ssthresh__ MUST be set to no more than the value given by _equation 4_.
* Until all lost segments in the window of data in question are repaired, the number of segments transmitted in each RTT MUST be no more than half the number of outstanding segments when the loss was detected.
* After all loss in the given window of segments has been successfully retransmitted, __cwnd__ MUST be set to no more than __ssthresh__ and congestion avoidance MUST be used to further increase __cwnd__.
* Loss in two successive windows of data, or the loss of a retransmission, should be taken as two indications of congestion and, therefore, __cwnd__ (and __ssthresh__) MUST be lowered twice in this case.

We RECOMMEND that TCP implementors employ some form of advanced loss recovery that can cope with multiple losses in a window of data.  The algorithms detailed in [RFC3782](http://tools.ietf.org/html/rfc3782) and [RFC3517](http://tools.ietf.org/html/rfc3517) conform to the general principles outlined above.  We note that while these are not the only two algorithms that conform to the above general principles these two algorithms have been vetted by the community and are currently on the Standards Track.


