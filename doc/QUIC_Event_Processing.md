# QUIC Event Processing

---------------------

## Table of Contents

* [Overview](#overview)
* [Packet Events](#packetevents)
    * [Packet Received](#)
        * [DATA Packet](#)
        * [FEC Protected DATA Packet](#)
        * [FEC Packet](#)
* [Frame Events](#frameevents)
    * [Connection Management Event](#)
        * [CONNECTION_CLOSE_FRAME](#)
        * [GO_AWAY_FRAME Event](#)
        * [PING_FRAME Event](#)
    * [Stream Management Event](#)
        * [New Stream Event (=first STREAM_FRAME)](#)
        * [Half-Close Stream Event (=last STREAM_FRAME with FIN bit)](#)
        * [RESET_STREAM_FRAME Event](#)
    * [Data Event](#)
        * [STREAM_FRAME Event](#)
        * [PADDING_FRAME Event](#)
    * [Data Management Event](#)
        * [ACK_FRAME Event](#)
        * [STOP_WAITING_FRAME Event](#)
        * [WINDOW_UPDATE Event](#)
        * [BLOCKED_FRAME Event](#)
* [Timeout Events](#timeoutevents)
    * [Ack Delay](#ackdelay)
    * [Retransmission Timeout (RTO) Event](#retransmissiontimeout)
    * [Crypto Hanshake Timeout Event ](#cryptohandshaketimeout)
    * [Ping Timeout](#pingtimeout)
    * [Send Timeout & Resume Write Timeout (pacing & resume write)](#sendtimer)
    * [FEC Timer (?)](#fectimer)

## <A name="overview"></A> Overview

## <A name="packetevents"></A> Packet Events

## <A name="frameevents"></A> Frame Events

## <A name="timeoutevents"></A> Timeout Events

### <A name="ackdelay"></A> Ack Delay Event

Ack delay before sending ACK_FRAME depends on the retransmission mode:

* __MaximumDelayedAckTime = 25 ms__
* __MinimumRetransmissionTime = 200 ms__
* _HANDSHAKE MODE_ :
    * __Ack delay = 0 ms__ (no delay before sending Ack !)
* Otherwise :
    * __Ack delay = Min( MaximumDelayedAckTime, MinimumRetransmissionTime/2 ) = 25 ms__

### <A name="retransmissiontimeout"></A> Retransmission Timeout (RTO) Event

Always reset the retransmission alarm when an ack comes in, since we now have a better estimate of the current RTT than when it was set. Calcul of the Retransmission timeout (__RTO__) depends on the retransmission mode:

* _HANDSHAKE MODE_ :
    * The Crypto Retransmission Delay (ms) is equivalent to the Tail Loss Probe Delay, but slightly more aggressive because crypto handshake messages don't incur a delayed ack time.
    * __SRTT__ = smoothed RTT in ms
    * __MinimumHandshakeTimeout = 10 ms__
    * __ConsecutiveCryptoRetransmissionCount__ = number of consecutive crypto packet needed to retransmit
    * __CryptoRetransmissionDelay = max( MinimumHandshakeTimeout , 1.5*SRTT ) * (2^ConsecutiveCryptoRetransmissionCount)__
    * __RTO = CryptoRetransmissionDelay__
    * ( RTO += CurrentTime in discrete time )
* _LOSS MODE_
    * _TCP Loss algorithm_
        * Set the timeout for the earliest retransmittable packet where early retransmit applies
        * __NumberOfNacksBeforeRetransmission = 3__
        * __MinimumLossDelay = 5 ms__
        * __SRTT__ = smoothed RTT in ms
        * __EarlyRetransmitDelay = Max( MinimumLossDelay, 1.25*SRTT )__
        * __RTO = EarlyRetransmitDelay__
        * ( RTO += LastUnackedPacketSentTime in discrete time )
    * _Time Loss algorithm_
        * Packet is consider lost with a LossDelay timeout after their sending
        * __MinimumLossDelay = 5 ms__
        * __SRTT__ = smoothed RTT in ms
        * __LatestRTT__ = the latest estimated RTT value in ms (no smoothed)
        * __LossDelay = 1.25 * Max( MinimumLossDelay, SRTT, LatestRTT )__
        * __RTO = LossDelay__
        * ( RTO += LastUnackedPacketSentTime in discrete time )
* _TAIL LOSS PROBE_
        * __MinimumTailLossProbeTimeout = 10 ms__
        * __MinimumRetransmissionTime= 200 ms__
    * if more than one packet in flight:
        * __TailLossProbeDelay = Max( MinimumTailLossProbeTimeout, 2*SRTT )__
    * otherwise
        * __TailLossProbeDelay = Max( 2 * SRTT, 1.5 * SRTT + MinimumRetransmissionTime/2 )__
    * __RTO = TailLossProbeDelay__
    * ( RTO += LastUnackedPacketSentTime in discrete time )
* _RTO_ (the first outstanding packet)
    * Must wait at minimum for Tail Loss Probe packets to be acked
    * __DefaultRetransmissionTime = 500 ms__
    * __MinimumRetransmissionTime = 200 ms__
    * __MaximumRetransmissionTime = 60.000 ms__
    * __MaximumRetransmissions = 10__
    * __ConsecutiveRTOCount__ = consecutive number RTO events before receiving any ACK_FRAME
    * __RetransmissionDelay = SRTT + 4*MeanDeviationRTT__
    * __RetransmissionDelay * = (2 ^ Min( ConsecutiveRTOCount , MaximumRetransmissions ))__
    * __RetransmissionDelay = Min( RetransmissionDelay, MaximumRetransmissionTime )__
    * __RTO = Max( RetransmissionDelay, TailLossProbeDelay, MinimumRetransmissionTime )__
    * ( RTO += LastUnackedPacketSentTime in discrete time )

### <A name="cryptohandshaketimeout"></A> Crypto Handshake Timeout Event

* __Max time before crypto handshake = 10 seconds__
* __Max idle time before crypto handshake = 5 seconds__ (no network activity)

### <A name="pingtimeout"></A> Ping Timeout Event

* If there is open streams:
    * a QUIC PING_FRAME must be send if no QUIC packet is send or received for a "ping timeout" duration
* __Ping timeout = 15 seconds__

### <A name="sendtimeout"></A> Send Timeout & Resume Write Timeout Event

* Variable delay to wait before sending packets ...

### <A name="fectimer"></A> FEC Timer Event

We want to put some space between a protected packet and the FEC packet to avoid losing them both within the same loss episode. On the other hand, we expect to be able to recover from any loss in about an RTT. We resolve this tradeoff by sending an FEC packet at most half an RTT, or equivalently, half the max number of in-flight packets,  the first protected packet. Since we don't want to delay a FEC packet past half a RTT, we set the max FEC group size to be half the current congestion window.

* When a FEC Timer event is received then:
    * Flush QUIC packets in queue,
    * Send FEC protected data Frames
    * Send the (last) FEC packet that closes the FEC group
* __FEC Timer = RTT/2__

