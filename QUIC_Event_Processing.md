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
    * [Ack Timer](#acktimer)
    * [Retransmission Timeout Event](#retransmissiontimeout)
    * [Crypto Hanshake Timeout Event ](#cryptohandshaketimeout)
    * [Ping Timeout](#pingtimeout)
    * [Send Timeout & Resume Write Timeout (pacing & resume write)](#sendtimer)
    * [FEC Timer (?)](#fectimer)

## <A name="overview"></A> Overview

## <A name="packetevents"></A> Packet Events

## <A name="frameevents"></A> Frame Events

## <A name="timeoutevents"></A> Timeout Events

### <A name="acktimer"></A> Ack Timer Event

### <A name="retransmissiontimeout"></A> Retransmission Timeout Event

* Always reset the retransmission alarm when an ack comes in, since we now have a better estimate of the current RTT than when it was set.
* __Retransmission timeout = __

* __HANDSHAKE MODE__
    * clock_->ApproximateNow().Add(GetCryptoRetransmissionDelay())
* __LOSS MODE__
    * loss_algorithm_->GetLossTimeout()
* __TAIL LOSS PROBE__
    * __Retransmission timeout__ = GetTailLossProbeDelay() + unacked_packets_.GetLastPacketSentTime()
* __RTO__
    // The RTO is based on the first outstanding packet
    QuicTime sent_time = unacked_packets_.GetLastPacketSentTime()
    QuicTime rto_time = sent_time.Add(GetRetransmissionDelay())    
    QuicTime tlp_time = unacked_packets_.GetLastPacketSentTime().Add(GetTailLossProbeDelay())
    Max(tlp_time, rto_time)  // Wait for TLP packets to be acked before an RTO fires

### <A name="cryptohandshaketimeout"></A> Crypto Handshake Timeout Event

* __Max time before crypto handshake = 10 seconds__
* __Max idle time before crypto handshake = 5 seconds__

### <A name="pingtimeout"></A> Ping Timeout Event

* If no QUIC packet is send or received for a "ping timeout" duration then a QUIC PING_FRAME must be send.
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

