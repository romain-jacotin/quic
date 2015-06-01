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
    * [Ack Timer](#)
    * [Retransmission Timeout Event](#retransmissiontimeout)
    * [Send Timer (pacing?)](#)
    * [Timeout Timer (?)](#)
    * [Ping Timer (?)](#)
    * [Resume Write Timer (?)](#)
    * [FEC Timer (?)](#)

## <A name="overview"></A> Overview

## <A name="packetevents"></A> Packet Events

## <A name="frameevents"></A> Frame Events

## <A name="timeoutevents"></A> Timeout Events

### <A name="retransmissiontimeout"></A> Retransmission Timeout Event
