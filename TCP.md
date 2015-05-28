# Transmission Control Protocol

Extracts from RFC793: [https://tools.ietf.org/html/rfc793](https://tools.ietf.org/html/rfc793)

---------------------

## Table of Content

* [Header Format](#headerformat)
* [Terminology](#terminology)
    * [Send Sequence Variables](#sendsequencevars)
    * [Receive Sequence Variables](#receivesequencevars)
    * [Current Segment Variables](#currentsegmentvars)
* [Sequence number](#sequencenumber)
    * [Initial Sequence Number Selection](#isns)
* [Data Communication](#datacommunication)
    * [Retransmission Timeout](#retransmissiontimeout)
    * [The Communication of Urgent Information](#urgent)
    * [Managing the window](#managingwindow)
* [Interfaces](#interfaces)
    * [OPEN](#open)
    * [SEND](#send)
    * [RECEIVE](#receive)
    * [CLOSE](#close)
    * [STATUS](#status)
    * [ABORT](#abort)
    * [TCP-to-User Messages](#tcptouser)
* [Event Processing](#eventprocessing)
    * [OPEN Call](#opencall)
    * [SEND Call](#sendcall)
    * [RECEIVE Call](#receivecall)
    * [CLOSE Call](#closecall)
    * [ABORT Call](#abortcall)
    * [STATUS Call](#statuscall)
    * [SEGMENT ARRIVES](#segmentarrives)
    * [USER TIMEOUT](#usertimeout)
    * [RETRANSMISSION TIMEOUT](#retransmissiontimeoutevent)
    * [TIME-WAIT TIMEOUT](#timewaittimeout)

## <A name="headerformat"></A> Header Format

__TCP Header Format__

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |             Source Port       |        Destination Port       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Sequence Number                       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         Acknowledgment Number                 |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Data |           |U|A|P|R|S|F|                               |
 | Offset| Reserved  |R|C|S|S|Y|I|           Window              |
 |       |           |G|K|H|T|N|N|                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |       Urgent Pointer          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                   Options                     |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                               data                            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
```

* __Source Port__: 16 bits
    * The source port number.
* __Destination Port__: 16 bits
    * The destination port number.
* __Sequence Number__: 32 bits
    * The sequence number of the first data octet in this segment (except when SYN is present). If SYN is present the sequence number is the initial sequence number (ISN) and the first data octet is ISN+1.
* __Acknowledgment Number__: 32 bits
    * If the ACK control bit is set this field contains the value of the next sequence number the sender of the segment is expecting to receive. Once a connection is established this is always sent.
* __Data Offset__: 4 bits
    * The number of 32 bit words in the TCP Header. This indicates where the data begins. The TCP header (even one including options) is an integral number of 32 bits long.
* __Reserved__: 6 bits
    * Reserved for future use. Must be zero.
* __Control Bits__: 6 bits (from left to right):
    * __URG__: Urgent Pointer field significant
    * __ACK__: Acknowledgment field significant
    * __PSH__: Push Function
    * __RST__: Reset the connection
    * __SYN__: Synchronize sequence numbers
    * __FIN__: No more data from sender
* __Window__: 16 bits
    * The number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept.
* __Checksum__: 16 bits
    * The checksum field is the 16 bit one’s complement of the one’s complement sum of all 16 bit words in the header and text. If a segment contains an odd number of header and text octets to be checksummed, the last octet is padded on the right with zeros to form a 16 bit word for checksum purposes. The pad is not transmitted as part of the segment. While computing the checksum, the checksum field itself is replaced with zeros.

The checksum also covers a 96 bit pseudo header conceptually
prefixed to the TCP header. This pseudo header contains the Source
 Address, the Destination Address, the Protocol, and TCP length.
 This gives the TCP protection against misrouted segments. This
 information is carried in the Internet Protocol and is transferred
 across the TCP/Network interface in the arguments or results of
 calls by the TCP on the IP.
```
 +--------+--------+--------+--------+
 |           Source Address          |
 +--------+--------+--------+--------+
 |        Destination Address        |
 +--------+--------+--------+--------+
 | zero   |  PTCL  |    TCP Length   |
 +--------+--------+--------+--------+
```
The TCP Length is the TCP header length plus the data length in
 octets (this is not an explicitly transmitted quantity, but is
 computed), and it does not count the 12 octets of the pseudo
 header.

* __Urgent Pointer__: 16 bits
    * This field communicates the current value of the urgent pointer as a positive offset from the sequence number in this segment. The urgent pointer points to the sequence number of the octet following the urgent data. This field is only be interpreted in segments with the URG control bit set.
* __Options__: variable
    * Options may occupy space at the end of the TCP header and are a multiple of 8 bits in length. All options are included in the checksum. An option may begin on any octet boundary. There are two cases for the format of an option:
        * __Case 1__: A single octet of option-kind.
        * __Case 2__: An octet of option-kind, an octet of option-length, and the actual option-data octets.
    The option-length counts the two octets of option-kind and option-length as well as the option-data octets. Note that the list of options may be shorter than the data offset field might imply. The content of the header beyond the End-of-Option option must be header padding (i.e., zero).

A TCP must implement all options. Currently defined options include (kind indicated in octal):

```
 Kind Length Meaning
 ---- ------ -------
  0     -    End of option list.
  1     -    No-Operation.
  2     4    Maximum Segment Size.
```

__End of Option List__

```
 +--------+
 |00000000|
 +--------+
  Kind=0
```

 This option code indicates the end of the option list. This
 might not coincide with the end of the TCP header according to
 the Data Offset field. This is used at the end of all options,
 not the end of each option, and need only be used if the end of
 the options would not otherwise coincide with the end of the TCP
 header.

__No-Operation__

```
 +--------+
 |00000001|
 +--------+
  Kind=1
```

This option code may be used between options, for example, to
align the beginning of a subsequent option on a word boundary.
There is no guarantee that senders will use this option, so
receivers must be prepared to process options even if they do
not begin on a word boundary.

__Maximum Segment Size__

```
 +--------+--------+---------+--------+
 |00000010|00000100|    max seg size  |
 +--------+--------+---------+--------+
  Kind=2   Length=4
```

## <A name="terminology"></A> Terminology

### <A name="sendsequencevars"></A> Send Sequence Variables

* __SND.UNA__ = send unacknowledged
* __SND.NXT__ = send next
* __SND.WND__ = send window
* __SND.UP__ = send urgent pointer
* __SND.WL1__ = segment sequence number used for last window update
* __SND.WL2__ = segment acknowledgment number used for last window update
* __ISS__ = initial send sequence number

__Send Sequence Space__

```
      1          2          3         4
 ----------|----------|----------|----------
        SND.UNA    SND.NXT    SND.UNA
                             +SND.WND
```

1. old sequence numbers which have been acknowledged
2. sequence numbers of unacknowledged data
3. sequence numbers allowed for new data transmission
4. future sequence numbers which are not yet allowed

### <A name="receivesequencevars"></A> Receive Sequence Variables

* __RCV.NXT__ = receive next
* __RCV.WND__ = receive window
* __RCV.UP__ = receive urgent pointer
* __IRS__ = initial receive sequence number

__Receive Sequence Space__

```
      1          2          3
 ----------|----------|----------
        RCV.NXT    RCV.NXT
                  +RCV.WND
```

1. old sequence numbers which have been acknowledged
2. sequence numbers allowed for new reception
3. future sequence numbers which are not yet allowed

### <A name="currentsegmentvars"></A> Current Segment Variables

* __SEG.SEQ__ = segment sequence number
* __SEG.ACK__ = segment acknowledgment number
* __SEG.LEN__ = segment length
* __SEG.WND__ = segment window
* __SEG.UP__ = segment urgent pointer
* __SEG.PRC__ = segment precedence value

## <A name="sequencenumber"></A> Sequence number

In response to sending data the TCP will receive acknowledgments.
The following comparisons are needed to process the acknowledgments.

* __SND.UNA__ = oldest unacknowledged sequence number
* __SND.NXT__ = next sequence number to be sent
* __SEG.ACK__ = acknowledgment from the receiving TCP (next sequence number expected by the receiving TCP)
* __SEG.SEQ__ = first sequence number of a segment
* __SEG.LEN__ = the number of octets occupied by the data in the segment (counting SYN and FIN)
* __SEG.SEQ__ + __SEG.LEN__ - 1 = last sequence number of a segment

A new acknowledgment (called an "acceptable ack"), is one for which the inequality below holds:

* __SND.UNA__ < __SEG.ACK__ =< __SND.NXT__

A segment on the retransmission queue is fully acknowledged if the sum of its sequence number and length
is less or equal than the acknowledgment value in the incoming segment.

When data is received the following comparisons are needed:

* __RCV.NXT__ = next sequence number expected on an incoming segments, and is the left or lower edge of the receive window
* __RCV.NXT__ + __RCV.WND__ - 1 = last sequence number expected on an incoming segment, and is the right or upper edge of the receive window
* __SEG.SEQ__ = first sequence number occupied by the incoming segment
* __SEG.SEQ__ + __SEG.LEN__ - 1 = last sequence number occupied by the incoming segment
 
A segment is judged to occupy a portion of valid receive sequence space if

* __RCV.NXT__ =< __SEG.SEQ__ < __RCV.NXT__ + __RCV.WND__

 or

* __RCV.NXT__ =< __SEG.SEQ__ + __SEG.LEN__ - 1 < __RCV.NXT__ + __RCV.WND__

The first part of this test checks to see if the beginning of the
segment falls in the window, the second part of the test checks to see
if the end of the segment falls in the window; if the segment passes
either part of the test it contains data in the window.
Actually, it is a little more complicated than this. Due to zero
windows and zero length segments, we have four cases for the
acceptability of an incoming segment:

```
 Segment Receive Test
 Length  Window
 ------- ------- -------------------------------------------
    0       0    SEG.SEQ = RCV.NXT
    0      >0    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
   >0       0    not acceptable
   >0      >0    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                 or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
```

Note that when the receive window is zero no segments should be
acceptable except ACK segments. Thus, it is be possible for a TCP to
maintain a zero receive window while transmitting data and receiving
ACKs. However, even when the receive window is zero, a TCP must
process the RST and URG fields of all incoming segments.

We have taken advantage of the numbering scheme to protect certain
control information as well. This is achieved by implicitly including
some control flags in the sequence space so they can be retransmitted
and acknowledged without confusion (i.e., one and only one copy of the
control will be acted upon). Control information is not physically
carried in the segment data space. Consequently, we must adopt rules
for implicitly assigning sequence numbers to control. The SYN and FIN
are the only controls requiring this protection, and these controls
are used only at connection opening and closing. For sequence number
purposes, the SYN is considered to occur before the first actual data
octet of the segment in which it occurs, while the FIN is considered
to occur after the last actual data octet in a segment in which it
occurs. The segment length (SEG.LEN) includes both data and sequence
space occupying controls. When a SYN is present then SEG.SEQ is the
sequence number of the SYN.

### <A name="isns"></A> Initial Sequence Number Selection

When new connections are created,
an initial sequence number (ISN) generator is employed which selects a
new 32 bit ISN. The generator is bound to a (possibly fictitious) 32
bit clock whose low order bit is incremented roughly every 4
microseconds. Thus, the ISN cycles approximately every 4.55 hours.
Since we assume that segments will stay in the network no more than
the Maximum Segment Lifetime (MSL) and that the MSL is less than 4.55
hours we can reasonably assume that ISN’s will be unique.

For each connection there is a send sequence number and a receive
sequence number. The initial send sequence number (ISS) is chosen by
the data sending TCP, and the initial receive sequence number (IRS) is
learned during the connection establishing procedure.

For a connection to be established or initialized, the two TCPs must
synchronize on each other’s initial sequence numbers. This is done in
an exchange of connection establishing segments carrying a control bit
called "SYN" (for synchronize) and the initial sequence numbers. As a
shorthand, segments carrying the SYN bit are also called "SYNs".
Hence, the solution requires a suitable mechanism for picking an
initial sequence number and a slightly involved handshake to exchange
the ISN’s.
The synchronization requires each side to send it’s own initial
sequence number and to receive a confirmation of it in acknowledgment
from the other side. Each side must also receive the other side’s
initial sequence number and send a confirming acknowledgment.

1. A --> B
    * __SYN__ my sequence number is X
2. A <-- B
    * __ACK__ your sequence number is X
    * __SYN__ my sequence number is Y
3. A --> B
    * __ACK__ your sequence number is Y

This is called the three way (or three message) handshake.

A three way handshake is necessary because sequence numbers are not
tied to a global clock in the network, and TCPs may have different
mechanisms for picking the ISN’s. The receiver of the first SYN has
no way of knowing whether the segment was an old delayed one or not,
unless it remembers the last sequence number used on the connection
(which is not always possible), and so it must ask the sender to
verify this SYN.

## <A name="datacommunication"></A> Data Communication

Once the connection is established data is communicated by the
 exchange of segments. Because segments may be lost due to errors
 (checksum test failure), or network congestion, TCP uses
 retransmission (after a timeout) to ensure delivery of every segment.
 Duplicate segments may arrive due to network or TCP retransmission.
 As discussed in the section on sequence numbers the TCP performs
 certain tests on the sequence and acknowledgment numbers in the
 segments to verify their acceptability.

* The sender of data keeps track of the next sequence number to use in the variable __SND.NXT__
* The receiver of data keeps track of the next sequence number to expect in the variable __RCV.NXT__
* The sender of data keeps track of the oldest unacknowledged sequence number in the variable __SND.UNA__
* If the data flow is momentarily idle and all data sent has been acknowledged then the three variables will be equal
* When the sender creates a segment and transmits it the sender advances __SND.NXT__
* When the receiver accepts a segment it advances __RCV.NXT__ and sends an acknowledgment
* When the data sender receives an acknowledgment it advances __SND.UNA__
* The extent to which the values of these variables differ is a measure of the delay in the communication
* The amount by which the variables are advanced is the length of the data in the segment
* Note that once in the ESTABLISHED state all segments must carry current acknowledgment information
* The CLOSE user call implies a push function, as does the FIN control flag in an incoming segment

### <A name="retransmissiontimeout"></A> Retransmission Timeout

Because of the variability of the networks that compose an
 internetwork system and the wide range of uses of TCP connections the
 retransmission timeout must be dynamically determined. One procedure
 for determining a retransmission time out is given here as an
 illustration.

__An Example Retransmission Timeout Procedure__:

* Measure the elapsed time between sending a data octet with a particular sequence number and receiving an acknowledgment that
 covers that sequence number (segments sent do not have to match segments received).
    * This measured elapsed time is the Round Trip Time (__RTT__).
* Next compute a Smoothed Round Trip Time (__SRTT__) as:
    * __SRTT__ = ( __ALPHA__ * __SRTT__ ) + ((1 - __ALPHA__) * __RTT__)
* and based on this, compute the retransmission timeout (__RTO__) as:
    * RTO = min[__UBOUND__,max[__LBOUND__,(__BETA__ * __SRTT__)]]
        * where __UBOUND__ is an upper bound on the timeout (e.g., 1 minute),
        * __LBOUND__ is a lower bound on the timeout (e.g., 1 second),
        * __ALPHA__ is a smoothing factor (e.g., .8 to .9),
        * and __BETA__ is a delay variance factor (e.g., 1.3 to 2.0).

### <A name="urgent"></A> The Communication of Urgent Information

The objective of the TCP urgent mechanism is to allow the sending user
 to stimulate the receiving user to accept some urgent data and to
 permit the receiving TCP to indicate to the receiving user when all
 the currently known urgent data has been received by the user.

This mechanism permits a point in the data stream to be designated as
the end of urgent information. Whenever this point is in advance of
the receive sequence number (__RCV.NXT__) at the receiving TCP, that TCP
must tell the user to go into "urgent mode"; when the receive sequence
number catches up to the urgent pointer, the TCP must tell user to go
into "normal mode". If the urgent pointer is updated while the user
is in "urgent mode", the update will be invisible to the user.

The method employs a urgent field which is carried in all segments
transmitted. The URG control flag indicates that the urgent field is
meaningful and must be added to the segment sequence number to yield
the urgent pointer. The absence of this flag indicates that there is
no urgent data outstanding.

To send an urgent indication the user must also send at least one data
octet. If the sending user also indicates a push, timely delivery of
the urgent information to the destination process is enhanced.

### <A name="managingwindow"></A> Managing the Window

The window sent in each segment indicates the range of sequence
 numbers the sender of the window (the data receiver) is currently
 prepared to accept. There is an assumption that this is related to
 the currently available data buffer space available for this
 connection.

Indicating a large window encourages transmissions. If more data
 arrives than can be accepted, it will be discarded. This will result
 in excessive retransmissions, adding unnecessarily to the load on the
 network and the TCPs. Indicating a small window may restrict the
 transmission of data to the point of introducing a round trip delay
 between each new segment transmitted.

The mechanisms provided allow a TCP to advertise a large window and to
 subsequently advertise a much smaller window without having accepted
 that much data. This, so called "shrinking the window," is strongly
 discouraged. The robustness principle dictates that TCPs will not
 shrink the window themselves, but will be prepared for such behavior
 on the part of other TCPs.

The sending TCP must be prepared to accept from the user and send at
 least one octet of new data even if the send window is zero. The
 sending TCP must regularly retransmit to the receiving TCP even when
 the window is zero. Two minutes is recommended for the retransmission
 interval when the window is zero. This retransmission is essential to
 guarantee that when either TCP has a zero window the re-opening of the
 window will be reliably reported to the other.

When the receiving TCP has a zero window and a segment arrives it must
 still send an acknowledgment showing its next expected sequence number
 and current window (zero).

The sending TCP packages the data to be transmitted into segments
which fit the current window, and may repackage segments on the
 retransmission queue. Such repackaging is not required, but may be
 helpful.

In a connection with a one-way data flow, the window information will
 be carried in acknowledgment segments that all have the same sequence
 number so there will be no way to reorder them if they arrive out of
 order. This is not a serious problem, but it will allow the window
 information to be on occasion temporarily based on old reports from
 the data receiver. A refinement to avoid this problem is to act on
 the window information from segments that carry the highest
 acknowledgment number (that is segments with acknowledgment number
 equal or greater than the highest previously received).

The window management procedure has significant influence on the
 communication performance. The following comments are suggestions to
 implementers.

__Window Management Suggestions:__

* Allocating a very small window causes data to be transmitted in
 many small segments when better performance is achieved using
 fewer large segments.
* One suggestion for avoiding small windows is for the receiver to
 defer updating a window until the additional allocation is at
 least X percent of the maximum allocation possible for the
 connection (where X might be 20 to 40).
* Another suggestion is for the sender to avoid sending small
 segments by waiting until the window is large enough before
 sending data. If the the user signals a push function then the
 data must be sent even if it is a small segment.
* Note that the acknowledgments should not be delayed or unnecessary
 retransmissions will result. One strategy would be to send an
 acknowledgment when a small segment arrives (with out updating the
 window information), and then to send another acknowledgment with
 new window information when the window is larger.
* The segment sent to probe a zero window may also begin a break up
 of transmitted data into smaller and smaller segments. If a
 segment containing a single data octet sent to probe a zero window
 is accepted, it consumes one octet of the window now available.
 If the sending TCP simply sends as much as it can whenever the
 window is non zero, the transmitted data will be broken into
 alternating big and small segments. As time goes on, occasional
 pauses in the receiver making window allocation available will
 result in breaking the big segments into a small and not quite so
 big pair. And after a while the data transmission will be in
 mostly small segments.
* The suggestion here is that the TCP implementations need to
 actively attempt to combine small window allocations into larger
 windows, since the mechanisms for managing the window tend to lead
 to many small windows in the simplest minded implementations.

## <A name="interfaces"></A> Interfaces

The timeout, if present, permits the caller to set up a timeout
for all data submitted to TCP. If data is not successfully
delivered to the destination within the timeout period, the TCP
will abort the connection. The present global default is five minutes.

### <A name="open"></A> OPEN

```
OPEN(local port, foreign socket, active/passive [, timeout] [, precedence] [, security/compartment] [, options])
-> local connection name
```

### <A name="send"></A> SEND

```
SEND(local connection name, buffer address, byte count, PUSH flag, URGENT flag [,timeout])
```

### <A name="receive"></A> RECEIVE

```
RECEIVE(local connection name, buffer address, byte count)
-> byte count, urgent flag, push flag
```

### <A name="close"></A> CLOSE
```
CLOSE (local connection name)
```

### <A name="status"></A> STATUS

```
STATUS(local connection name) -> status data
```

This is an implementation dependent user command and could be
 excluded without adverse effect. Information returned would
 typically come from the TCB associated with the connection.
 This command returns a data block containing the following
 information:

* local socket,
* foreign socket,
* local connection name,
* receive window,
* send window,
* connection state,
* number of buffers awaiting acknowledgment,
* number of buffers pending receipt,
* urgent state,
* precedence,
* security/compartment,
* and transmission timeout.

### <A name="abort"></A> ABORT

```
ABORT(local connection name)
```

### <A name="tcptouser"></A> TCP-to-User Messages

It is assumed that the operating system environment provides a
 means for the TCP to asynchronously signal the user program. When
 the TCP does signal a user program, certain information is passed
 to the user. Often in the specification the information will be
 an error message. In other cases there will be information
 relating to the completion of processing a SEND or RECEIVE or
 other user call.

The following information is provided:

* Local Connection Name:
    * Always
* Response String:
    * Always
* Buffer Address:
    * SEND & RECEIVE
* Byte count (counts bytes received):
    * RECEIVE
* Push flag:
    * RECEIVE
* Urgent flag:
    * RECEIVE

## <A name="eventprocessing"></A> Event Processing

Events that occur:

* User Calls
    * __OPEN__
    * __SEND__
    * __RECEIVE__
    * __CLOSE__
    * __ABORT__
    * __STATUS__
* Arriving Segments
    * __SEGMENT ARRIVES__
* Timeouts
    * __USER TIMEOUT__
    * __RETRANSMISSION TIMEOUT__
    * __TIME-WAIT TIMEOUT__

-----------------

### <A name="opencall"></A> OPEN Call

* __CLOSED STATE__
    * Create a new transmission control block (TCB) to hold connection state information. Fill in local socket identifier, foreign socket, precedence, security/compartment, and user timeout information. Note that some parts of the foreign socket may be unspecified in a passive OPEN and are to be filled in by the parameters of the incoming SYN segment.
    * Verify the security and precedence requested are allowed for this user, if not return _"error: precedence not allowed"_ or _"error: security/compartment not allowed."_
    * If passive enter the __LISTEN state__ and return.
    * If active and the foreign socket is unspecified, return _"error: foreign socket unspecified"_;
    * if active and the foreign socket is specified, issue a SYN segment. An initial send sequence number (__ISS__) is selected. A SYN segment of the form `<SEQ=ISS><CTL=SYN>` is sent. Set __SND.UNA = ISS__ , __SND.NXT = ISS+1__, enter __SYN-SENT state__, and return.
    * If the caller does not have access to the local socket specified, return "error: connection illegal for this process".
    * If there is no room to create a new connection, return _"error: insufficient resources"_.
* __LISTEN STATE__
    * If active and the foreign socket is specified, then change the connection from passive to active, select an __ISS__. Send a SYN segment, set __SND.UNA = ISS__, __SND.NXT = ISS+1__. Enter __SYN-SENT state__.
    * Data associated with SEND may be sent with SYN segment or queued for transmission after entering ESTABLISHED state.
    * The urgent bit if requested in the command must be sent with the data segments sent as a result of this command.
    * If there is no room to queue the request, respond with _"error: insufficient resources"_.
    * If Foreign socket was not specified, then return _"error: foreign socket unspecified"_.
* __SYN-SENT STATE__
* __SYN-RECEIVED STATE__
* __ESTABLISHED STATE__
* __FIN-WAIT-1 STATE__
* __FIN-WAIT-2 STATE__
* __CLOSE-WAIT STATE__
* __CLOSING STATE__
* __LAST-ACK STATE__
* __TIME-WAIT STATE__
    * Return _"error: connection already exists"_.

----------------

### <A name="sendcall"></A> SEND Call

* __CLOSED STATE__
    * If the user does not have access to such a connection, then return _"error: connection illegal for this process"_.
    * Otherwise, return _"error: connection does not exist"_.
* __LISTEN STATE__
    * If the foreign socket is specified, then change the connection from passive to active, select an __ISS__. Send a SYN segment, set __SND.UNA__ = __ISS__, __SND.NXT__ = __ISS+1__. Enter __SYN-SENT state__. Data associated with SEND may be sent with SYN segment or queued for transmission after entering ESTABLISHED state. The urgent bit if requested in the command must be sent with the data segments sent as a result of this command.
    * If there is no room to queue the request, respond with _"error: insufficient resources"_.
    * If Foreign socket was not specified, then return _"error: foreign socket unspecified"_.
* __SYN-SENT STATE__
* __SYN-RECEIVED STATE__
    * Queue the data for transmission after entering __ESTABLISHED state__.
    * If no space to queue, respond with _"error: insufficient resources"_.
* __ESTABLISHED STATE__
* __CLOSE-WAIT STATE__
    * Segmentize the buffer and send it with a piggybacked acknowledgment (acknowledgment value = __RCV.NXT__).
    * If there is insufficient space to remember this buffer, simply return _"error: insufficient resources"_.
    * If the urgent flag is set, then __SND.UP = SND.NXT-1__ and set the urgent pointer in the outgoing segments.
* __FIN-WAIT-1 STATE__
* __FIN-WAIT-2 STATE__
* __CLOSING STATE__
* __LAST-ACK STATE__
* __TIME-WAIT STATE__
    * Return _"error: connection closing"_ and do not service request.

----------------

### <A name="receivecall"></A> RECEIVE Call

* __CLOSED STATE__
    * If the user does not have access to such a connection, return _"error: connection illegal for this process"_.
    * Otherwise return _"error: connection does not exist"_.
* __LISTEN STATE__
* __SYN-SENT STATE__
* __SYN-RECEIVED STATE__
    * Queue for processing after entering __ESTABLISHED state__.
    * If there is no room to queue this request, respond with _"error: insufficient resources"_.
    * Queue for processing after entering __ESTABLISHED state__.
    * If there is no room to queue this request, respond with _"error: insufficient resources"_.
    * Queue for processing after entering __ESTABLISHED state__.
    * If there is no room to queue this request, respond with _"error: insufficient resources"_.
* __ESTABLISHED STATE__
* __FIN-WAIT-1 STATE__
* __FIN-WAIT-2 STATE__
    * If insufficient incoming segments are queued to satisfy the request, queue the request.
    * If there is no queue space to remember the RECEIVE, respond with _"error: insufficient resources"_.
    * Reassemble queued incoming segments into receive buffer and return to user.
    * Mark "push seen" (PUSH) if this is the case.
    * If __RCV.UP__ is in advance of the data currently being passed to the user notify the user of the presence of urgent data.
    * When the TCP takes responsibility for delivering data to the user that fact must be communicated to the sender via an acknowledgment. The formation of such an acknowledgment is described below in the discussion of processing an incoming segment.
* __CLOSE-WAIT STATE__
    * Since the remote side has already sent FIN, RECEIVEs must be satisfied by text already on hand, but not yet delivered to the user.
    * If no text is awaiting delivery, the RECEIVE will get a _"error: connection closing"_ response.
    * Otherwise, any remaining text can be used to satisfy the RECEIVE.
* __CLOSING STATE__
* __LAST-ACK STATE__
* __TIME-WAIT STATE__
    * Return _"error: connection closing"_.

----------------

### <A name="closecall"></A> CLOSE Call

* __CLOSED STATE__
    * If the user does not have access to such a connection, return _"error: connection illegal for this process"_.
    * Otherwise, return _"error: connection does not exist"_.
* __LISTEN STATE__
    * Any outstanding RECEIVEs are returned with _"error: closing"_ responses.
    * Delete TCB, enter CLOSED state, and return.
* __SYN-SENT STATE__
    * Delete the TCB and return _"error: closing"_ responses to any queued SENDs, or RECEIVEs.
* __SYN-RECEIVED STATE__
    * If no SENDs have been issued and there is no pending data to send, then form a FIN segment and send it, and enter __FIN-WAIT-1 state__;
    * otherwise queue for processing after entering __ESTABLISHED state__.
* __ESTABLISHED STATE__
    * Queue this until all preceding SENDs have been segmentized, then form a FIN segment and send it.
    * In any case, enter __FIN-WAIT-1 state__.
* __FIN-WAIT-1 STATE__
* __FIN-WAIT-2 STATE__
    * Strictly speaking, this is an error and should receive a _"error: connection closing"_ response. An _"ok"_ response would be acceptable, too, as long as a second FIN is not emitted (the first FIN may be retransmitted though).
* __CLOSE-WAIT STATE__
    * Queue this request until all preceding SENDs have been segmentized; then send a FIN segment, enter __CLOSING state__.
* __CLOSING STATE__
    * Respond with _"error: connection closing"_.
* __LAST-ACK STATE__
    * Respond with _"error: connection closing"_.
* __TIME-WAIT STATE__
    * Respond with _"error: connection closing"_.

----------------

### <A name="abortcall"></A> ABORT Call

* __CLOSED STATE__
    * If the user should not have access to such a connection, return _"error: connection illegal for this process"_.
    * Otherwise return _"error: connection does not exist"_.
* __LISTEN STATE__
    * Any outstanding RECEIVEs should be returned with _"error: connection reset"_ responses.
    * Delete TCB, enter __CLOSED state__, and return.
* __SYN-SENT STATE__
    * All queued SENDs and RECEIVEs should be given _"connection reset"_ notification, delete the TCB, enter __CLOSED state__, and return.
* __SYN-RECEIVED STATE__
* __ESTABLISHED STATE__
* __FIN-WAIT-1 STATE__
* __FIN-WAIT-2 STATE__
* __CLOSE-WAIT STATE__
    * Send a reset segment: `<SEQ=SND.NXT><CTL=RST>`
    * All queued SENDs and RECEIVEs should be given _"connection reset"_ notification;
    * all segments queued for transmission (except for the RST formed above) or retransmission should be flushed, delete the TCB, enter __CLOSED state__, and return.
* __CLOSING STATE__
* __LAST-ACK STATE__
* __TIME-WAIT STATE__
    * Respond with _"ok"_ and delete the TCB, enter __CLOSED state__, and return.

----------------

### <A name="statuscall"></A> STATUS Call

* __CLOSED STATE__
    * If the user should not have access to such a connection, return _"error: connection illegal for this process"_.
    * Otherwise return _"error: connection does not exist"_.
* __LISTEN STATE__
* __SYN-SENT STATE__
* __SYN-RECEIVED STATE__
* __ESTABLISHED STATE__
* __FIN-WAIT-1 STATE__
* __FIN-WAIT-2 STATE__
* __CLOSE-WAIT STATE__
* __CLOSING STATE__
* __LAST-ACK STATE__
* __TIME-WAIT STATE__
    * Return associated "state", and the TCB pointer

----------------

### <A name="segmentarrives"></A> SEGMENT ARRIVES

* __If the state is CLOSED then__
    * all data in the incoming segment is discarded.
    * An incoming segment containing a RST is discarded.
    * An incoming segment not containing a RST causes a RST to be sent in response.
        * The acknowledgment and sequence field values are selected to make the reset sequence acceptable to the TCP that sent the offending segment.
        * If the ACK bit is off, sequence number zero is used, `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`.
        * If the ACK bit is on, `<SEQ=SEG.ACK><CTL=RST>`.
* __If the state is LISTEN then__
    * first check for an RST
        * An incoming RST should be ignored.
        * Return.
    * second check for an ACK
        * Any acknowledgment is bad if it arrives on a connection still in the __LISTEN state__. An acceptable reset segment should be formed for any arriving ACK-bearing segment. The RST should be formatted as follows: `<SEQ=SEG.ACK><CTL=RST>`
        * Return.
    * third check for a SYN
        * If the SYN bit is set, check the security.
            * If the security/compartment on the incoming segment does not exactly match the security/compartment in the TCB then send a reset `<SEQ=SEG.ACK><CTL=RST>` and return.
        * If the SEG.PRC is greater than the TCB.PRC then if allowed by the user and the system set TCB.PRC<-SEG.PRC, if not allowed send a reset `<SEQ=SEG.ACK><CTL=RST>` and return.
        * If the SEG.PRC is less than the TCB.PRC then continue.
        * Set __RCV.NXT = SEG.SEQ+1__, __IRS = SEG.SEQ__ and any other control or text should be queued for processing later.
        * __ISS__ should be selected and a SYN segment sent of the form: `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`
        * __SND.NXT = ISS+1__ and __SND.UNA = ISS__. The connection state should be changed to __SYN-RECEIVED state__.
        * Note that any other incoming control or data (combined with SYN) will be processed in the SYN-RECEIVED state, but processing of SYN and ACK should not be repeated. If the listen was not fully specified (i.e., the foreign socket was not fully specified), then the unspecified fields should be filled in now.
    * fourth other text or control
        * Any other control or text-bearing segment (not containing SYN) must have an ACK and thus would be discarded by the ACK processing.
        * An incoming RST segment could not be valid, since it could not have been sent in response to anything sent by this incarnation of the connection.
        * So you are unlikely to get here, but if you do, drop the segment, and return.
* __If the state is SYN-SENT then__
    * first check the ACK bit
        * If the ACK bit is set
            * If __SEG.ACK =< ISS__ or __SEG.ACK > SND.NXT__ send a reset (unless the RST bit is set, if so drop the segment and return) `<SEQ=SEG.ACK><CTL=RST>` and discard the segment. Return.
            * If __SND.UNA =< SEG.ACK =< SND.NXT__ then the ACK is acceptable.
    * second check the RST bit
        * If the RST bit is set
            * If the ACK was acceptable then signal the user _"error: connection reset"_, drop the segment, enter CLOSED state, delete TCB, and return.
            * Otherwise (no ACK) drop the segment and return.
    * third check the security and precedence
        * If the security/compartment in the segment does not exactly match the security/compartment in the TCB, send a reset
            * If there is an ACK `<SEQ=SEG.ACK><CTL=RST>`
            * Otherwise `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`
        * If there is an ACK
            * The precedence in the segment must match the precedence in the TCB, if not, send a reset `<SEQ=SEG.ACK><CTL=RST>`
        * If there is no ACK
            * If the precedence in the segment is higher than the precedence in the TCB then if allowed by the user and the system raise the precedence in the TCB to that in the segment, if not allowed to raise the prec then send a reset. `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`
            * If the precedence in the segment is lower than the precedence in the TCB continue.
        * If a reset was sent, discard the segment and return.
    * fourth check the SYN bit
        * This step should be reached only if the ACK is ok, or there is no ACK, and it the segment did not contain a RST.
        * If the SYN bit is on and the security/compartment and precedence are acceptable then, __RCV.NXT = SEG.SEQ+1__, __IRS = SEG.SEQ__. __SND.UNA__ should be advanced to equal __SEG.ACK__ (if there is an ACK), and any segments on the retransmission queue which are thereby acknowledged should be removed.
        * If __SND.UNA > ISS__ (our SYN has been ACKed), change the connection state to __ESTABLISHED state__, form an ACK segment `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` and send it. Data or controls which were queued for transmission may be included.
        * If there are other controls or text in the segment then continue processing at the sixth step below where the URG bit is checked, otherwise return.
        * Otherwise enter __SYN-RECEIVED state__, form a SYN,ACK segment `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>` and send it.
        * If there are other controls or text in the segment, queue them for processing after the __ESTABLISHED state__ has been reached, return.
    * fifth, if neither of the SYN or RST bits is set then drop the segment and return.

Otherwise (state not equal to __CLOSE__, __LISTEN__ or __SYN_SENT state__),

1. __Check sequence number,__
    * __SYN-RECEIVED STATE__
    * __ESTABLISHED STATE__
    * __FIN-WAIT-1 STATE__
    * __FIN-WAIT-2 STATE__
    * __CLOSE-WAIT STATE__
    * __CLOSING STATE__
    * __LAST-ACK STATE__
    * __TIME-WAIT STATE__
        * Segments are processed in sequence. Initial tests on arrival are used to discard old duplicates, but further processing is done in __SEG.SEQ__ order.
        * If a segment’s contents straddle the boundary between old and new, only the new parts should be processed.
        * There are four cases for the acceptability test for an incoming segment: <PRE>
Segment Receive Test
Length  Window
   0       0    SEG.SEQ = RCV.NXT
   0      >0    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
  >0       0    not acceptable
  >0      >0    RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
             or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND</PRE>
        * If the __RCV.WND__ is zero, no segments will be acceptable, but special allowance should be made to accept valid ACKs, URGs and RSTs.
        * If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return): `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`
        * After sending the acknowledgment, drop the unacceptable segment and return.
        * In the following it is assumed that the segment is the idealized segment that begins at __RCV.NXT__ and does not exceed the window.
        * One could tailor actual segments to fit this assumption by trimming off any portions that lie outside the window (including SYN and FIN), and only processing further if the segment then begins at __RCV.NXT__.
        * Segments with higher begining sequence numbers may be held for later processing.
2. __Check the RST bit,__
    * __SYN-RECEIVED STATE__
        * If the RST bit is set
            * If this connection was initiated with a passive OPEN (i.e., came from the __LISTEN state__), then return this connection to __LISTEN state__ and return. The user need not be informed.
            * If this connection was initiated with an active OPEN (i.e., came from __SYN-SENT state__) then the connection was refused, signal the user "connection refused".
            * In either case, all segments on the retransmission queue should be removed.
            * And in the active OPEN case, enter the __CLOSED state__ and delete the TCB, and return.
    * __ESTABLISHED__
    * __FIN-WAIT-1__
    * __FIN-WAIT-2__
    * __CLOSE-WAIT__
        * If the RST bit is set then, any outstanding RECEIVEs and SEND should receive _"reset"_ responses.
        * All segment queues should be flushed.
        * Users should also receive an unsolicited general _"connection reset"_ signal.
        * Enter the __CLOSED state__, delete the TCB, and return.
    * __CLOSING STATE__
    * __LAST-ACK STATE__
    * __TIME-WAIT__
        * If the RST bit is set then, enter the __CLOSED state__, delete the TCB, and return.
3. __Check security and precedence,__
    * __SYN-RECEIVED__
        * If the security/compartment and precedence in the segment do not exactly match the security/compartment and precedence in the TCB then send a reset, and return.
    * __ESTABLISHED STATE__
        * If the security/compartment and precedence in the segment do not exactly match the security/compartment and precedence in the TCB then send a reset, any outstanding RECEIVEs and SEND should receive _"reset"_ responses.
        * All segment queues should be flushed.
        * Users should also receive an unsolicited general _"connection reset"_ signal.
        * Enter the __CLOSED state__, delete the TCB, and return.
    * Note this check is placed following the sequence check to prevent a segment from an old connection between these ports with a different security or precedence from causing an abort of the current connection.
4. __Check the SYN bit,__
    * __SYN-RECEIVED__
    * __ESTABLISHED STATE__
    * __FIN-WAIT STATE-1__
    * __FIN-WAIT STATE-2__
    * __CLOSE-WAIT STATE__
    * __CLOSING STATE__
    * __LAST-ACK STATE__
    * __TIME-WAIT STATE__
        * If the SYN is in the window it is an error, send a reset, any outstanding RECEIVEs and SEND should receive _"reset"_ responses, all segment queues should be flushed, the user should also receive an unsolicited general _"connection reset"_ signal, enter the __CLOSED state__, delete the TCB, and return.
        * If the SYN is not in the window this step would not be reached and an ack would have been sent in the first step (sequence number check).
5. __Check the ACK field,__
    * if the ACK bit is off drop the segment and return
    * if the ACK bit is on
        * __SYN-RECEIVED STATE__
            * If __SND.UNA =< SEG.ACK =< SND.NXT__ then enter __ESTABLISHED state__ and continue processing
            * If the segment acknowledgment is not acceptable, form a reset segment, `<SEQ=SEG.ACK><CTL=RST>` and send it
        * __ESTABLISHED STATE__
            * If __SND.UNA < SEG.ACK =< SND.NXT__ then __SND.UNA = SEG.ACK__
            * Any segments on the retransmission queue which are thereby entirely acknowledged are removed.
            * Users should receive positive acknowledgments for buffers which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with _"ok"_ response).
            * If the ACK is a duplicate (__SEG.ACK < SND.UNA__), it can be ignored.
            * If the ACK acks something not yet sent (__SEG.ACK > SND.NXT__) then send an ACK, drop the segment, and return.
            * If __SND.UNA < SEG.ACK =< SND.NXT__, the send window should be updated.
            * If (__SND.WL1 < SEG.SEQ__ or (__SND.WL1 == SEG.SEQ__ and __SND.WL2 =< SEG.ACK__)), set __SND.WND = SEG.WND__, set __SND.WL1 = SEG.SEQ__, and set __SND.WL2 = SEG.ACK__
            * Note that __SND.WND__ is an offset from __SND.UNA__, that __SND.WL1__ records the sequence number of the last segment used to update __SND.WND__, and that __SND.WL2__ records the acknowledgment number of the last segment used to update __SND.WND__.
            The check here prevents using old segments to update the window.
        * __FIN-WAIT-1 STATE__
            * In addition to the processing for the __ESTABLISHED state__, if our FIN is now acknowledged then enter __FIN-WAIT-2 state__ and continue processing in that state.
        * __FIN-WAIT-2 STATE__
            * In addition to the processing for the __ESTABLISHED state__, if the retransmission queue is empty, the user’s CLOSE can be acknowledged (_"ok"__) but do not delete the TCB.
        * __CLOSE-WAIT STATE__
            * Do the same processing as for the __ESTABLISHED state__.
        * __CLOSING STATE__
            * In addition to the processing for the __ESTABLISHED state__, if the ACK acknowledges our FIN then enter the __TIME-WAIT state__, otherwise ignore the segment.
        * __LAST-ACK STATE__
            * The only thing that can arrive in this state is an acknowledgment of our FIN.
            If our FIN is now acknowledged, delete the TCB, enter the __CLOSED state__, and return.
        * __TIME-WAIT STATE__
            * The only thing that can arrive in this state is a retransmission of the remote FIN. Acknowledge it, and restart the 2 MSL timeout.
6. __Check the URG bit,__
    * __ESTABLISHED STATE__
    * __FIN-WAIT-1 STATE__
    * __FIN-WAIT-2 STATE__
        * If the URG bit is set, __RCV.UP = max(RCV.UP,SEG.UP)__, and signal the user that the remote side has urgent data if the urgent pointer (__RCV.UP__) is in advance of the data consumed.
        * If the user has already been signaled (or is still in the _"urgent mode"_) for this continuous sequence of urgent data, do not
 signal the user again.
    * __CLOSE-WAIT STATE__
    * __CLOSING STATE__
    * __LAST-ACK STATE__
    * __TIME-WAIT__
        * This should not occur, since a FIN has been received from the remote side.
        * Ignore the URG.
7. __Process the segment text,__
    * __ESTABLISHED STATE__
    * __FIN-WAIT-1 STATE__
    * __FIN-WAIT-2 STATE__
        * Once in the __ESTABLISHED state__, it is possible to deliver segment text to user RECEIVE buffers.
        * Text from segments can be moved into buffers until either the buffer is full or the segment is empty.
        * If the segment empties and carries an PUSH flag, then the user is informed, when the buffer is returned, that a PUSH has been received.
        * When the TCP takes responsibility for delivering the data to the user it must also acknowledge the receipt of the data.
        * Once the TCP takes responsibility for the data it advances __RCV.NXT__ over the data accepted, and adjusts __RCV.WND__ as apporopriate to the current buffer availability. The total of __RCV.NXT__ and __RCV.WND__ should not be reduced.
        * Send an acknowledgment of the form: `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`
        * This acknowledgment should be piggybacked on a segment being transmitted if possible without incurring undue delay.
    * __CLOSE-WAIT STATE__
    * __CLOSING STATE__
    * __LAST-ACK STATE__
    * __TIME-WAIT STATE__
        * This should not occur, since a FIN has been received from the remote side.
        * Ignore the segment text.
8. __Check the FIN bit:__
    * Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT since the SEG.SEQ cannot be validated; drop the segment and return.
If the FIN bit is set, signal the user _"connection closing"_ and return any pending RECEIVEs with same message, advance __RCV.NXT__ over the FIN, and send an acknowledgment for the FIN. Note that FIN implies PUSH for any segment text not yet delivered to the user.
    * __SYN-RECEIVED STATE__
    * __ESTABLISHED STATE__
        * Enter the __CLOSE-WAIT state__.
    * __FIN-WAIT-1 STATE__
        * If our FIN has been ACKed (perhaps in this segment), then enter __TIME-WAIT state__, start the time-wait timer, turn off the other timers; otherwise enter the __CLOSING state__.
    * __FIN-WAIT-2 STATE__
        * Enter the TIME-WAIT state. Start the time-wait timer, turn off the other timers.
    * __CLOSE-WAIT STATE__
        * Remain in the __CLOSE-WAIT state__.
    * __CLOSING STATE__
        * Remain in the __CLOSING state__.
    * __LAST-ACK STATE__
        * Remain in the __LAST-ACK state__.
    * __TIME-WAIT STATE__
        * Remain in the __TIME-WAIT state__. Restart the 2 MSL time-wait timeout.

and return.

----------------

### <A name="usertimeout"></A> USER TIMEOUT

For any state if the user timeout expires, flush all queues, signal the user _"error: connection aborted due to user timeout"_ in general and for any outstanding calls, delete the TCB, enter the __CLOSED state__ and return.

----------------

### <A name="retransmissiontimeoutevent"></A> RETRANSMISSION TIMEOUT

For any state if the retransmission timeout expires on a segment in the retransmission queue, send the segment at the front of the retransmission queue again, reinitialize the retransmission timer, and return.

----------------

### <A name="timewaittimeout"></A> TIME-WAIT TIMEOUT

If the time-wait timeout expires on a connection delete the TCB, enter the __CLOSED state__ and return.

