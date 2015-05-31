

# CUBIC Congestion Control

Extracts from __draft-rhee-tcpm-cubic-02__: [https://tools.ietf.org/html/draft-rhee-tcpm-cubic-02](https://tools.ietf.org/html/draft-rhee-tcpm-cubic-02)

---------------------

## Table of Content

* [Window growth function](#windowgrowth)
    * [TCP-friendly region](#tcpfriendly)
    * [Concave region](#concaveregion)
    * [Convex region](#convexregion)
* [Multiplicative decrease](#multiplicationdecrease)
* [Fast Convergence](#fastconvergence)
* [Discussion](#discussion)
    * [Fairness to standard TCP](#fairnesstotcp)

## <A name="windowgrowth"></A> Window growth function

CUBIC maintains the acknowledgment (ACK) clocking of Standard TCP by increasing congestion window only at the reception of ACK.
The protocol does not make any change to the fast recovery and retransmit of TCP-NewReno [RFC3782] and TCP-SACK [RFC2018].
During congestion avoidance after fast recovery, CUBIC changes the window update algorithm of Standard TCP.
Suppose that W_max is the window size before the window is reduced in the last fast retransmit and recovery.

The window growth function of CUBIC uses the following function:

* _Equation 1:_
    * __W(t) = C*(t-K)^3 + W_max__

Where C is a constant fixed to determine the aggressiveness of window growth in high BDP networks, t is the elapsed time from the last window eduction, and K is the time period that the above function takes to increase W to W_max when there is no further loss event and is calculated by using the following equation:

* _Equation 2:_
    * __K = cubic_root(W_max*beta/C)__

where beta is the multiplication decrease factor. We discuss how we set C in the next Section in more details.

Upon receiving an ACK during congestion avoidance, CUBIC computes the window growth rate during the next RTT period using _Equation 1_. It sets W(t+RTT) as the candidate target value of congestion window.

Suppose that the current window size is cwnd. Depending on the value of cwnd, CUBIC runs in three different modes.

1. __TCP friendly region__ : if cwnd is less than the window size that Standard TCP would reach at time t after the last loss event (we describe below how to determine this window size of Standard TCP in term of time t)
2. __Concave region__ : if cwnd is less than W_max
3. __Convex region__ : if cwnd is larger than W_max

![CUBIC window growth function](./CUBIC.png)
Below, we describe the exact actions taken by CUBIC in each region.

### <A name="tcpfriendly"></A> TCP-friendly region

When receiving an ACK in congestion avoidance, we first check whether the protocol is in the TCP region or not. This is done as follows. We can analyze the window size of Standard TCP in terms of the elapsed time t. Using a simple analysis in [FHP00], we can analyze the average window size of additive increase and multiplicative decrease (AIMD) with an additive factor alpha and a multiplicative factor beta to be the following function:

* _Equation 3:_
    * __(alpha/2 * (2-beta)/beta * 1/p)^0.5__

By the same analysis, the average window size of Standard TCP with alpha=1 and beta=0.5 is (3/2 *1/p) ^ 0.5.

Thus, for _Equation 3_ to be the same as that of Standard TCP, alpha must be equal to 3*beta/(2-beta).
As Standard TCP increases its window by alpha per RTT, we can get the window size of Standard TCP in terms of the elapsed time t as follows:

* _Equation 4:_
    * __W_tcp(t) = W_max*(1-beta) + 3 * beta/(2-beta) * t/RTT__

  
If cwnd is less than W_tcp(t), then the protocol is in the TCP friendly region:

* In this region __cwnd SHOULD be set to W_tcp(t) at each reception of ACK__.

### <A name="concaveregion"></A> Concave region

When receiving an ACK in congestion avoidance, if the protocol is not in the TCP-friendly region and cwnd is less than W_max, then the protocol is in the concave region.

* In this region, cwnd MUST be incremented by __(W(t+RTT) - cwnd)/cwnd__.

### <A name="convexregion"></A> Convex region

When the window size of CUBIC is larger than W_max, it passes the plateau of the cubic function after which CUBIC follows the convex profile of the cubic function.  Since cwnd is larger than the previous saturation point W_max, this indicates that the network conditions might have been perturbed since the last loss event, possibly implying more available bandwidth after some flow departures. Since the Internet is highly asynchronous, some amount of perturbation is always possible without causing a major change in available bandwidth. In this phase, CUBIC is being very careful by very slowly increasing its window size. The convex profile ensures that the window increases very slowly at the beginning and gradually increases its growth rate. We also call this phase as the maximum probing phase since CUBIC is searching for a new W_max.

* In this region, __cwnd MUST be incremented by (W(t+RTT) - cwnd)/cwnd for each received ACK__.

## <A name="multiplicativedecrease"></A> Multiplicative decrease

* When a packet loss occurs, CUBIC reduces its window size by a factor of beta
* Parameter __beta SHOULD be set to 0.2__

```
W_max = cwnd            // remember the window size before reduction
cwnd = cwnd * (1-beta)  // window reduction
```

A side effect of setting beta to a smaller value than 0.5 is slower convergence. We believe that while a more adaptive setting of beta could result in faster convergence, it will make the analysis of the protocol much harder. This adaptive adjustment of beta is an item for the next version of CUBIC.

## <A name="fastconvergence"></A> Fast convergence

To improve the convergence speed of CUBIC, we add a heuristic in the protocol. When a new flow joins the network, existing flows in the network need to give up their bandwidth shares to allow the flow some room for growth if the existing flows have been using all the bandwidth of the network. To increase this release of bandwidth by existing flows, the following mechanism called fast convergence SHOULD be implemented.

With fast convergence, when a loss event occurs, before a window reduction of congestion window, a flow remembers the last value of W_max before it updates W_max for the current loss event.  Let us call the last value of W_max to be W_last_max.

```
if (W_max < W_last_max) {      // check downward trend,
    W_last_max = W_max         // remember the last W_max.
    W_max = W_max*(2-beta)/2   // further reduce W_max.
} else                         // check upward trend.
W_last_max = W_max             // remember the last W_max.
```

This allows W_max to be slightly less than the original W_max. Since flows spend most of time around their W_max, flows with larger bandwidth shares tend to spend more time around the plateau allowing more time for flows with smaller shares to increase their windows.

## <A name="discussion"></A> Discussion

With a deterministic loss model where the number of packets between two successive lost events is always 1/p, CUBIC always operates with the concave window profile which greatly simplifies the performance analysis of CUBIC.

The average window size of CUBIC can be obtained by the following function:

* _Equation 5:_
    * __(C*(4-beta)/4/beta)^0.25 * (RTT ^ 0.75) / (p ^ 0.75)__

   With beta set to 0.2, the above formula is reduced to:

* _Equation 6:_
    * __(C*3.8/0.8)^0.25 * (RTT ^ 0.75) / (p ^ 0.75)__

We will determine the value of C in the following subsection using _Equation 6_.

### <A name="fairnesstotcp"></A> Fairness to standard TCP

In environments where standard TCP is able to make reasonable use of the available bandwidth, CUBIC does not significantly change this state.

Standard TCP performs well in the following two types of networks:

1. networks with a small bandwidth-delay product (BDP).
2. networks with a short RTT, but not necessarily a small BDP

CUBIC is designed to behave very similarly to standard TCP in the above two types of networks.

The following two tables show the average window size of standard TCP, HSTCP, and CUBIC.

* The average window size of standard TCP and HSTCP is from [RFC3649].
* The average window size of CUBIC is calculated by using _Equation 6_ and CUBIC TCP friendly mode for three different values of C.

_Response function of standard TCP, HSTCP, and CUBIC in networks with __RTT = 100ms__.  
The average window size W is in MSS-sized segments._

```
   +----------+-------+--------+-------------+-------------+-----------+
   |     Loss |   TCP |  HSTCP |       CUBIC |       CUBIC |     CUBIC |
   |   Rate P |       |        |    (C=0.04) |     (C=0.4) |     (C=4) |
   +----------+-------+--------+-------------+-------------+-----------+
   |    10^-2 |    12 |     12 |          12 |          12 |        12 |
   |          |       |        |             |             |           |
   |    10^-3 |    38 |     38 |          38 |          38 |        66 |
   |          |       |        |             |             |           |
   |    10^-4 |   120 |    263 |         120 |         209 |       371 |
   |          |       |        |             |             |           |
   |    10^-5 |   379 |   1795 |         660 |        1174 |      2087 |
   |          |       |        |             |             |           |
   |    10^-6 |  1200 |  12279 |        3713 |        6602 |     11740 |
   |          |       |        |             |             |           |
   |    10^-7 |  3795 |  83981 |       20878 |       37126 |     66022 |
   |          |       |        |             |             |           |
   |    10^-8 | 12000 | 574356 |      117405 |      208780 |    371269 |
   +----------+-------+--------+-------------+-------------+-----------+
```

_Response function of standard TCP, HSTCP, and CUBIC in networks with __RTT = 10ms__.  
The average window size W is in MSS-sized segments._

```
   +--------+-----------+-----------+------------+-----------+---------+
   |   Loss |   Average |   Average |      CUBIC |     CUBIC |   CUBIC |
   | Rate P |     TCP W |   HSTCP W |   (C=0.04) |   (C=0.4) |   (C=4) |
   +--------+-----------+-----------+------------+-----------+---------+
   |  10^-2 |        12 |        12 |         12 |        12 |      12 |
   |        |           |           |            |           |         |
   |  10^-3 |        38 |        38 |         38 |        38 |      38 |
   |        |           |           |            |           |         |
   |  10^-4 |       120 |       263 |        120 |       120 |     120 |
   |        |           |           |            |           |         |
   |  10^-5 |       379 |      1795 |        379 |       379 |     379 |
   |        |           |           |            |           |         |
   |  10^-6 |      1200 |     12279 |       1200 |      1200 |    2087 |
   |        |           |           |            |           |         |
   |  10^-7 |      3795 |     83981 |       3795 |      6603 |   11740 |
   |        |           |           |            |           |         |
   |  10^-8 |     12000 |    574356 |      20878 |     37126 |   66022 |
   +--------+-----------+-----------+------------+-----------+---------+
```

* Both tables show that CUBIC with any of these three C values is more friendly to TCP than HSTCP, especially in networks with a short RTT where TCP performs reasonably well.  For example, in a network with RTT = 10ms and p=10^(-6), TCP has an average window of 1200 packets.
* If the packet size is 1500 bytes, then TCP can achieve an average rate of 1.44 Gbps. In this case, CUBIC with C=0.04 or C=0.4 achieves exactly the same rate as Standard TCP, whereas HSTCP is about ten times more aggressive than Standard TCP.

We can see that C determines the aggressiveness of CUBIC in competing with other protocols for the bandwidth.

CUBIC is more friendly to the Standard TCP, if the value of C is lower. However, we do not recommend to set C to a very low value like 0.04, since CUBIC with a low C cannot efficiently use the bandwidth in long RTT and high bandwidth networks. Based on these observations, we find C=0.4 gives a good balance between TCP-friendliness and aggressiveness of window growth. Therefore, __C SHOULD be set to 0.4__.

With C set to 0.4, _Equation 6_ is reduced to:

* _Equation 7:_
    * __1.17 * (RTT ^ 0.75) / (p ^ 0.75)__


