// Package quic provides a portable interface for network I/O with QUIC, a multiplexed stream transport over UDP.
//
// See https://www.chromium.org/quic
package quic

import "net"
import "time"

type QUICListener struct {
}

type QUICSession struct {
}

type StreamConn struct {
}

// ListenUDP listens for incoming UDP packets addressed to the local address laddr.
// Net must be "udp", "udp4", or "udp6".
// If laddr has a port of 0, ListenUDP will choose an available port.
// The LocalAddr method of the returned QUICSession can be used to discover the port.
// The returned connection's ReadFrom and WriteTo methods can be used to receive and send UDP packets with per-packet addressing.
func ListenQUIC(net string, laddr *net.UDPAddr) (*QUICListener, error) {
	return nil, nil
}

// AcceptQUIC accepts the next incoming new QUIC call and returns the new session.
func (l *QUICListener) AcceptQUIC() (*QUICSession, error) {
	return nil, nil
}

// Addr returns the listener's network address, a *UDPAddr.
func (l *QUICListener) Addr() (a net.UDPAddr) {
	return
}

// Close stops listening on the QUIC address.
// Already Accepted sessions are not closed.
func (l *QUICListener) Close() error {
	return nil
}

// SetDeadline sets the deadline associated with the listener.
// A zero time value disables the deadline.
func (l *QUICListener) SetDeadline(t time.Time) error {
	return nil
}

// DialQUIC connects to the remote address raddr on the network net, which must be "udp", "udp4", or "udp6".
// If laddr is not nil, it is used as the local address for the connection.
func DialQUIC(net string, laddr, raddr *net.UDPAddr) (*QUICSession, error) {
	return nil, nil
}

// Close closes the session.
func (s *QUICSession) Close() error {
	return nil
}

// PublicReset closes immediatly the session.
func (s *QUICSession) PublicReset() error {
	return nil
}

// LocalAddr returns the local network address.
func (s *QUICSession) LocalAddr() (l net.UDPAddr) {
	return
}

// RemoteAddr returns the remote network address.
func (s *QUICSession) RemoteAddr() (r net.UDPAddr) {
	return
}

// SetKeepAlive sets whether the QUIC session should send PING frames on the connection.
func (s *QUICSession) SetKeepAlive(keepalive bool) error {
	return nil
}

// SetKeepAlivePeriod sets period between QUIC PING frames.
func (s *QUICSession) SetKeepAlivePeriod(d time.Duration) error {
	return nil
}

// PING is a blocking function that send a PING frame and waits for the associated ACK
func (s *QUICSession) Ping(keepalive bool) error {
	return nil
}

// NewStrem creates and add a new Stream connection on the QUIC session.
func (s *QUICSession) NewStream() (*StreamConn, error) {
	return nil, nil
}

// AcceptStream accepts the next incoming stream and returns the new connection.
func (s *QUICSession) AcceptStream() (*StreamConn, error) {
	return nil, nil
}

// Close closes the connection.
func (c *StreamConn) Close() error {
	return nil
}

// CloseRead shuts down the reading side of the Stream connection.
// Most callers should just use Close.
func (c *StreamConn) CloseRead() error {
	return nil
}

// CloseWrite shuts down the writing side of the Stream connection.
// Most callers should just use Close.
func (c *StreamConn) CloseWrite() error {
	return nil
}

// Read implements the net.Conn Read method.
// Read reads data from the Stream connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *StreamConn) Read(b []byte) (int, error) {
	return 0, nil
}

// Write implements the net.Conn Write method.
// Write writes data to the Stream connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *StreamConn) Write(b []byte) (int, error) {
	return 0, nil
}

// Write writes data to the Stream connection with Forward Error Correction (FEC).
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *StreamConn) WriteFEC(b []byte) (int, error) {
	return 0, nil
}

// Write writes important data to the Stream connection by sending duplicate QUIC packet with pacing.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *StreamConn) WriteDuplicate(b []byte) (int, error) {
	return 0, nil
}

// SetDeadline implements the net.Conn SetDeadline method.
func (c *StreamConn) SetDeadline(t time.Time) error {
	return nil
}

// SetLinger sets the behavior of Close on a connection which still has data waiting to be sent or to be acknowledged.
//
// If sec < 0 (the default), the operating system finishes sending the data in the background.
//
// If sec == 0, the operating system discards any unsent or unacknowledged data.
//
// If sec > 0, the data is sent in the background as with sec < 0.
// On some operating systems after sec seconds have elapsed any remaining unsent data may be discarded.
func (c *StreamConn) SetLinger(sec int) error {
	return nil
}

// SetNoDelay controls whether the operating system should delay packet transmission in hopes of sending fewer packets (like TCP Nagle's algorithm).
// The default is true (no delay), meaning that data is sent as soon as possible after a Write.
func (c *StreamConn) SetNoDelay(noDelay bool) error {
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *StreamConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (c *StreamConn) SetWriteDeadline(t time.Time) error {
	return nil
}
