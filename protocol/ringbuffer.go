package protocol

import "errors"

// RingBuffer implements io.ReadWriter interface with an internal buffer.
// It is safe to have only one Reader and only one concurrent Writer.
// But it is totally unsafe to use it as is with multiple readers or multiple writers without an external synchronization mechanism.
type RingBuffer struct {
	buffer   []byte
	size     int
	writePos int
	readPos  int
}

// NewReadBuffer is a factory for RingBuffer, from various size in bytes.
func NewRingBuffer(size int) (error, *RingBuffer) {
	b := make([]byte, size, size)
	if len(b) != size {
		return errors.New("RingBuffer: Failed to allocated memory buffer"), nil
	}
	return nil, &RingBuffer{
		buffer: b,
		size:   size}
}

// GetBufferSize returns the size of the buffer.
func (this *RingBuffer) GetBufferSize() int {
	return this.size
}

// CanRead returns the current number of bytes in the RingBuffer that can be reads.
func (this *RingBuffer) CanRead() int {
	n := this.writePos - this.readPos
	if n >= 0 {
		return n
	} else {
		return len(this.buffer) - n
	}
}

// CanRead returns the current number of bytes in the RingBuffer that can be writes.
func (this *RingBuffer) CanWrite() int {
	n := this.readPos - this.writePos
	if n >= 0 {
		return n
	} else {
		return len(this.buffer) - n
	}
}

// Resize function grows or diminishes the buffer as soon as it is possible.
//
// Depending on current RingBuffer's state, growth can be done immediatly or when enough Reading & Writing have occured so the RingBuffer is not half cut on the end and the beginning of the buffer.
//
// Depending on current RingBuffer's state, diminish can be done immedialtly or when enough Reading have occured.
func (this *RingBuffer) Resize(newsize int) error {
	return errors.New("RingBuffer: Resize FUNC NOT YET IMPLEMENTED !")
}

// Read reads up to len(p) bytes into p. It returns the number of bytes read (0 <= n <= len(p)) and any error encountered.
// Even if Read returns n < len(p), it may use all of p as scratch space during the call.
// If some data is available but not len(p) bytes, Read conventionally returns what is available instead of waiting for more.
//
// Implementations does not retain p.
func (this *RingBuffer) Read(p []byte) (n int, err error) {
	rp := this.readPos
	wp := this.writePos
	n = wp - rp
	if n == 0 {
		// current read buffer is empty
		return
	}
	lenp := len(p)
	max := len(this.buffer)
	if n < 0 { // current read buffer is cut in two parts
		n = max - n
		// Can't read more than what we have in buffer
		if n > lenp { // read subset of read buffer
			n = lenp
			a := max - rp
			if a > n { // read only a subset of the first part of read buffer
				copy(p[:n], this.buffer[rp:rp+n]) // first part
			} else { // read the entire first part and a subset of second part
				copy(p[:a], this.buffer[rp:rp+a]) // first part
				a = n - a
				if a > 0 {
					copy(p[a:], this.buffer[:a]) // second part
				}
			}
		} else { // read the entire read buffer
			a := max - rp
			copy(p[:a], this.buffer[rp:rp+a]) // first part of read buffer
			copy(p[a:], this.buffer[:n-a])    // second part of read buffer
		}
	} else { // current read buffer is in only one part
		// Can't read more than what we have in buffer
		if n > lenp {
			n = lenp
		}
		// copy the readed data and move forward reading pointer
		n = copy(p[:n], this.buffer[rp:rp+n])
		this.readPos += n
	}
	this.readPos = (rp + n) % max
	return n, nil
}

// Write writes len(p) bytes from p to the underlying data stream.
// It returns the number of bytes written from p (0 <= n <= len(p)) and any error encountered that caused the write to stop early.
// Write returns a non-nil error if it returns n < len(p).
// Write does not modify the slice data.
//
// Implementations does not retain p.
func (this *RingBuffer) Write(p []byte) (n int, err error) {
	return
}
