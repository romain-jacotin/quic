package protocol

import "errors"

// RingBuffer implements io.Reader interface with an internal ring buffer.
// RingBuffer makes copy on Read(), but not on Write() where it returns a slice pointing to the ring buffer on Write call (it is not a io.Writer interface).
//
//
// It is safe to have only one Reader and only one concurrent Writer.
// But it is totally unsafe to use it as is with multiple readers or multiple writers without an external synchronization mechanism.
type RingBuffer struct {
	buffer   []byte
	size     int
	writePos int
	readPos  int
}

// NewRingBuffer is a factory for RingBuffer, from various size in bytes.
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
	rp := this.readPos
	wp := this.writePos
	n = rp - wp
	if n == 0 {
		// current read buffer is full
		return
	}
	lenp := len(p)
	max := len(this.buffer)
	if n < 0 { // current write buffer is cut in two parts
		n = max - n
		// Can't write more than what we have in buffer
		if n > lenp { // write subset of write buffer
			n = lenp
			a := max - wp
			if a > n { // write only a subset of the first part of write buffer
				copy(this.buffer[wp:wp+n], p[:n]) // first part
			} else { // write the entire first part and a subset of second part
				copy(this.buffer[wp:wp+a], p[:a]) // first part
				a = n - a
				if a > 0 {
					copy(this.buffer[:a], p[a:]) // second part
				}
			}
		} else { // write the entire read buffer
			a := max - wp
			copy(this.buffer[wp:wp+a], p[:a]) // first part of write buffer
			copy(this.buffer[:n-a], p[a:])    // second part of write buffer
		}
	} else { // current write buffer is in only one part
		// Can't write more than what we have in buffer
		if n > lenp {
			n = lenp
		}
		// copy the readed data and move forward reading pointer
		n = copy(this.buffer[wp:wp+n], p[:n])
		this.writePos += n
	}
	this.writePos = (wp + n) % max
	return n, nil
}
