package protocol

import "errors"

// RingBuffer implements io.Reader interface with an internal ring buffer.
// RingBuffer makes copy on Read(), but not on Write() where it returns a slice pointing to the ring buffer on Write call (it is not a io.Writer interface).
//
//
// It is safe to have only one Reader and only one concurrent Writer.
// But it is totally unsafe to use it as is with multiple readers or multiple writers without an external synchronization mechanism.
type RingBuffer struct {
	buffer      []byte
	size        int
	writeOffset uint64
	readOffset  uint64
	ch          chan int
}

// NewRingBuffer is a factory for RingBuffer, from various size in bytes.
func NewRingBuffer(size int) (error, *RingBuffer) {
	b := make([]byte, size, size)
	if len(b) != size {
		return errors.New("RingBuffer: Failed to allocated memory buffer"), nil
	}
	return nil, &RingBuffer{
		buffer: b,
		size:   size,
		ch:     make(chan int)}
}

// GetBufferSize returns the size of the buffer.
func (this *RingBuffer) GetBufferSize() int {
	return this.size
}

// CanRead returns the current number of bytes in the RingBuffer that can be reads.
func (this *RingBuffer) CanRead() int {
	return int(this.writeOffset - this.readOffset)
}

// CanWrite returns the current number of bytes in the RingBuffer that can be writes.
func (this *RingBuffer) CanWrite() int {
	return len(this.buffer) - int(this.writeOffset-this.readOffset)
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
	lenp := len(p)
	if lenp == 0 { // no data to read
		return
	}
	max := len(this.buffer)
	maxread := int(this.writeOffset - this.readOffset)
	if maxread == 0 {
		// buffer is empty
		return
	}
	// Can't read more than what we have in buffer
	if lenp > max {
		n = max
	} else {
		n = lenp
	}
	if n > maxread {
		n = maxread
	}
	// Translate to RingBuffer index
	rp := int(this.readOffset % uint64(max))
	// Copy from the ring buffer
	a := max - rp
	if a > 0 {
		if a > n {
			a = n
		}
		copy(p[:a], this.buffer[rp:rp+a]) // first part of write buffer
	}
	b := n - a
	if b > 0 {
		copy(p[a:], this.buffer[:b]) // second part of write buffer
	}
	this.readOffset += uint64(n)
	return n, nil
}

// Write writes len(p) bytes from p to the underlying data stream.
// It returns the number of bytes written from p (0 <= n <= len(p)) and any error encountered that caused the write to stop early.
// Write returns a non-nil error if it returns n < len(p).
// Write does not modify the slice data.
//
// Implementations does not retain p.
func (this *RingBuffer) Write(p []byte) (n int, err error) {
	lenp := len(p)
	if lenp == 0 { // no data to write
		return
	}
	max := len(this.buffer)
	maxwrite := max - int(this.writeOffset-this.readOffset)
	if maxwrite == 0 {
		// current buffer is full
		return maxwrite, nil
	}
	// Can't write more than what we have in buffer
	if lenp > max {
		n = max
	} else {
		n = lenp
	}
	if n > maxwrite {
		n = maxwrite
	}
	// Translate to RingBuffer index
	wp := int(this.writeOffset % uint64(max))
	// Copy to the ring buffer
	a := max - wp
	if a > 0 {
		if a > n {
			a = n
		}
		copy(this.buffer[wp:wp+a], p[:a]) // first part of write buffer
	}
	b := n - a
	if b > 0 {
		copy(this.buffer[:b], p[a:]) // second part of write buffer
	}
	this.writeOffset += uint64(n)
	return n, nil
}
