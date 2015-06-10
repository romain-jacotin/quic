package protocol

import "testing"
import "bytes"

func TestRingBuffer(t *testing.T) {
	var n int
	readData := make([]byte, 52)
	writeData := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	// Create a RingBuffer
	err, rb := NewRingBuffer(6)
	if err != nil {
		t.Error(err)
	}

	// Check initial RingBuffer values
	n = rb.GetBufferSize()
	if n != 6 {
		t.Errorf("Bad GetBufferSize value : %v", n)
	}

	n = rb.CanRead()
	if n != 0 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 6 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Write 2 bytes and check RingBuffer values
	n, _ = rb.Write(writeData[:2])
	if n != 2 {
		t.Errorf("Bad Write value = %v", n)
	}

	n = rb.CanRead()
	if n != 2 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 4 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Read only 2 bytes out of 4
	n, _ = rb.Read(readData[0:4])
	if n != 2 {
		t.Errorf("Bad Read value = %v", n)
	}

	n = rb.CanRead()
	if n != 0 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 6 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Write 4 bytes
	n, _ = rb.Write(writeData[2:6])
	if n != 4 {
		t.Errorf("Bad Write value = %v", n)
	}

	n = rb.CanRead()
	if n != 4 {
		t.Errorf("Bad CanRead value = %v", n)
	}
	n = rb.CanWrite()
	if n != 2 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Read 4 writes
	n, _ = rb.Read(readData[2:6])
	if n != 4 {
		t.Errorf("Bad Read value = %v", n)
	}

	n = rb.CanRead()
	if n != 0 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 6 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Write 4 bytes
	n, _ = rb.Write(writeData[6:10])
	if n != 4 {
		t.Errorf("Bad Write value = %v", n)
	}

	n = rb.CanRead()
	if n != 4 {
		t.Errorf("Bad CanRead value = %v", n)
	}
	n = rb.CanWrite()
	if n != 2 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Read 4 bytes
	n, _ = rb.Read(readData[6:10])
	if n != 4 {
		t.Errorf("Bad Read value = %v", n)
	}

	n = rb.CanRead()
	if n != 0 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 6 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Write 4 bytes
	n, _ = rb.Write(writeData[10:14])
	if n != 4 {
		t.Errorf("Bad Write value = %v", n)
	}

	n = rb.CanRead()
	if n != 4 {
		t.Errorf("Bad CanRead value = %v", n)
	}
	n = rb.CanWrite()
	if n != 2 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Read 4 bytes
	n, _ = rb.Read(readData[10:14])
	if n != 4 {
		t.Errorf("Bad Read value = %v", n)
	}

	n = rb.CanRead()
	if n != 0 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 6 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Write 5 bytes
	n, _ = rb.Write(writeData[14:19])
	if n != 5 {
		t.Errorf("Bad Write value = %v", n)
	}

	n = rb.CanRead()
	if n != 5 {
		t.Errorf("Bad CanRead value = %v", n)
	}
	n = rb.CanWrite()
	if n != 1 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Read 4 bytes
	n, _ = rb.Read(readData[14:18])
	if n != 4 {
		t.Errorf("Bad Read value = %v", n)
	}

	n = rb.CanRead()
	if n != 1 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 5 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Write 5 bytes over 6
	n, _ = rb.Write(writeData[19:25])
	if n != 5 {
		t.Errorf("Bad Write value = %v", n)
	}

	n = rb.CanRead()
	if n != 6 {
		t.Errorf("Bad CanRead value = %v", n)
	}
	n = rb.CanWrite()
	if n != 0 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Read 6 bytes
	n, _ = rb.Read(readData[18:24])
	if n != 6 {
		t.Errorf("Bad Read value = %v", n)
	}

	n = rb.CanRead()
	if n != 0 {
		t.Errorf("Bad CanRead value = %v", n)
	}

	n = rb.CanWrite()
	if n != 6 {
		t.Errorf("Bad CanWrite value = %v", n)
	}

	// Verify
	if !bytes.Equal(readData[:24], writeData[:24]) {
		t.Errorf("Read data %v different from Write data %v", string(readData[:24]), string(writeData[:24]))
	}
}
