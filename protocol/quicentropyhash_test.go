package protocol

import "testing"
import "fmt"

func Test_GetEntropyHash(t *testing.T) {
	var seqnum QuicPacketSequenceNumber
	var entropy bool
	var hash QuicEntropyHash
	var err error

	rb, s := NewEntropyHashRingBuffer()
	fmt.Printf("Size = %v\n", s)
	entropy = true
	for i := 0; i < (65536 * 8); i++ {
		if seqnum, err = rb.GetNewPacket(entropy); err != nil {
			t.Errorf("GetNewPacket : error %v", err)
			return
		}
		fmt.Printf("get bit [%v] = %v (%v expected)\n", seqnum, rb.getEntropy(seqnum), entropy)
		if hash, err = rb.GetEntropyHash(seqnum); err != nil {
			t.Errorf("GetEntropyHash : error %v", err)
			return
		}
		fmt.Printf("get hash[%v] = %x\n", seqnum, hash)
	}
	for i := range rb.hashes {
		if rb.hashes[i] != 0xff {
			t.Error("bad hashes initialization with GetNewPacket")
			return
		}
	}
}
