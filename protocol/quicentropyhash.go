package protocol

import "errors"

const MAXIMUM_ENTROPY_CONSECUTIVE_SEQNUM = 0x80000 // = 524288

type QuicEntropyHash byte

type EntropyHashRingBuffer struct {
	largestKnownSeqNum      QuicPacketSequenceNumber // start of ring (=read)
	largestKnownEntropyHash QuicEntropyHash          // Cumulative entropy hash since first packet
	nextSeqNum              QuicPacketSequenceNumber // end of ring (=write)
	hashes                  [0x10000]byte            // = 65536 bytes
}

// NewEntropyHashRingBuffer is a factory that returns an EntropyHashRingBuffer and its associated size.
// The size of the EntropyHashRingBuffer represents the total number of consecutive packet sequence number for which entropy bits can be stored.
// Ring buffer left capacity is decreasing each time 'GetNewPacket()' is called.
// Ring buffer left capacity is increasing each time 'SetLargestKnownPacket()' is called.
// It is possible to generate and manage 2^46 packets sequence number and associated entropy bit,
// but the current limitation is that there must be no more than MAXIMUM_ENTROPY_CONSECUTIVE_SEQNUM packets in flight.
// At this time, MAXIMUM_ENTROPY_CONSECUTIVE_SEQNUM = 524.288 consecutive sequence numbers with a memory footprint of only 64KB,
// if considering a conservative mean stream frame size of 512 bytes, then a theoretical maximum congestion window of 268.435.456 bytes can be managed.
func NewEntropyHashRingBuffer() (entropymanager *EntropyHashRingBuffer, size int) {
	entropymanager = &EntropyHashRingBuffer{largestKnownSeqNum: 1, nextSeqNum: 1}
	size = MAXIMUM_ENTROPY_CONSECUTIVE_SEQNUM
	return
}

// getEntropy returns the entropy bit status for a given Sequence Number.
// Note: no boundary check is make on the sequence number: for debugging and 'go test' purpose only.
func (this *EntropyHashRingBuffer) getEntropy(seqnum QuicPacketSequenceNumber) bool {
	if QuicEntropyHash(this.hashes[(seqnum>>3)&0xffff]&(1<<(seqnum&0x7))) == 0 {
		return false
	}
	return true
}

// setEntropy sets the entropy bit status for a given Sequence Number.
// Note: no boundary check is make on the sequence number: for debugging and 'go test' purpose only.
func (this *EntropyHashRingBuffer) setEntropy(seqnum QuicPacketSequenceNumber, entropy bool) {
	if entropy {
		this.hashes[(seqnum>>3)&0xffff] |= (1 << (seqnum & 0x7))
	} else {
		this.hashes[(seqnum>>3)&0xffff] &= (0xff ^ (1 << (seqnum & 0x7)))
	}
	return
}

// GetEntropyHash returns the non cumulative entropy hash for the requested sequence number.
// Example : if packet 42 as entropy flag set, then GetEntropyHash(42) returns the absolute hash value 0x04
func (this *EntropyHashRingBuffer) GetEntropyHash(seqnum QuicPacketSequenceNumber) (hash QuicEntropyHash, err error) {
	if (seqnum >= this.nextSeqNum) || (seqnum < this.largestKnownSeqNum) {
		err = errors.New("EntropyHashRingBuffer.GetEntropyHash : invalid Packet Sequence Number")
		return
	}
	hash = QuicEntropyHash(this.hashes[(seqnum>>3)&0xffff] & (1 << (seqnum & 0x7)))
	return
}

// GetCumulativeEntropyHash returns the cumulative entropy hash for the requested sequence number since the very first packet.
func (this *EntropyHashRingBuffer) GetCumulativeEntropyHash(seqnum QuicPacketSequenceNumber) (hash QuicEntropyHash, err error) {
	if (seqnum < this.largestKnownSeqNum) || (seqnum >= this.nextSeqNum) {
		err = errors.New("EntropyHashRingBuffer.GetCumulativeEntropyHash : invalid Packet Sequence Number")
	}
	hash = this.largestKnownEntropyHash
	if seqnum > this.largestKnownSeqNum {
		for i := this.largestKnownSeqNum; i < seqnum; i++ {
			hash ^= QuicEntropyHash(this.hashes[(i>>3)&0xffff] & (1 << (i & 0x7)))
		}
	}
	return
}

// GetCumulativeEntropyHashFromTo returns the cumulative entropy hash 'from' a starting sequence number 'to' a ending sequence number,
// and returns an error if the given sequence numbers are out of scope of the ring buffer.
// Note that the 'from' sequence number must be less than or equal to the 'to' sequence number.
func (this *EntropyHashRingBuffer) GetCumulativeEntropyHashFromTo(from, to QuicPacketSequenceNumber) (hash QuicEntropyHash, err error) {
	if (from > to) || (from < this.largestKnownSeqNum) || (to >= this.nextSeqNum) {
		err = errors.New("EntropyHashRingBuffer.GetCumulativeEntropyHashFromTo : invalid 'from' and 'to' Packet Sequence Number")
	}
	hash = QuicEntropyHash(this.hashes[(from>>3)&0xffff] & (1 << (from & 0x7)))
	for i := from; i <= to; i++ {
		hash ^= QuicEntropyHash(this.hashes[(i>>3)&0xffff] & (1 << (i & 0x7)))
	}
	return
}

// GetNewPacket returns a monotonic increasing packet sequence number for which the given entropy bit is stored in the ring buffer.
// GetNewPacket is typically called for creating/sending a new QUIC packet.
func (this *EntropyHashRingBuffer) GetNewPacket(entropy bool) (seqnum QuicPacketSequenceNumber, err error) {
	// Check if ring buffer is full
	if int(this.nextSeqNum-this.largestKnownSeqNum) >= MAXIMUM_ENTROPY_CONSECUTIVE_SEQNUM {
		err = errors.New("EntropyHashRingBuffer.GetNewPacket : ring buffer full, can't store new packet entropy")
		return
	}
	seqnum = this.nextSeqNum
	if entropy {
		// Set the correct bit in the correct byte of the ring buffer
		this.hashes[(seqnum>>3)&0xffff] |= (1 << (seqnum & 0x7))
	} else {
		// Clear the correct bit in the correct byte of the ring buffer
		this.hashes[(seqnum>>3)&0xffff] &= (0xff ^ (1 << (seqnum & 0x7)))
	}
	this.nextSeqNum++
	return
}

// SetLargestKnownPacket removes the begining hashes from the ring buffer up to and including the given Sequence Number,
// it returns the cumulative entropy hash for this new largest known sequence number and an error if the given sequence number is out of scope of the ring buffer.
func (this *EntropyHashRingBuffer) SetLargestKnownPacket(seqnum QuicPacketSequenceNumber) (hash QuicEntropyHash, err error) {
	// Check sequence number validity towards current bounds of the ring buffer
	if (seqnum < this.largestKnownSeqNum) || (seqnum >= this.nextSeqNum) {
		err = errors.New("EntropyHashRingBuffer.SetLargestKnownPacket : invalid Packet Sequence Number")
	}
	// Compute and return the hash for this new largest known sequence number
	hash = this.largestKnownEntropyHash
	if seqnum > this.largestKnownSeqNum {
		for i := this.largestKnownSeqNum; i < seqnum; i++ {
			hash ^= QuicEntropyHash(this.hashes[(i>>3)&0xffff] & (1 << (i & 0x7)))
		}
		// Update Largest Known Entropy Hash
		this.largestKnownEntropyHash = hash
		// Update Largest Known Sequence Number
		this.largestKnownSeqNum = seqnum
	}
	return
}
