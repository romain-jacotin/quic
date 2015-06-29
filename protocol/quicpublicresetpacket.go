package protocol

import "encoding/binary"
import "errors"

/*

     0        1        2        3        4         8
+--------+--------+--------+--------+--------+--   --+
| Public |    Connection ID (64)                ...  | ->
|Flags(8)|                                           |
+--------+--------+--------+--------+--------+--   --+

     9       10       11        12       13      14
+--------+--------+--------+--------+--------+--------+---
|      Quic Tag (32)                |  Tag value map      ... ->
|         (PRST)                    |  (variable length)
+--------+--------+--------+--------+--------+--------+---


Public flags:
+---+---+---+---+---+---+---+---+
| 0 | 0 | SeqNum| ConnID|Rst|Ver|
+---+---+---+---+---+---+---+---+

*/

type QuicPublicResetNonceProof uint64

type QuicPublicResetPacket struct {
	msg            Message
	nonceProof     QuicPublicResetNonceProof
	rejectedSeqNum QuicPacketSequenceNumber
	buffer         [16]byte
}

// Erase
func (this *QuicPublicResetPacket) Erase() {
	this.msg.tags = nil
	this.msg.values = nil
	this.nonceProof = 0
	this.rejectedSeqNum = 0
}

// ParseData
func (this *QuicPublicResetPacket) ParseData(data []byte) (size int, err error) {
	var b bool
	var buffer []byte

	// Check minimum Public Reset packet size
	l := len(data)
	if l < (40) {
		err = errors.New("QuicPublicResetPacket.ParseData : data size too small to contain Public Reset packet")
		return
	}
	// Read uint32 message tag
	this.msg.msgTag = MessageTag(binary.LittleEndian.Uint32(data))
	size = 4
	if this.msg.msgTag != TagPRST {
		err = errors.New("QuicPublicResetPacket.ParseData : invalid Public Reset packet, PRST message tag required")
		return
	}
	// Read uint16 number of entries and ignore next uint16 of padding
	numEntries := uint16(binary.LittleEndian.Uint16(data[size:]))
	if numEntries < 2 {
		err = errors.New("QuicPublicResetPacket.ParseData : invalid Public Reset packet, RNON and RSEG tags required")
		return
	}
	if numEntries > MaxMessageTagNumEntries {
		err = errors.New("QuicPublicResetPacket.ParseData : invalid number of Tag entries in Public Reset packet (>128)")
		return
	}
	size = 8
	// Ask for next data size
	needMoreData := int(8*numEntries) + size
	if l < needMoreData {
		err = errors.New("QuicPublicResetPacket.ParseData : data size too small to contain Public Reset packet")
		return
	}
	// Allocate ressources for tag-offset pairs
	this.msg.tags = make([]MessageTag, numEntries)
	endOffsets := make([]uint32, numEntries)
	for i := 0; i < int(numEntries); i++ {
		// Read uint32 tag
		this.msg.tags[i] = MessageTag(binary.LittleEndian.Uint32(data[size:]))
		size += 4
		// Read uint32 offset
		endOffsets[i] = uint32(binary.LittleEndian.Uint32(data[size:]))
		size += 4
	}
	// Ask for next data size
	needMoreData += int(endOffsets[numEntries-1])
	if l < needMoreData {
		err = errors.New("QuicPublicResetPacket.ParseData : data size too small to contain Public Reset packet")
		return
	}
	// Allocate ressources for tag-value pairs
	this.msg.values = make([][]byte, numEntries)
	// Read values
	offset := 0
	for i := 0; i < int(numEntries); i++ {
		this.msg.values[i] = data[size+offset : uint32(size)+endOffsets[i]]
		offset = int(endOffsets[i])
	}
	size += offset
	// Do we have mandatory RNON tag/value pair ?
	if b, buffer = this.msg.ContainsTag(TagRNON); !b {
		err = errors.New("QuicPublicResetPacket.ParseData : invalid Public Reset packet, RNON tag required")
		return
	}
	// Parse Nonce Proof
	if len(buffer) != 8 {
		err = errors.New("QuicPublicResetPacket.ParseData : invalid Public Reset packet, invalid RNON value size (no 64bit value size)")
		return
	}
	this.nonceProof = QuicPublicResetNonceProof(binary.LittleEndian.Uint64(buffer))
	// Do we have mandatory RSEQ tag/value pair ?
	if b, buffer = this.msg.ContainsTag(TagRSEQ); !b {
		err = errors.New("QuicPublicResetPacket.ParseData : invalid Public Reset packet, RSEQ tag required")
		return
	}
	// Parse Rejected Sequence Number
	if len(buffer) != 8 {
		err = errors.New("QuicPublicResetPacket.ParseData : invalid Public Reset packet, invalid RSEQ value size (no 64bit value size)")
		return
	}
	this.rejectedSeqNum = QuicPacketSequenceNumber(binary.LittleEndian.Uint64(buffer))
	return
}

// GetSerializedSize
func (this *QuicPublicResetPacket) GetSerializedSize() (size int) {
	size = int(this.msg.GetSerializeSize())
	return
}

// GetSerializedData
func (this *QuicPublicResetPacket) GetSerializedData(data []byte) (size int, err error) {

	this.msg.msgTag = TagPRST
	// Add 'RNON' tag/value pair
	binary.LittleEndian.PutUint64(this.buffer[0:8], uint64(this.nonceProof))
	if b, _ := this.msg.ContainsTag(TagRNON); b {
		this.msg.UpdateTagValue(TagRNON, this.buffer[0:8])
	} else {
		this.msg.AddTagValue(TagRNON, this.buffer[0:8])
	}
	// Add 'RSEQ' tag/value pair
	binary.LittleEndian.PutUint64(this.buffer[8:16], uint64(this.rejectedSeqNum))
	if b, _ := this.msg.ContainsTag(TagRSEQ); b {
		this.msg.UpdateTagValue(TagRSEQ, this.buffer[8:16])
	} else {
		this.msg.AddTagValue(TagRSEQ, this.buffer[8:16])
	}
	size = int(this.msg.GetSerializeSize())
	if len(data) < size {
		err = errors.New("QuicPublicResetPacket.GetSerializedData : data size too small to contain Public Reset packet")
		size = 0
	}
	copy(data, this.msg.GetSerialize())
	return
}

// GetNonceProof
func (this *QuicPublicResetPacket) GetNonceProof() QuicPublicResetNonceProof {
	return this.nonceProof
}

// SetNonceProof
func (this *QuicPublicResetPacket) SetNonceProof(nonce QuicPublicResetNonceProof) {
	this.nonceProof = nonce
}

// GetRejectedSequenceNumber
func (this *QuicPublicResetPacket) GetRejectedSequenceNumber() QuicPacketSequenceNumber {
	return this.rejectedSeqNum
}

// SetRejectedSequenceNumber
func (this *QuicPublicResetPacket) SetRejectedSequenceNumber(seqnum QuicPacketSequenceNumber) {
	this.rejectedSeqNum = seqnum
}
