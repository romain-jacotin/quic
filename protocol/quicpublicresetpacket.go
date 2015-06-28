package protocol

import "encoding/binary"
import "errors"

type QuicPublicResetPacket struct {
	msg            Message
	nonce          []byte
	rejectedSeqNum QuicPacketSequenceNumber
	buffer         [8]byte
}

// Erase
func (this *QuicPublicResetPacket) Erase() {
	this.msg.tags = nil
	this.msg.values = nil
	this.nonce = nil
	this.rejectedSeqNum = 0
}

// ParseData
func (this *QuicPublicResetPacket) ParseData(data []byte) (size int, err error) {
	// NOT YET IMPLEMENTED !
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetSerializedSize
func (this *QuicPublicResetPacket) GetSerializedSize() (size int) {
	// NOT YET IMPLEMENTED !
	return
}

// GetSerializedData
func (this *QuicPublicResetPacket) GetSerializedData(data []byte) (size int, err error) {
	this.msg.msgTag = TagPRST
	this.msg.AddTagValue(TagRNON, this.nonce)
	binary.LittleEndian.PutUint64(this.buffer[:], uint64(this.rejectedSeqNum))
	this.msg.AddTagValue(TagRSEQ, this.buffer[:])
	return
}

// GetNonce
func (this *QuicPublicResetPacket) GetNonce() []byte {
	return this.nonce
}

// SetNonce
func (this *QuicPublicResetPacket) SetNonce(nonce []byte) {
	this.nonce = nonce
}

// GetRejectedSequenceNumber
func (this *QuicPublicResetPacket) GetRejectedSequenceNumber() QuicPacketSequenceNumber {
	return this.rejectedSeqNum
}

// SetRejectedSequenceNumber
func (this *QuicPublicResetPacket) SetRejectedSequenceNumber(seqnum QuicPacketSequenceNumber) {
	this.rejectedSeqNum = seqnum
}
