package protocol

import "errors"

// QuicFECPacket
type QuicFECPacket struct {
	seqNum     QuicPacketSequenceNumber
	offset     QuicFecGroupNumberOffset
	redundancy []byte
}

// Erase
func (this *QuicFECPacket) Erase() {
	this.seqNum = 0
	this.offset = 0
	this.redundancy = nil
}

// Setup
func (this *QuicFECPacket) Setup(seqnum QuicPacketSequenceNumber, offset QuicFecGroupNumberOffset) {
	this.seqNum = seqnum - QuicPacketSequenceNumber(offset)
	this.offset = offset
}

// ParseData
func (this *QuicFECPacket) ParseData(data []byte) (size int, err error) {
	// All left data is the redundancy FEC Packet of the associated FEC Group
	this.redundancy = data
	size = len(data)
	return
}

// GetSerializedSize
func (this *QuicFECPacket) GetSerializedSize() (size int) {
	return len(this.redundancy)
}

// GetSerializedData
func (this *QuicFECPacket) GetSerializedData(data []byte) (size int, err error) {
	if len(data) < len(this.redundancy) {
		err = errors.New("QuicFECPacket.GetSerializedData : data size too small to contain FEC Packet redundancy")
		return
	}
	size = copy(data, this.redundancy)
	return
}
