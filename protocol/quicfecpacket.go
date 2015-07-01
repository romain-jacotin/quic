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
	size = len(data)
	if size > 0 {
		this.redundancy = data
	} else {
		size = 0
		err = errors.New("QuicFECPacket.ParseData : invalid FEC Redundancy data of size = 0")
	}
	return
}

// GetSerializedSize
func (this *QuicFECPacket) GetSerializedSize() (size int) {
	return len(this.redundancy)
}

// GetSerializedData
func (this *QuicFECPacket) GetSerializedData(data []byte) (size int, err error) {
	if len(this.redundancy) == 0 {
		err = errors.New("QuicFECPacket.GetSerializedData : invalid FEC Redundancy data of size = 0")
		return
	}
	if len(data) < len(this.redundancy) {
		err = errors.New("QuicFECPacket.GetSerializedData : data size too small to contain FEC Packet redundancy")
		return
	}
	size = copy(data, this.redundancy)
	return
}

// SetRedundancyData
func (this *QuicFECPacket) SetRedundancyData(data []byte) {
	this.redundancy = data
}

// GetRedundancyData
func (this *QuicFECPacket) GetRedundancyData() (data []byte) {
	data = this.redundancy
	return
}
