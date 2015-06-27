package protocol

import "errors"

// QuicFECPacket
type QuicFECPacket struct {
	redundancy []byte
}

// ParseData
func (this *QuicFECPacket) ParseData(data []byte) (size int, err error) {
	this.redundancy = data
	size = len(data)
	return
}

// GetSerializedSize
func (this *QuicFECPacket) GetSerializedSize() (size int) {
	return
}

// GetSerializedData
func (this *QuicFECPacket) GetSerializedData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}
