package protocol

import "errors"

type QuicPublicResetPacket struct {
}

// ParseData
func (this *QuicPublicResetPacket) ParseData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetSerializedSize
func (this *QuicPublicResetPacket) GetSerializedSize() (size int) {
	return
}

// GetSerializedData
func (this *QuicPublicResetPacket) GetSerializedData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}
