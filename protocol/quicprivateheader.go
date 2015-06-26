package protocol

import "errors"

// QuicPrivateHeader
type QuicPrivateHeader struct {
	flagFec bool
}

// ParseData
func (this *QuicPrivateHeader) ParseData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetSerializedSize
func (this *QuicPrivateHeader) GetSerializedSize() (size int) {
	return
}

// GetSerializedData
func (this *QuicPrivateHeader) GetSerializedData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetFecFlag
func (this *QuicPrivateHeader) GetFecFlag() bool {
	return this.flagFec
}

// SetFecFlag
func (this *QuicPrivateHeader) SetFecFlag(fecFlag bool) {
	this.flagFec = fecFlag
	return
}
