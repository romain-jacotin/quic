package protocol

import "errors"

// QuicPacket
type QuicPacket struct {
	publicHeader  QuicPublicHeader
	privateHeader QuicPrivateHeader
	// If FEC Packet only
	fecRedundancy []byte
	// If PublicResetPacket only
	publicReset QuicPublicResetPacket
	buffer      [1500]byte
}

// ParseData
func (this *QuicPacket) ParseData(data []byte) (size int, err error) {
	var s int

	// Parse QuicPublicHeader
	if s, err = this.publicHeader.ParseData(data); err != nil {
		// Error while parsing QuicPublicHeader
		return
	}
	size += s
	if this.publicHeader.GetPublicResetFlag() {
		// Parse PublicResetPacket
		if s, err = this.publicReset.ParseData(data[s:]); err != nil {
			// Error while parsing QuiPublicResetPacket
			return
		}
		size += s
	} else {
		// Parse QuicPrivateHeader
		if s, err = this.privateHeader.ParseData(data); err != nil {
			// Error while parsing QuicPrivateHeader
			return
		}
		size += s
		if this.privateHeader.GetFecFlag() {
			// Parse Fec redundancy payload
			this.fecRedundancy = data[s:]
			size += len(this.fecRedundancy)
		} else {
			// Parse Frames vector

		}
	}
	if size != len(data) {
		err = errors.New("QuicPacket.ParseData : internal error parsed bytes count different from data size")
	}
	return
}

// GetSerializedDataSize
func (this *QuicPacket) GetSerializedDataSize() (size int) {
	return
}

// GetSerializedData
func (this *QuicPacket) GetSerializedData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}
