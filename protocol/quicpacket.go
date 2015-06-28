package protocol

import "errors"

const cFRAMEBUFFERSIZE = 4

// QuicPacket
type QuicPacket struct {
	publicHeader  QuicPublicHeader
	privateHeader QuicPrivateHeader
	// If FEC Packet only
	fecPacket QuicFECPacket
	// If PublicResetPacket only
	publicReset QuicPublicResetPacket
	// If Frames Packet only
	framesSet []QuicFrame // framesSet uses frameBuffer array for the first cFRAMEBUFFERSIZE frames and after need making bigger slices
	// internal buffers
	buffer      [1472]byte                  // internal buffer to store serialized QUIC Packet at reception or before encryption and transmit
	frameBuffer [cFRAMEBUFFERSIZE]QuicFrame // array used by framesSet for the first cFRAMEBUFFERSIZE frames only
}

// Erase
func (this *QuicPacket) Erase() {
	this.publicHeader.Erase()
	this.privateHeader.Erase()
	this.fecPacket.Erase()
	this.publicReset.Erase()
	this.framesSet = nil
}

// ParseData
func (this *QuicPacket) ParseData(data []byte) (size int, err error) {
	var s int
	var fecgroupnum QuicFecGroupNumberOffset

	l := len(data)
	// Parse QuicPublicHeader
	if s, err = this.publicHeader.ParseData(data); err != nil {
		// Error while parsing QuicPublicHeader
		return
	}
	size += s
	if this.publicHeader.GetPublicResetFlag() {
		// Parse PublicResetPacket
		if s, err = this.publicReset.ParseData(data[size:]); err != nil {
			// Error while parsing QuiPublicResetPacket
			return
		}
		size += s
	} else {
		// Parse QuicPrivateHeader
		if s, err = this.privateHeader.ParseData(data[size:]); err != nil {
			// Error while parsing QuicPrivateHeader
			return
		}
		size += s
		if this.privateHeader.GetFecPacketFlag() {
			// Setup the FEC Packet based on Sequence Number and FEC Group Offset
			if fecgroupnum, err = this.privateHeader.GetFecGroupNumberOffset(); err != nil {
				return
			}
			this.fecPacket.Setup(this.publicHeader.GetSequenceNumber(), fecgroupnum)
			// Parse Fec redundancy payload
			if s, err = this.fecPacket.ParseData(data[size:]); err != nil {
				// Error while parsing QuicPrivateHeader
				return
			}
			size += s
		} else {
			// Parse Frames vector
			i := 0
			for left := l - size; left > 0; i++ {
				if i == 0 { // initialize the frames set to use frameBuffer array
					this.framesSet = this.frameBuffer[:1]
				} else if (i % cFRAMEBUFFERSIZE) > 0 { // grow the frame set by using existing slice capacity (+1)
					this.framesSet = this.framesSet[:i]
				} else { // grow the frame set with make (+ccFRAMEBUFFERSIZE) and copy
					fs := make([]QuicFrame, i, ((i/cFRAMEBUFFERSIZE)+1)*cFRAMEBUFFERSIZE)
					copy(fs, this.framesSet)
				}
				// Parse next QuicFrame
				if s, err = this.framesSet[i].ParseData(data[size:]); err != nil {
					return
				}
				size += s
				left -= s
			}
		}
	}
	if size != l {
		err = errors.New("QuicPacket.ParseData : internal error parsed bytes count different from data size") // Must be impossible
	}
	return
}

// GetSerializedSize
func (this *QuicPacket) GetSerializedSize() (size int) {
	// NOT YET IMPLEMENTED
	return
}

// GetSerializedData
func (this *QuicPacket) GetSerializedData() (data []byte, err error) {
	data = this.buffer[:this.GetSerializedSize()]
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}
