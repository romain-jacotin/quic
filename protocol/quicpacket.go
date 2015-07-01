package protocol

import "errors"
import "encoding/binary"

const cFRAMEBUFFERSIZE = 4

const (
	QUICPACKETTYPE_UNKNOW         = 0
	QUICPACKETTYPE_PUBLICRESET    = 1
	QUICPACKETTYPE_VERSION        = 2
	QUICPACKETTYPE_FEC            = 3
	QUICPACKETTYPE_FRAME          = 4
	QUICPACKETTYPE_PROTECTEDFRAME = 5
)

type QuicPacketType int

// QuicPacket
type QuicPacket struct {
	packetType    QuicPacketType
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
	this.packetType = QUICPACKETTYPE_UNKNOW
	this.framesSet = nil
	for i, _ := range this.buffer {
		this.buffer[i] = 0
	}
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
		// This is a Public Reset packet type
		this.packetType = QUICPACKETTYPE_PUBLICRESET
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
			// This is a FEC packet type
			this.packetType = QUICPACKETTYPE_FEC
			// Setup the FEC Packet based on Sequence Number and FEC Group Offset
			if fecgroupnum, err = this.privateHeader.GetFecGroupNumberOffset(); err != nil {
				return
			}
			this.fecPacket.Setup(this.publicHeader.GetSequenceNumber(), fecgroupnum)
			// Parse Fec redundancy payload
			if s, err = this.fecPacket.ParseData(data[size:]); err != nil {
				// Error while parsing QuicFECPacket
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
	switch this.packetType {
	case QUICPACKETTYPE_PUBLICRESET:
		size = 9 + this.publicReset.GetSerializedSize()
		return
	case QUICPACKETTYPE_VERSION, QUICPACKETTYPE_FRAME, QUICPACKETTYPE_PROTECTEDFRAME:
		size = this.publicHeader.GetSerializedSize() + this.privateHeader.GetSerializedSize() // + this.framesSet.GetSerializedSize()
		return
	case QUICPACKETTYPE_FEC:
		size = this.publicHeader.GetSerializedSize() + this.publicReset.GetSerializedSize()
		return
	}
	return
}

// GetSerializedData
func (this *QuicPacket) GetSerializedData() (data []byte, err error) {
	var s, size int

	switch this.packetType {
	case QUICPACKETTYPE_PUBLICRESET:
		// Serialize public flags
		this.buffer[0] = QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit
		// Serialize Connection ID (64-bit)
		binary.LittleEndian.PutUint64(this.buffer[1:], uint64(this.publicHeader.connId))
		size, err = this.publicReset.GetSerializedData(this.buffer[9:])
		data = this.buffer[:size+9]
		return
	case QUICPACKETTYPE_VERSION, QUICPACKETTYPE_FRAME, QUICPACKETTYPE_PROTECTEDFRAME:
		size = this.publicHeader.GetSerializedSize() + this.privateHeader.GetSerializedSize() // + this.framesSet.GetSerializedSize()
		data = this.buffer[:size]
		return
	case QUICPACKETTYPE_FEC:
		if size, err = this.publicHeader.GetSerializedData(this.buffer[:]); err != nil {
			return
		}
		if s, err = this.privateHeader.GetSerializedData(this.buffer[size:]); err != nil {
			return
		}
		size += s
		if s, err = this.fecPacket.GetSerializedData(this.buffer[size:]); err != nil {
			return
		}
		size += s
		data = this.buffer[:size]
		return
	}
	err = errors.New("QuicPacket.GetSerializedData : can't serialized unknown packet type")
	return
}

// GetPacketType
func (this *QuicPacket) GetPacketType() (packettype QuicPacketType) {
	return this.packetType
}

// SetPacketType
func (this *QuicPacket) SetPacketType(packettype QuicPacketType) {
	this.packetType = packettype
}
