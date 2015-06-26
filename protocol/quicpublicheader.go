package protocol

import "errors"

const (
	// Flag for Connection ID size in QuicPublicHeader
	QUICFLAG_CONNID_64bit = 0x0C
	QUICFLAG_CONNID_32bit = 0x08
	QUICFLAG_CONNID_8bit  = 0x04
	QUICFLAG_CONNID_0bit  = 0x00
	// Flag for Sequence Number size in QuicPublicHeader
	QUICFLAG_SEQNUM_48bit = 0x30
	QUICFLAG_SEQNUM_32bit = 0x20
	QUICFLAG_SEQNUM_16bit = 0x10
	QUICFLAG_SEQNUM_8bit  = 0x00
)

// Public Header field types
type QuicVersion uint32
type QuicConnectionID uint64
type QuicPacketSequenceNumber uint64

// QuicPublicHeader
type QuicPublicHeader struct {
	// Public flags
	flagVersion     bool
	flagPublicReset bool
	connIDByteSize  int
	seqNumByteSize  int
	// Public Fields
	connId  QuicConnectionID
	version QuicVersion
	seqNum  QuicPacketSequenceNumber
}

// ParseData
func (this *QuicPublicHeader) ParseData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetSerializedSize
func (this *QuicPublicHeader) GetSerializedSize() (size int) {
	return
}

// GetSerializedData
func (this *QuicPublicHeader) GetSerializedData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// HasVersion
func (this *QuicPublicHeader) HasVersion() bool {
	return this.flagVersion
}

// GetVersion
func (this *QuicPublicHeader) GetVersion() QuicVersion {
	return this.version
}

// SetVersion
func (this *QuicPublicHeader) SetVersion(version QuicVersion) {
	this.version = version
}

// GetPublicResetFlag
func (this *QuicPublicHeader) GetPublicResetFlag() bool {
	return this.flagPublicReset
}

// SetPublicResetFlag
func (this *QuicPublicHeader) SetPublicResetFlag(state bool) {
	this.flagPublicReset = state
}

// GetConnectionID
func (this *QuicPublicHeader) GetConnectionID() QuicConnectionID {
	return this.connId
}

// SetConnectionID
func (this *QuicPublicHeader) SetConnectionID(connID QuicConnectionID) {
	this.connId = connID
}
