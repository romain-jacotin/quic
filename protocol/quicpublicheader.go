package protocol

import "errors"
import "encoding/binary"

/*

     0        1        2        3        4            8
+--------+--------+--------+--------+--------+---    ---+
| Public |    Connection ID (0, 8, 32, or 64)    ...    | ->
|Flags(8)|      (variable length)                       |
+--------+--------+--------+--------+--------+---    ---+

     9       10       11        12
+--------+--------+--------+--------+
|      Quic Version (32)            | ->
|         (optional)                |
+--------+--------+--------+--------+

    13      14       15        16        17       18       19       20
+--------+--------+--------+--------+--------+--------+--------+--------+
|         Sequence Number (8, 16, 32, or 48)          |Private | FEC (8)|
|                         (variable length)           |Flags(8)|  (opt) |
+--------+--------+--------+--------+--------+--------+--------+--------+


Public flags:
+---+---+---+---+---+---+---+---+
| 0 | 0 | SeqNum| ConnID|Rst|Ver|
+---+---+---+---+---+---+---+---+

FLAGS    SeqNum size  ConnID size

00 00    1            0
00 01    1            1
00 10    1            4
00 11    1            8
01 00    2            0
01 01    2            1
01 10    2            4
01 11    2            8
10 00    4            0
10 01    4            1
10 10    4            4
10 11    4            8
11 00    6            0
11 01    6            1
11 10    6            4
11 11    6            8

*/

var parsePublicheaderConnectionIdSize = []int{0, 1, 4, 8, 0, 1, 4, 8, 0, 1, 4, 8, 0, 1, 4, 8}
var parsePublicheaderSequenceNumberSize = []int{1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 6, 6, 6, 6}

const (
	// Mask and flag for Version in QuicPublicHeader
	QUICFLAG_VERSION = 0x01
	// Mask and flag for Public reset in QuicPublicHeader
	QUICFLAG_PUBLICRESET = 0x02
	// Mask and flags for Connection ID size in QuicPublicHeader
	QUICMASK_CONNID_SIZE  = 0x0C
	QUICFLAG_CONNID_64bit = 0x0C
	QUICFLAG_CONNID_32bit = 0x08
	QUICFLAG_CONNID_8bit  = 0x04
	QUICFLAG_CONNID_0bit  = 0x00
	// Mask and flags for Sequence Number size in QuicPublicHeader
	QUICMASK_SEQNUM_SIZE  = 0x30
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

// Erase
func (this *QuicPublicHeader) Erase() {
	this.flagVersion = false
	this.flagPublicReset = false
	this.connIDByteSize = 0
	this.connId = 0
	this.version = 0
	this.seqNumByteSize = 0
	this.seqNum = 0
}

// ParseData
func (this *QuicPublicHeader) ParseData(data []byte) (size int, err error) {
	// Check minimum Public Header size
	l := len(data)
	if l < 2 {
		err = errors.New("QuicPublicHeader.ParseData : too little data (< 2 bytes)")
		return
	}
	// Parse public flags
	pf := data[0]
	// Parse unused bits
	if (pf & 0xc0) != 0 {
		err = errors.New("QuicPublicHeader.ParseData : unused bits must be set to 0")
		return
	}
	// Parse Public reset flag
	if (pf & QUICFLAG_PUBLICRESET) == QUICFLAG_PUBLICRESET {
		this.flagPublicReset = true
		// Check  minimum Public header size for 64-bit Connection ID
		if l < 9 {
			err = errors.New("QuicPublicHeader.ParseData : too little data for Public Reset (< 9 bytes)")
			return
		}
		// Parse the 64-bit Connection ID
		this.connIDByteSize = 8
		this.connId = QuicConnectionID(binary.LittleEndian.Uint64(data[1:]))
		size = 9
		return
	} else {
		this.flagPublicReset = false
	}
	// Parse version flag
	if (pf & QUICFLAG_VERSION) == QUICFLAG_VERSION {
		this.flagVersion = true
	} else {
		this.flagVersion = false
	}
	// Parse Connection ID size in bytes
	pf = (pf >> 2) & 0x0f
	this.connIDByteSize = parsePublicheaderConnectionIdSize[pf]
	// Parse Sequence Number size in bytes
	this.seqNumByteSize = parsePublicheaderSequenceNumberSize[pf]
	// Check minimum data left based on theoric Public Header size
	s := (1 + this.connIDByteSize + this.seqNumByteSize)
	if this.flagVersion {
		s += 4
	}
	if l < s {
		err = errors.New("QuicPublicHeader.ParseData : too little data left based on public flags")
		return
	}
	// Parse Connection ID
	size = 1
	switch this.connIDByteSize {
	case 0:
		this.connId = 0
		break
	case 1:
		this.connId = QuicConnectionID(data[size])
		break
	case 4:
		this.connId = QuicConnectionID(binary.LittleEndian.Uint32(data[size:]))
		break
	case 8:
		this.connId = QuicConnectionID(binary.LittleEndian.Uint64(data[size:]))
		break
	}
	size += this.connIDByteSize
	// Parse QUIC version if needed
	if this.flagVersion {
		this.version = QuicVersion(binary.LittleEndian.Uint32(data[size:]))
		size += 4
	}
	// Parse Sequence Number
	switch this.seqNumByteSize {
	case 1:
		this.seqNum = QuicPacketSequenceNumber(data[size])
		break
	case 2:
		this.seqNum = QuicPacketSequenceNumber(binary.LittleEndian.Uint16(data[size:]))
		break
	case 4:
		this.seqNum = QuicPacketSequenceNumber(binary.LittleEndian.Uint32(data[size:]))
		break
	case 6:
		this.seqNum = QuicPacketSequenceNumber(binary.LittleEndian.Uint32(data[size:])) +
			(QuicPacketSequenceNumber(binary.LittleEndian.Uint16(data[size+4:])) << 32)
		break
	}
	size += this.seqNumByteSize
	if size != s { // This test should be removed at first official release 1.0
		err = errors.New("QuicPublicHeader.ParseData : internal error parsed bytes count different from calculated size") // Must be impossible
	}
	return
}

// GetSerializedSize
func (this *QuicPublicHeader) GetSerializedSize() (size int) {
	size = (1 + this.connIDByteSize + this.seqNumByteSize)
	if this.flagVersion {
		size += 4
	}
	return
}

// GetSerializedData
func (this *QuicPublicHeader) GetSerializedData(data []byte) (size int, err error) {
	var pf byte

	// Serialize Public Reset public header
	if this.flagPublicReset {
		if len(data) < 9 {
			err = errors.New("QuicPublicHeader.GetSerializedData : data size too small to contain Public Reset packet")
			return
		}
		// Serialize Public flags
		data[0] = QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit
		// Serialize Connection ID
		binary.LittleEndian.PutUint64(data[1:], uint64(this.connId))
		size = 9
		return
	}
	// Check minimum data size
	s := (1 + this.connIDByteSize + this.seqNumByteSize)
	if this.flagVersion {
		s += 4
	}
	if s > len(data) {
		err = errors.New("QuicPublicHeader.GetSerializedData : data size too small to contain the serialized data")
		return
	}
	// Serialized Public flags, Connection ID, Version and Sequence Number
	switch this.connIDByteSize {
	case 0:
		pf = QUICFLAG_CONNID_0bit
		break
	case 1:
		pf = QUICFLAG_CONNID_8bit
		data[1] = byte(this.connId)
		break
	case 4:
		pf = QUICFLAG_CONNID_32bit
		binary.LittleEndian.PutUint32(data[1:], uint32(this.connId))
		break
	case 8:
		pf = QUICFLAG_CONNID_64bit
		binary.LittleEndian.PutUint64(data[1:], uint64(this.connId))
		break
	}
	size = this.connIDByteSize + 1
	if this.flagVersion {
		pf |= 0x01
		binary.LittleEndian.PutUint32(data[size:], uint32(this.version))
		size += 4
	}
	switch this.seqNumByteSize {
	case 1:
		pf |= QUICFLAG_SEQNUM_8bit
		data[size] = byte(this.seqNum)
		break
	case 2:
		pf |= QUICFLAG_SEQNUM_16bit
		binary.LittleEndian.PutUint16(data[size:], uint16(this.seqNum))
		break
	case 4:
		pf |= QUICFLAG_SEQNUM_32bit
		binary.LittleEndian.PutUint32(data[size:], uint32(this.seqNum))
		break
	case 6:
		pf |= QUICFLAG_SEQNUM_48bit
		binary.LittleEndian.PutUint32(data[size:], uint32(this.seqNum))
		binary.LittleEndian.PutUint16(data[size+4:], uint16(this.seqNum>>32))
		break
	}
	data[0] = pf
	size += this.seqNumByteSize
	if size != s { // This test should be removed at first official release 1.0
		err = errors.New("QuicPublicHeader.GetSerializedData : internal error serialized bytes count different from calculated size") // Must be impossible
	}
	return
}

// GetVersionFlag
func (this *QuicPublicHeader) GetVersionFlag() bool {
	return this.flagVersion
}

// SetVersionFlag
func (this *QuicPublicHeader) SetVersionFlag(state bool) {
	this.flagVersion = state
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

// SetConnectionIdSize
func (this *QuicPublicHeader) SetConnectionIdSize(size int) (err error) {
	switch size {
	case 0, 1, 4, 8:
		this.connIDByteSize = size
		return
		break
	}
	return errors.New("QuicPublicHeader.SetConnectionIdSize : invalid size")
}

// GetSequenceNumber
func (this *QuicPublicHeader) GetSequenceNumber() QuicPacketSequenceNumber {
	return this.seqNum
}

// SetSequenceNumber
func (this *QuicPublicHeader) SetSequenceNumber(seqNum QuicPacketSequenceNumber) {
	this.seqNum = seqNum
}

// SetSequenceNumberSize
func (this *QuicPublicHeader) SetSequenceNumberSize(size int) (err error) {
	switch size {
	case 1, 2, 4, 6:
		this.seqNumByteSize = size
		return
		break
	}
	return errors.New("QuicPublicHeader.SetConnectionIdSize : invalid size")
}
