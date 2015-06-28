package protocol

import "errors"

/*

     0       1
+--------+--------+
|Private | FEC (8)|
|Flags(8)|  (opt) |
+--------+--------+


Private flags:
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 |FEC|GRP|ENT|
+---+---+---+---+---+---+---+---+

*/

const (
	// Mask and flag for Entropy bit in QuicPrivateHeader
	QUICFLAG_ENTROPY = 0x01
	// Mask and flag for FEC Group offset presence in QuicPrivateHeader
	QUICFLAG_FECGROUP = 0x02
	// Mask and flag for FEC Packet in QuicPrivateHeader
	QUICFLAG_FECPACKET = 0x04
)

// QuicFecGroupNumberOffset
type QuicFecGroupNumberOffset byte

// QuicPrivateHeader
type QuicPrivateHeader struct {
	flagFecPacket        bool
	flagFecGroup         bool
	flagEntropy          bool
	fecGroupNumberOffset QuicFecGroupNumberOffset
}

// Erase
func (this *QuicPrivateHeader) Erase() {
	this.flagFecPacket = false
	this.flagFecGroup = false
	this.flagEntropy = false
	this.fecGroupNumberOffset = 0
}

// ParseData
func (this *QuicPrivateHeader) ParseData(data []byte) (size int, err error) {
	var pv byte

	l := len(data)
	if l == 0 {
		err = errors.New("QuicPrivateHeader.ParseData : no data (= 0 byte)")
		return
	}
	// Parse Private Flags
	pv = data[0]
	// Parse unused bits
	if (pv & 0xf8) != 0 {
		err = errors.New("QuicPrivateHeader.ParseData : unused bits must be set to 0")
		return
	}
	// Parse FEC Group presence flag
	if (pv & QUICFLAG_FECGROUP) == QUICFLAG_FECGROUP {
		this.flagFecGroup = true
		if l < 2 {
			err = errors.New("QuicPrivateHeader.ParseData : too little data FEC Group (< 2 bytes)")
			return
		}
		this.fecGroupNumberOffset = QuicFecGroupNumberOffset(data[1])
		size = 2
	} else {
		size = 1
	}
	// Parse Entropy bit
	if (pv & QUICFLAG_ENTROPY) == QUICFLAG_ENTROPY {
		this.flagEntropy = true
	}
	// Parse FEC Packet flag
	if (pv & QUICFLAG_FECPACKET) == QUICFLAG_FECPACKET {
		this.flagFecPacket = true
		if !this.flagFecGroup {
			err = errors.New("QuicPrivateHeader.ParseData : internal error FEC packet must have FEC Group Number offset") // Must be impossible
			return
		}
	}
	return
}

// GetSerializedSize
func (this *QuicPrivateHeader) GetSerializedSize() (size int) {
	if this.flagFecGroup {
		return 2
	}
	return 1
}

// GetSerializedData
func (this *QuicPrivateHeader) GetSerializedData(data []byte) (size int, err error) {
	var pv QuicFecGroupNumberOffset

	if this.flagFecPacket && (!this.flagFecGroup) {
		err = errors.New("QuicPrivateHeader.GetSerializedData : internal error FEC packet must have FEC Group Number offset") // Must be impossible
		return
	}
	if this.flagFecGroup {
		size = 2
	} else {
		size = 1
	}
	// Check minimum data size
	if len(data) < size {
		size = 0
		err = errors.New("QuicPrivateHeader.GetSerializedData : data size too small to contain Private Header")
		return
	}
	// Serialized Entropy flag
	if this.flagEntropy {
		pv |= QUICFLAG_ENTROPY
	}
	// Serialized FEC Group presence flag
	if this.flagFecGroup {
		pv |= QUICFLAG_FECGROUP
	}
	// Serialized FEC Packet flag
	if this.flagFecPacket {
		pv |= QUICFLAG_FECPACKET
	}
	data[0] = byte(pv)
	// Serialized FEC Group Number Offset
	if this.flagFecGroup {
		data[1] = byte(this.fecGroupNumberOffset)
	}
	return
}

// GetFecPacketFlag
func (this *QuicPrivateHeader) GetFecPacketFlag() bool {
	return this.flagFecPacket
}

// SetFecPacketFlag
func (this *QuicPrivateHeader) SetFecPacketFlag(state bool) {
	this.flagFecPacket = state
	return
}

// GetFecGroupFlag
func (this *QuicPrivateHeader) GetFecGroupFlag() bool {
	return this.flagFecGroup
}

// SetFecGroupFlag
func (this *QuicPrivateHeader) SetFecGroupFlag(state bool) {
	this.flagFecGroup = state
	return
}

// GetEntropyFlag
func (this *QuicPrivateHeader) GetEntropyFlag() bool {
	return this.flagEntropy
}

// SetEntropyFlag
func (this *QuicPrivateHeader) SetEntropyFlag(state bool) {
	this.flagEntropy = state
	return
}

// GetFecGroupNumberOffset
func (this *QuicPrivateHeader) GetFecGroupNumberOffset() (offset QuicFecGroupNumberOffset, err error) {
	if this.flagFecGroup {
		offset = this.fecGroupNumberOffset
		return
	}
	err = errors.New("QuicPrivateHeader.GetFecGroupNumberOffset : no FEC Group Number offset in this Private Header")
	return
}

// SetFecGroupNumberOffset
func (this *QuicPrivateHeader) SetFecGroupNumberOffset(offset QuicFecGroupNumberOffset) {
	this.fecGroupNumberOffset = offset
	return
}
