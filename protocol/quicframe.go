package protocol

import "errors"

/*

Regular Frame flags:
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 |RegularType|
+---+---+---+---+---+---+---+---+

FLAGS

000  0  PADDING
001  1  RST_STREAM
010  2  CONNECTION_CLOSE
011  3  GOAWAY
100  4  WINDOW_UPDATE
101  5  BLOCKED
110  6  STOP_WAITING
111  7  PING

-----------------------------------------------------------

ACK Frame flags:
+---+---+---+---+---+---+---+---+
| 0 | 1 |NAC|TRC|LargLen|MissLen|
+---+---+---+---+---+---+---+---+

FLAGS    Largest      Missing Packet Sequence Number
         Observed     Delta
         size         size

00 00    1            1
00 01    1            2
00 10    1            4
00 11    1            6
01 00    2            1
01 01    2            2
01 10    2            4
01 11    2            6
10 00    4            1
10 01    4            2
10 10    4            4
10 11    4            6
11 00    6            1
11 01    6            2
11 10    6            4
11 11    6            6

-----------------------------------------------------------

STREAM Frame flags:
+---+---+---+---+---+---+---+---+
| 1 |FIN|Len| Offset Len| Stream|
+---+---+---+---+---+---+---+---+

FLAGS    Byte Offset size  StreamID size

000 00   0                 1
000 01   0                 2
000 10   0                 3
000 11   0                 4
001 00   2                 1
001 01   2                 2
001 10   2                 3
001 11   2                 4
010 00   3                 1
010 01   3                 2
010 10   3                 3
010 11   3                 4
011 00   4                 1
011 01   4                 2
011 10   4                 3
011 11   4                 4
100 00   5                 1
100 01   5                 2
100 10   5                 3
100 11   5                 4
101 00   6                 1
101 01   6                 2
101 10   6                 3
101 11   6                 4
110 00   7                 1
110 01   7                 2
110 10   7                 3
110 11   7                 4
111 00   8                 1
111 01   8                 2
111 10   8                 3
111 11   8                 4

*/

var parseMissingPacketSequenceNumberDeltaSize = []uint{1, 2, 4, 6, 1, 2, 4, 6, 1, 2, 4, 6, 1, 2, 4, 6}
var parseLargestObservedSize = []uint{1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 6, 6, 6, 6}

var parseStreamIdSize = []uint{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}
var parseByteOffsetSize = []uint{0, 0, 0, 0, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8}

const (
	// Quic Frame type
	QUICFRAMETYPE_STREAM                   = 0x80
	QUICFRAMETYPE_STREAM_MASK              = 0x80
	QUICFRAMETYPE_ACK                      = 0x40
	QUICFRAMETYPE_ACK_MASK                 = 0xc0
	QUICFRAMETYPE_CONGESTION_FEEDBACK      = 0x20
	QUICFRAMETYPE_CONGESTION_FEEDBACK_MASK = 0xe0
	QUICFRAMETYPE_REGULAR_MASK             = 0x1f
	QUICFRAMETYPE_PADDING                  = 0x00
	QUICFRAMETYPE_RST_STREAM               = 0x01
	QUICFRAMETYPE_CONNECTION_CLOSE         = 0x02
	QUICFRAMETYPE_GOAWAY                   = 0x03
	QUICFRAMETYPE_WINDOW_UPDATE            = 0x04
	QUICFRAMETYPE_BLOCKED                  = 0x05
	QUICFRAMETYPE_STOP_WAITING             = 0x06
	QUICFRAMETYPE_PING                     = 0x07
	// STREAM FRAME mask and flags
	QUICFLAG_FIN              = 0x40
	QUICFLAG_DATALENGTH       = 0x20
	QUICMASK_BYTEOFFSET_SIZE  = 0x1c
	QUICFLAG_BYTEOFFSET_64bit = 0x1c
	QUICFLAG_BYTEOFFSET_56bit = 0x18
	QUICFLAG_BYTEOFFSET_48bit = 0x14
	QUICFLAG_BYTEOFFSET_40bit = 0x10
	QUICFLAG_BYTEOFFSET_32bit = 0x0c
	QUICFLAG_BYTEOFFSET_24bit = 0x08
	QUICFLAG_BYTEOFFSET_16bit = 0x04
	QUICMASK_STREAMID_SIZE    = 0x03
	QUICFLAG_STREAMID_32bit   = 0x03
	QUICFLAG_STREAMID_24bit   = 0x02
	QUICFLAG_STREAMID_16bit   = 0x01
	QUICFLAG_STREAMID_8bit    = 0x00
	// ACK FRAME mask and flags
	QUICFLAG_NACK                           = 0x20
	QUICFLAG_TRUNCATED                      = 0x10
	QUICMASK_LARGESTOBSERVED_SIZE           = 0x0c
	QUICFLAG_LARGESTOBSERVED_48bit          = 0x0c
	QUICFLAG_LARGESTOBSERVED_32bit          = 0x08
	QUICFLAG_LARGESTOBSERVED_16bit          = 0x04
	QUICFLAG_LARGESTOBSERVED_8bit           = 0x00
	QUICMASK_MISSINGPACKETSEQNUMDELTA_SIZE  = 0x03
	QUICFLAG_MISSINGPACKETSEQNUMDELTA_48bit = 0x03
	QUICFLAG_MISSINGPACKETSEQNUMDELTA_32bit = 0x02
	QUICFLAG_MISSINGPACKETSEQNUMDELTA_16bit = 0x01
	QUICFLAG_MISSINGPACKETSEQNUMDELTA_8bit  = 0x00
)

type QuicFrameType byte
type QuicStreamID uint32
type QuicByteOffset uint64

type QuicFrame struct {
	frameType QuicFrameType

	// STREAM Frame fields:
	flagFIN            bool
	flagDataLength     bool
	streamId           QuicStreamID
	streamIdByteSize   uint
	byteOffset         QuicByteOffset
	byteOffsetByteSize uint
	frameLength        uint16
	frameData          []byte
	// ACK Frame fields: ???
	flagNack                                 bool
	flagTruncated                            bool
	entropyHash                              QuicEntropyHash
	largestObserved                          QuicPacketSequenceNumber
	largestObservedByteSize                  uint
	largestObservedDeltaTime                 uint16
	missingPacketSequenceNumberDeltaByteSize uint
	numTimestamp                             byte
	deltaFromLargestObserved                 byte
	timeSinceLargestObserved                 uint32
	timestampsDeltaLargestObserved           [255]byte
	timestampsTimeSincePrevious              [255]uint16
	numMissingRanges                         byte
	missingPacketsSequenceNumberDelta        [255]QuicPacketSequenceNumber
	missingRangeLength                       [255]byte
	numRevived                               byte
	revivedPackets                           [255]QuicPacketSequenceNumber
	// CONGESTION_FEEDBACK Frame --> (no fields)
	// PADDING Frame fields --> re-used of 'frameLength'
	// RST_STREAM Frame fields --> re-used of 'streamID' and 'byteOffset'
	errorCode QuicErrorCode
	// CONNECTION_CLOSE Frame fields --> re-used of 'errorCode', 'frameLength' and 'frameData'
	// GOAWAY Frame fields --> re-used of 'errorCode', 'streamId', frameLength' and 'frameData'
	// WINDOW_UPDATE Frame fields --> re-used of 'streamID' and 'byteOffset'
	// BLOCKED Frame fields --> re-used of 'streamID'
	// STOP_WAITING Frame fields --> re-used of 'entropy'
	leastUnackedDelta         QuicPacketSequenceNumber
	leastUnackedDeltaByteSize uint
	// PING Frame --> (no fields)
}

// Erase
func (this *QuicFrame) Erase() {
	this.frameType = 0
	// STREAM Frame fields
	this.flagFIN = false
	this.flagDataLength = false
	this.streamId = 0
	this.streamIdByteSize = 0
	this.byteOffset = 0
	this.byteOffsetByteSize = 0
	this.frameLength = 0
	this.frameData = nil
	// ACK Frame
	this.flagNack = false
	this.flagTruncated = false
	this.entropyHash = 0
	this.largestObserved = 0
	this.largestObservedByteSize = 0
	this.missingPacketSequenceNumberDeltaByteSize = 0
	this.numTimestamp = 0
	this.deltaFromLargestObserved = 0
	this.timeSinceLargestObserved = 0
	this.numMissingRanges = 0
	this.numRevived = 0
	// CONGESTION_FEEDBACK Frame fields
	// PADDING Frame fields
	// RST_STREAM Frame fields
	this.errorCode = 0
	// CONNECTION_CLOSE Frame fields
	// GOAWAY Frame fields
	// WINDOW_UPDATE Frame fields
	// BLOCKED Frame fields
	// STOP_WAITING Frame fields
	this.leastUnackedDelta = 0
	this.leastUnackedDeltaByteSize = 0
	// PING Frame fields
}

// ParseData
func (this *QuicFrame) ParseData(data []byte) (size int, err error) {
	l := len(data)
	if l == 0 {
		err = errors.New("QuicFrame.ParseData : no data to parse")
		return
	}
	// Parse the frame type (8-bit)
	ft := data[0]
	size = 1
	if (ft & QUICFRAMETYPE_STREAM_MASK) == QUICFRAMETYPE_STREAM {
		// This is a STREAM Frame
		this.frameType = QUICFRAMETYPE_STREAM
		// Parse FIN flag
		if (ft & QUICFLAG_FIN) == QUICFLAG_FIN {
			this.flagFIN = true
		} else {
			this.flagFIN = false
		}
		// Parse Data Length flag
		if (ft & QUICFLAG_DATALENGTH) == QUICFLAG_DATALENGTH {
			this.flagDataLength = true
		} else {
			this.flagDataLength = false
		}
		// Parse Byte Offset size flags
		ft &= 0x1f
		this.byteOffsetByteSize = parseByteOffsetSize[ft]
		// Parse Stream ID size flags
		this.streamIdByteSize = parseStreamIdSize[ft]
		// Check data length
		if this.flagDataLength {
			if l < int(3+this.streamIdByteSize+this.byteOffsetByteSize) {
				err = errors.New("QuicFrame.ParseData : not enough data to parse for STREAM frame")
				return
			}
		} else {
			if l < int(1+this.streamIdByteSize+this.byteOffsetByteSize) {
				err = errors.New("QuicFrame.ParseData : not enough data to parse for STREAM frame")
				return
			}
		}
		// Parse Stream ID (8-bit to 32-bit)
		this.streamId = 0
		for i := uint(0); i < this.streamIdByteSize; i++ {
			this.streamId |= QuicStreamID(data[size]) << (i << 3)
			size++
		}
		// Parse Byte Offset (0-bit to 64-bit)
		this.byteOffset = 0
		for i := uint(0); i < this.byteOffsetByteSize; i++ {
			this.byteOffset |= QuicByteOffset(data[size]) << (i << 3)
			size++
		}
		// Parse Data Length (16-bit)
		if this.flagDataLength {
			for i := uint(0); i < 2; i++ {
				this.frameLength |= uint16(data[size]) << (i << 3)
				size++
			}
		}
		// Check data length
		if l < (size + int(this.frameLength)) {
			err = errors.New("QuicFrame.ParseData : not enough data to parse for STREAM frame")
			return
		}
		// Parse stream data
		this.frameData = data[size : size+int(this.frameLength)]
		size += int(this.frameLength)
		return
	} else if (ft & QUICFRAMETYPE_ACK_MASK) == QUICFRAMETYPE_ACK {
		// This is an ACK Frame
		this.frameType = QUICFRAMETYPE_ACK
		// Parse NACK flag
		if (ft & QUICFLAG_NACK) == QUICFLAG_NACK {
			this.flagNack = true
		} else {
			this.flagNack = false
		}
		// Parse TRUNCATED flag
		if (ft & QUICFLAG_TRUNCATED) == QUICFLAG_TRUNCATED {
			this.flagTruncated = true
		} else {
			this.flagTruncated = false
		}
		// Parse Largest Observed size flags
		ft &= 0x1f
		this.largestObservedByteSize = parseLargestObservedSize[ft]
		// Parse Missing Packet Sequence Number size flags
		this.missingPacketSequenceNumberDeltaByteSize = parseMissingPacketSequenceNumberDeltaSize[ft]
		// Check data length
		if l < (5 + int(this.largestObservedByteSize)) {
			err = errors.New("QuicFrame.ParseData : not enough data to parse for ACK frame")
			return
		}
		// Parse Received Entropy
		this.entropyHash = QuicEntropyHash(data[1])
		size++
		// Parse Largest Observed Sequence Number (8-bit to 48-bit)
		this.largestObserved = 0
		for i := uint(0); i < this.largestObservedByteSize; i++ {
			this.largestObserved |= QuicPacketSequenceNumber(data[size]) << (i << 3)
			size++
		}
		// Parse Largest Observed Delta Time (16-bit float)
		for i := uint(0); i < 2; i++ {
			this.largestObservedDeltaTime |= uint16(data[size]) << (i << 3)
			size++
		}
		// Parse NumTimestamp
		this.numTimestamp = data[size]
		size++
		if this.numTimestamp > 0 {
			// Check data length
			if l < (size + (int(this.numTimestamp) * 3)) {
				err = errors.New("QuicFrame.ParseData : not enough data to parse for ACK frame")
				return
			}
			// Parse Delta From Largest Observed
			this.deltaFromLargestObserved = data[size]
			size++
			// Parse Time Since Largest Observed
			this.timeSinceLargestObserved = 0
			for i := uint(0); i < 4; i++ {
				this.timeSinceLargestObserved |= uint32(data[size]) << (i << 3)
				size++
			}
			for j := byte(1); j < this.numTimestamp; j++ {
				// Parse Delta Largest Observed
				this.timestampsDeltaLargestObserved[j] = data[size]
				size++
				// Parse Time Since Previous Timestamp
				this.timestampsTimeSincePrevious[j] = 0
				for i := uint(0); i < 2; i++ {
					this.timestampsTimeSincePrevious[j] |= uint16(data[i]) << (i << 3)
					size++
				}
			}
		}
		// Parse Missing Packets and Revived Packets
		if this.flagNack {
			// Check data length
			if l < (size + 2) {
				err = errors.New("QuicFrame.ParseData : not enough data to parse for ACK frame")
				return
			}
			// Parse Num Missing Packets
			this.numMissingRanges = data[size]
			size++
			if this.numMissingRanges > 0 {
				// Check data length
				if l < (1 + size + (int(this.numMissingRanges) * int(1+this.missingPacketSequenceNumberDeltaByteSize))) {
					err = errors.New("QuicFrame.ParseData : not enough data to parse for ACK frame")
					return
				}
				for j := byte(0); j < this.numMissingRanges; j++ {
					// Parse Missing Packet Sequence Number Delta
					this.missingPacketsSequenceNumberDelta[j] = 0
					for i := uint(0); i < uint(this.missingPacketSequenceNumberDeltaByteSize); i++ {
						this.missingPacketsSequenceNumberDelta[j] |= QuicPacketSequenceNumber(data[i]) << (i << 3)
						size++
					}
					// Parse Missing Packet Range Length
					this.missingRangeLength[j] = data[size]
					size++
				}
			}
			// Parse Num Revived Packets
			this.numRevived = data[size]
			size++
			if this.numRevived > 0 {
				// Check data length
				if l < (size + (int(this.numRevived) * int(this.largestObservedByteSize))) {
					err = errors.New("QuicFrame.ParseData : not enough data to parse for ACK frame")
					return
				}
				// Parse Revived Packets
				for j := byte(0); j < this.numRevived; j++ {
					// Parse Revived Packet
					this.revivedPackets[j] = 0
					for i := uint(0); i < this.largestObservedByteSize; i++ {
						this.revivedPackets[j] |= QuicPacketSequenceNumber(data[i]) << (i << 3)
						size++
					}
				}
			}
		}
		return
	} else {
		switch ft {
		case 0x00: // PADDING Frame
			this.frameType = QUICFRAMETYPE_PADDING
			this.frameLength = uint16(l - 1)
			size = l
			return
		case 0x01: // RST_STREAM Frame
			this.frameType = QUICFRAMETYPE_RST_STREAM
			// Check data length
			if l < 17 {
				err = errors.New("QuicFrame.ParseData : not enough data (<17) for RST_STREAM Frame size")
				return
			}
			// Parse StreamId (32-bit)
			this.streamId = 0
			for i := uint(0); i < 4; i++ {
				this.streamId |= QuicStreamID(data[size]) << (i << 3)
				size++
			}
			// Parse Byte offset (64-bit)
			this.byteOffset = 0
			for i := uint(0); i < 8; i++ {
				this.byteOffset |= QuicByteOffset(data[size]) << (i << 3)
				size++
			}
			// Parse Error code (32-bit)
			this.errorCode = 0
			for i := uint(0); i < 4; i++ {
				this.errorCode |= QuicErrorCode(data[size]) << (i << 3)
				size++
			}
			return
		case 0x02: // CONNECTION_CLOSE Frame
			this.frameType = QUICFRAMETYPE_CONNECTION_CLOSE
			// Parse Error Code (32-bit)
			this.errorCode = 0
			for i := uint(0); i < 4; i++ {
				this.errorCode |= QuicErrorCode(data[size]) << (i << 3)
				size++
			}
			// Parse Reason phrase Length (16-bit)
			for i := uint(0); i < 2; i++ {
				this.frameLength |= uint16(data[size]) << (i << 3)
				size++
			}
			// Check data length
			if l < (size + int(this.frameLength)) {
				err = errors.New("QuicFrame.ParseData : not enough data to parse for CONNECTION_CLOSE frame")
				return
			}
			// Parse Reason phrase
			this.frameData = data[size : size+int(this.frameLength)]
			size += int(this.frameLength)
			return
		case 0x03: // GOAWAY Frame
			this.frameType = QUICFRAMETYPE_GOAWAY
			// Parse Error Code (32-bit)
			this.errorCode = 0
			for i := uint(0); i < 4; i++ {
				this.errorCode |= QuicErrorCode(data[size]) << (i << 3)
				size++
			}
			// Parse Last Good StreamId (32-bit)
			this.streamId = 0
			for i := uint(0); i < 4; i++ {
				this.streamId |= QuicStreamID(data[size]) << (i << 3)
				size++
			}
			// Parse Reason phrase Length (16-bit)
			for i := uint(0); i < 2; i++ {
				this.frameLength |= uint16(data[size]) << (i << 3)
				size++
			}
			// Check data length
			if l < (size + int(this.frameLength)) {
				err = errors.New("QuicFrame.ParseData : not enough data to parse for CONNECTION_CLOSE frame")
				return
			}
			// Parse Reason phrase
			this.frameData = data[size : size+int(this.frameLength)]
			size += int(this.frameLength)
			return
		case 0x04: // WINDOW_UPDATE Frame
			this.frameType = QUICFRAMETYPE_WINDOW_UPDATE
			// Check data length
			if l < 13 {
				err = errors.New("QuicFrame.ParseData : not enough data (<13) for WINDOW_UPDATE Frame size")
				return
			}
			// Parse StreamId (32-bit)
			this.streamId = 0
			for i := uint(0); i < 4; i++ {
				this.streamId |= QuicStreamID(data[size]) << (i << 3)
				size++
			}
			// Parse Byte offset (64-bit)
			this.byteOffset = 0
			for i := uint(0); i < 8; i++ {
				this.byteOffset |= QuicByteOffset(data[size]) << (i << 3)
				size++
			}
			return
		case 0x05: // BLOCKED Frame
			this.frameType = QUICFRAMETYPE_BLOCKED
			// Check data length
			if l < 5 {
				err = errors.New("QuicFrame.ParseData : not enough data (<5) for BLOCKED Frame size")
				return
			}
			// Parse StreamId (32-bit)
			this.streamId = 0
			for i := uint(0); i < 4; i++ {
				this.streamId |= QuicStreamID(data[size]) << (i << 3)
				size++
			}
			return
		case 0x06: // STOP_WAITING Frame
			this.frameType = QUICFRAMETYPE_STOP_WAITING
			// Check data length
			if l < int(this.leastUnackedDeltaByteSize+2) {
				err = errors.New("QuicFrame.ParseData : not enough data for STOP_WAITING Frame size")
				return
			}
			// Parse SentEntropy
			this.entropyHash = QuicEntropyHash(data[size])
			size++
			// Parse Least Unacked Delta (8-bit to 48-bit)
			this.leastUnackedDelta = 0
			for i := uint(0); i < this.leastUnackedDeltaByteSize; i++ {
				this.leastUnackedDelta |= QuicPacketSequenceNumber(data[size]) << (i << 3)
				size++
			}
			return
		case 0x07: // PING Frame
			this.frameType = QUICFRAMETYPE_PING
			return
		}
	}
	err = errors.New("QuicFrame.ParseData : unknown frame type")
	return
}

// GetSerializedSize
func (this *QuicFrame) GetSerializedSize() (size int) {
	switch this.frameType {
	case QUICFRAMETYPE_STREAM: // variable length
		size = 1 + int(this.streamIdByteSize) + int(this.byteOffsetByteSize) + int(this.frameLength)
		if this.flagDataLength {
			size += 2
		}
		return
	case QUICFRAMETYPE_ACK: // variable length
		size = 5 + int(this.largestObservedByteSize) +
			int(this.numTimestamp*3) +
			int(this.numMissingRanges)*int(this.missingPacketSequenceNumberDeltaByteSize+1) +
			int(this.numRevived)*int(this.largestObservedByteSize)
		if this.numTimestamp > 0 {
			size += 2
		}
		return
	case QUICFRAMETYPE_CONGESTION_FEEDBACK: // unknow length ...
		size = 1
		return
	case QUICFRAMETYPE_PADDING: // variable length
		size = int(1 + this.frameLength)
		return
	case QUICFRAMETYPE_RST_STREAM: // fix length (17 bytes)
		size = 17
		return
	case QUICFRAMETYPE_CONNECTION_CLOSE: // variable length
		size = 7 + int(this.frameLength)
		return
	case QUICFRAMETYPE_GOAWAY: // variable length
		size = int(11 + this.frameLength)
		return
	case QUICFRAMETYPE_WINDOW_UPDATE: // fix length (13 bytes)
		size = 13
		return
	case QUICFRAMETYPE_BLOCKED: // fix length (5 bytes)
		size = 5
		return
	case QUICFRAMETYPE_STOP_WAITING: // 3 <= variable length <= 8
		size = int(2 + this.leastUnackedDeltaByteSize)
		return
	case QUICFRAMETYPE_PING: // fix length (1 byte)
		size = 1
		return
	}
	return
}

// GetSerializedData
func (this *QuicFrame) GetSerializedData(data []byte) (size int, err error) {
	l := len(data)
	ft := this.frameType
	switch ft {
	case QUICFRAMETYPE_STREAM: // variable length
		// Check data length
		size = 1 + int(this.streamIdByteSize) + int(this.byteOffsetByteSize) + int(this.frameLength)
		if this.flagDataLength {
			size += 2
		}
		if l < size {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for STOP_WAITING Frame size")
			size = 0
			return
		}
		// Serialize frame type
		if this.flagFIN {
			ft |= QUICFLAG_FIN
		}
		if this.flagDataLength {
			ft |= QUICFLAG_DATALENGTH
		}
		switch this.streamIdByteSize {
		case 1:
			ft |= QUICFLAG_STREAMID_8bit
			break
		case 2:
			ft |= QUICFLAG_STREAMID_16bit
			break
		case 3:
			ft |= QUICFLAG_STREAMID_24bit
			break
		case 4:
			ft |= QUICFLAG_STREAMID_32bit
			break
		}
		switch this.byteOffsetByteSize {
		case 2:
			ft |= QUICFLAG_BYTEOFFSET_16bit
			break
		case 3:
			ft |= QUICFLAG_BYTEOFFSET_24bit
			break
		case 4:
			ft |= QUICFLAG_BYTEOFFSET_32bit
			break
		case 5:
			ft |= QUICFLAG_BYTEOFFSET_40bit
			break
		case 6:
			ft |= QUICFLAG_BYTEOFFSET_48bit
			break
		case 7:
			ft |= QUICFLAG_BYTEOFFSET_56bit
			break
		case 8:
			ft |= QUICFLAG_BYTEOFFSET_64bit
			break
		}
		data[0] = byte(ft)
		size = 1
		// Serialize StreamId (8-bit to 32-bit)
		for i := uint(0); i < this.streamIdByteSize; i++ {
			data[size] = byte(this.streamId >> (i << 3))
			size++
		}
		// Serialize Byte Offset (0-bit to 64-bit)
		for i := uint(0); i < this.byteOffsetByteSize; i++ {
			data[size] = byte(this.byteOffset >> (i << 3))
			size++
		}
		if this.flagDataLength {
			// Serialize Data Length
			for i := uint(0); i < 2; i++ {
				data[size] = byte(this.frameLength >> (i << 3))
				size++
			}
		}
		// Serialize Stream Data
		for i := uint16(0); i < this.frameLength; i++ {
			data[size] = this.frameData[i]
			size++
		}
		return
	case QUICFRAMETYPE_ACK: // variable length
		// Check data length
		size = 5 + int(this.largestObservedByteSize) +
			int(this.numTimestamp*3) +
			int(this.numMissingRanges)*int(this.missingPacketSequenceNumberDeltaByteSize+1) +
			int(this.numRevived)*int(this.largestObservedByteSize)
		if this.numTimestamp > 0 {
			size += 2
		}
		if l < size {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for ACK Frame size")
			size = 0
			return
		}
		// Serialize frame type (8-bit)
		if this.flagNack {
			ft |= QUICFLAG_NACK
		}
		if this.flagTruncated {
			ft |= QUICFLAG_TRUNCATED
		}
		switch this.largestObservedByteSize {
		case 1:
			ft |= QUICFLAG_LARGESTOBSERVED_8bit
			break
		case 2:
			ft |= QUICFLAG_LARGESTOBSERVED_16bit
			break
		case 4:
			ft |= QUICFLAG_LARGESTOBSERVED_32bit
			break
		case 6:
			ft |= QUICFLAG_LARGESTOBSERVED_48bit
			break
		}
		switch this.missingPacketSequenceNumberDeltaByteSize {
		case 1:
			ft |= QUICFLAG_MISSINGPACKETSEQNUMDELTA_8bit
			break
		case 2:
			ft |= QUICFLAG_MISSINGPACKETSEQNUMDELTA_16bit
			break
		case 4:
			ft |= QUICFLAG_MISSINGPACKETSEQNUMDELTA_32bit
			break
		case 6:
			ft |= QUICFLAG_MISSINGPACKETSEQNUMDELTA_48bit
			break
		}
		data[0] = byte(ft)
		// Serialize Received Entropy (8-bit)
		data[1] = byte(this.entropyHash)
		// Serialize Largest Observed (8-bit to 48-bit)
		size = 2
		for i := uint(0); i < this.largestObservedByteSize; i++ {
			data[size] = byte(this.largestObserved >> (i << 3))
			size++
		}
		// Serialize Delta Observed Delta Time (16-bit float)
		for i := uint(0); i < 2; i++ {
			data[size] = byte(this.largestObservedDeltaTime >> (i << 3))
			size++
		}
		// Serialize Number of Timestamps (8-bit)
		data[size] = this.numTimestamp
		size++
		if this.numTimestamp > 0 {
			// Serialize Delta Largest Observed (8-bit)
			data[size] = this.deltaFromLargestObserved
			size++
			// Serialize Time Since Largest Observed (32-bit)
			for i := uint(0); i < 4; i++ {
				data[size] = byte(this.timeSinceLargestObserved >> (i << 3))
				size++
			}
			// Serialize Timestamps
			for j := byte(1); j < this.numTimestamp; j++ {
				// Serialize Delta Largest Observed
				data[size] = this.timestampsDeltaLargestObserved[j]
				size++
				// Serialize Time Since Previous Timestamp
				for i := uint(0); i < 2; i++ {
					data[size] = byte(this.timestampsTimeSincePrevious[j] >> (i << 3))
					size++
				}
			}
		}
		if this.flagNack {
			// Serialize Number of Missing Packets
			data[size] = this.numMissingRanges
			size++
			// Serialize Missing Packets
			if this.numMissingRanges > 0 {
				for j := byte(0); j < this.numMissingRanges; j++ {
					// Serialize Missing Packet Sequence Number Delta
					for i := uint(0); i < this.missingPacketSequenceNumberDeltaByteSize; i++ {
						data[size] = byte(this.missingPacketsSequenceNumberDelta[j] >> (i << 3))
						size++
					}
					// Serialize Missing Packets Range Length
					data[size] = this.missingRangeLength[j]
					size++
				}
			}
			// Serialize Number of Revived Packets
			data[size] = this.numRevived
			size++
			// Serialize Revived Packets
			if this.numRevived > 0 {
				for j := byte(0); j < this.numRevived; j++ {
					// Serialize Revived Packet Sequence Number
					for i := uint(0); i < this.largestObservedByteSize; i++ {
						data[size] = byte(this.revivedPackets[j] >> (i << 3))
						size++
					}
				}
			}
		}
		return
	case QUICFRAMETYPE_PADDING: // variable length
		// Check data length
		if l < int(1+this.frameLength) {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for PADDING Frame size")
			return
		}
		// Serialize frame type (8-bit)
		data[0] = QUICFRAMETYPE_PADDING
		// Serialize padding length of zeros
		size = int(this.frameLength)
		for i := 1; i <= size; i++ {
			data[i] = 0
		}
		size++
		return
	case QUICFRAMETYPE_RST_STREAM: // fix length (17 bytes)
		// Check data length
		if l < 17 {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for RST_STREAM Frame size (<17)")
			return
		}
		// Serialize frame type (8-bit)
		data[0] = QUICFRAMETYPE_RST_STREAM
		// Serialize Stream ID (32-bit)
		size = 1
		for i := uint(0); i < 4; i++ {
			data[size] = byte(this.streamId >> (i << 3))
			size++
		}
		// Serialize Byte offset (64-bit)
		for i := uint(0); i < 8; i++ {
			data[size] = byte(this.byteOffset >> (i << 3))
			size++
		}
		// Serialize Error code (32-bit)
		for i := uint(0); i < 4; i++ {
			data[size] = byte(this.errorCode >> (i << 3))
			size++
		}
		return
	case QUICFRAMETYPE_CONNECTION_CLOSE: // variable length
		// Check data length
		if l < int(7+this.frameLength) {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for CONNECTION_CLOSE Frame size")
			return
		}
		// Serialize frame type (8-bit)
		data[0] = QUICFRAMETYPE_CONNECTION_CLOSE
		size = 1
		// Serialize Error Code (32-bit)
		for i := uint(0); i < 4; i++ {
			data[size] = byte(this.errorCode >> (i << 3))
			size++
		}
		// Serialize Reason Phrase length (16-bit)
		for i := uint(0); i < 2; i++ {
			data[size] = byte(this.frameLength >> (i << 3))
			size++
		}
		// Serialize Reason Phrase (variable length)
		for i := uint16(0); i < this.frameLength; i++ {
			data[size] = this.frameData[i]
			size++
		}
		return
	case QUICFRAMETYPE_GOAWAY: // variable length
		// Check data length
		if l < int(11+this.frameLength) {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for GOAWAY Frame size")
			return
		}
		// Serialize frame type (8-bit)
		data[0] = QUICFRAMETYPE_GOAWAY
		size = 1
		// Serialize Error Code (32-bit)
		for i := uint(0); i < 4; i++ {
			data[size] = byte(this.errorCode >> (i << 3))
			size++
		}
		// Serialize Last Good Stream ID (32-bit)
		for i := uint(0); i < 4; i++ {
			data[size] = byte(this.streamId >> (i << 3))
			size++
		}
		// Serialize Reason Phrase length (16-bit)
		for i := uint(0); i < 2; i++ {
			data[size] = byte(this.frameLength >> (i << 3))
			size++
		}
		// Serialize Reason Phrase (variable length)
		for i := uint16(0); i < this.frameLength; i++ {
			data[size] = this.frameData[i]
			size++
		}
		return
	case QUICFRAMETYPE_WINDOW_UPDATE: // fix length (13 bytes)
		// Check data length
		if len(data) < 13 {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for WINDOW_UPDATE Frame size (<13)")
			return
		}
		// Serialize frame type (8-bit)
		data[0] = QUICFRAMETYPE_WINDOW_UPDATE
		// Serialize Stream ID (32-bit)
		size = 1
		for i := uint(0); i < 4; i++ {
			data[size] = byte(this.streamId >> (i << 3))
			size++
		}
		// Serialize Byte offset (64-bit)
		for i := uint(0); i < 8; i++ {
			data[size] = byte(this.byteOffset >> (i << 3))
			size++
		}
		return
	case QUICFRAMETYPE_BLOCKED: // fix length (5 bytes)
		// Check data length
		if l < 5 {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for BLOCKED Frame size (<5)")
			return
		}
		// Serialize frame type (8-bit)
		data[0] = QUICFRAMETYPE_BLOCKED
		// Serialize Stream ID (32-bit)
		size = 1
		for i := uint(0); i < 4; i++ {
			data[size] = byte(this.streamId >> (i << 3))
			size++
		}
		return
	case QUICFRAMETYPE_STOP_WAITING: // 3 <= variable length <= 8
		// Check data length
		if l < int(2+this.leastUnackedDeltaByteSize) {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for STOP_WAITING Frame size")
			return
		}
		// Serialize frame type (8-bit)
		data[0] = QUICFRAMETYPE_STOP_WAITING
		// Serialize Sent Entropy (8-bit)
		data[1] = byte(this.entropyHash)
		// Serialize Least Unacked Delta (8-bit to 48 bit)
		size = 2
		for i := uint(0); i < this.leastUnackedDeltaByteSize; i++ {
			data[size] = byte(this.leastUnackedDelta >> (i << 3))
			size++
		}
		return
	case QUICFRAMETYPE_PING: // fix length (1 byte)
		// Check data length
		if l < 1 {
			err = errors.New("QuicFrame.GetSerializedData : not enough data for PING Frame size (<1)")
			return
		}
		// Serialized frame type (8-bit)
		data[0] = QUICFRAMETYPE_PING
		size = 1
		return
	}
	return
}

// SetFrameType
func (this *QuicFrame) SetFrameType(frameType QuicFrameType) {
	this.frameType = frameType
}

// GetFrameType
func (this *QuicFrame) GetFrameType() QuicFrameType {
	return this.frameType
}

// SetLeastUnackedDeltaByteSize
func (this *QuicFrame) SetLeastUnackedDeltaByteSize(leastunackedsize uint) {
	this.leastUnackedDeltaByteSize = leastunackedsize
}

// GetLeastUnackedDeltaByteSize
func (this *QuicFrame) GetLeastUnackedDeltaByteSize() uint {
	return this.leastUnackedDeltaByteSize
}
