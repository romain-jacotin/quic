package protocol

import "errors"

/*

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
	QUICFLAG_DATALENGTH = 0x20
	QUICFLAG_FIN        = 0x40
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
	receivedEntropy byte
	largestObserved QuicPacketSequenceNumber
	numTimestamp    byte
	numRanges       byte
	numRevived      byte
	// CONGESTION_FEEDBACK Frame --> (no fields)
	// PADDING Frame fields --> re-used of 'frameLength'
	// RST_STREAM Frame fields --> re-used of 'streamID' and 'byteOffset'
	errorCode QuicErrorCode
	// CONNECTION_CLOSE Frame fields --> re-used of 'errorCode', 'frameLength' and 'frameData'
	// GOAWAY Frame fields --> re-used of 'errorCode', 'frameLength' and 'frameData'
	lastGoodStreamId QuicStreamID
	// WINDOW_UPDATE Frame fields --> re-used of 'streamID' and 'byteOffset'
	// BLOCKED Frame fields --> re-used of 'streamID'
	// STOP_WAITING Frame fields:
	sentEntropy               byte
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
	this.receivedEntropy = 0
	this.largestObserved = 0
	this.numTimestamp = 0
	this.numRanges = 0
	this.numRevived = 0
	// CONGESTION_FEEDBACK Frame fields
	// PADDING Frame fields
	// RST_STREAM Frame fields
	this.errorCode = 0
	// CONNECTION_CLOSE Frame fields
	// GOAWAY Frame fields
	this.lastGoodStreamId = 0
	// WINDOW_UPDATE Frame fields
	// BLOCKED Frame fields
	// STOP_WAITING Frame fields
	this.sentEntropy = 0
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
		}
		// Parse Data Length flag
		if (ft & QUICFLAG_DATALENGTH) == QUICFLAG_DATALENGTH {
			this.flagDataLength = true
		}
		// Parse Byte Offset size flags
		ft &= 0x1f
		this.byteOffsetByteSize = parseByteOffsetSize[ft]
		// Parse Stream ID size flags
		this.byteOffsetByteSize = parseStreamIdSize[ft]
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
		err = errors.New("QuicFrame.ParseData : CONNECTION_CLOSE not yet implemented")
		return
	} else if (ft & QUICFRAMETYPE_CONGESTION_FEEDBACK_MASK) == QUICFRAMETYPE_CONGESTION_FEEDBACK {
		// This is a CONGESTION_FEEDBACK Frame
		this.frameType = QUICFRAMETYPE_CONGESTION_FEEDBACK
		err = errors.New("QuicFrame.ParseData : unknown CONGESTION_FEEDBACK frame type")
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
			if this.flagDataLength {
				for i := uint(0); i < 2; i++ {
					this.frameLength |= uint16(data[size]) << (i << 3)
					size++
				}
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
			this.lastGoodStreamId = 0
			for i := uint(0); i < 4; i++ {
				this.lastGoodStreamId |= QuicStreamID(data[size]) << (i << 3)
				size++
			}
			// Parse Reason phrase Length (16-bit)
			if this.flagDataLength {
				for i := uint(0); i < 2; i++ {
					this.frameLength |= uint16(data[size]) << (i << 3)
					size++
				}
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
			this.sentEntropy = data[size]
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
		return
	case QUICFRAMETYPE_ACK: // variable length
		return
	case QUICFRAMETYPE_CONGESTION_FEEDBACK: // unknow length ...
		return
	case QUICFRAMETYPE_PADDING: // variable length
		size = int(this.frameLength)
		return
	case QUICFRAMETYPE_RST_STREAM: // fix length (17 bytes)
		size = 17
		return
	case QUICFRAMETYPE_CONNECTION_CLOSE: // variable length
		return
	case QUICFRAMETYPE_GOAWAY: // variable length
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
	switch this.frameType {
	case QUICFRAMETYPE_STREAM: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_STREAM
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_ACK: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_ACK
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_CONGESTION_FEEDBACK: // unknow length ...
		// Serialize frame type
		data[0] = QUICFRAMETYPE_CONGESTION_FEEDBACK
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_PADDING: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_PADDING
		// Serialize padding length of zeros
		size = int(this.frameLength)
		for i := range data[:size] {
			data[i] = 0
		}
		return
	case QUICFRAMETYPE_RST_STREAM: // fix length (17 bytes)
		if len(data) < 17 {
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain RST_STREAM Frame (<17)")
			return
		}
		// Serialize frame type
		data[0] = QUICFRAMETYPE_RST_STREAM
		// Serialize Stream ID
		size = 1
		this.streamId = 0
		for i := uint(0); i < 4; i++ {
			this.streamId |= QuicStreamID(data[size]) << (i << 3)
			size++
		}
		// Serialize Byte offset
		this.byteOffset = 0
		for i := uint(0); i < 8; i++ {
			this.byteOffset |= QuicByteOffset(data[size]) << (i << 3)
			size++
		}
		// Serialize Error code
		this.errorCode = 0
		for i := uint(0); i < 4; i++ {
			this.errorCode |= QuicErrorCode(data[size]) << (i << 3)
			size++
		}
		return
	case QUICFRAMETYPE_CONNECTION_CLOSE: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_CONNECTION_CLOSE
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_GOAWAY: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_GOAWAY
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_WINDOW_UPDATE: // fix length (13 bytes)
		if len(data) < 13 {
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain WINDOW_UPDATE Frame (<13)")
			return
		}
		// Serialize frame type
		data[0] = QUICFRAMETYPE_WINDOW_UPDATE
		// Serialize Stream ID
		size = 1
		this.streamId = 0
		for i := uint(0); i < 4; i++ {
			this.streamId |= QuicStreamID(data[size]) << (i << 3)
			size++
		}
		// Serialize Byte offset
		this.byteOffset = 0
		for i := uint(0); i < 8; i++ {
			this.byteOffset |= QuicByteOffset(data[size]) << (i << 3)
			size++
		}
		return
	case QUICFRAMETYPE_BLOCKED: // fix length (5 bytes)
		if len(data) < 5 {
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain BLOCKED Frame (<5)")
			return
		}
		// Serialize frame type
		data[0] = QUICFRAMETYPE_BLOCKED
		// Serialize Stream ID
		size = 1
		this.streamId = 0
		for i := uint(0); i < 4; i++ {
			this.streamId |= QuicStreamID(data[size]) << (i << 3)
			size++
		}
		return
	case QUICFRAMETYPE_STOP_WAITING: // 3 <= variable length <= 8
		// Serialize frame type
		data[0] = QUICFRAMETYPE_STOP_WAITING
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_PING: // fix length (1 byte)
		// Check minimum data size
		if len(data) < 1 {
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain PING Frame (<1)")
			return
		}
		// Serialized frame type
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
